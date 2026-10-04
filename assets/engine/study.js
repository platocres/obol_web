/*!
 * obol engine — study.js
 * Study mode's engine half. Pure functions over the loaded packs (OBOL.packs.actions()) + ARSENAL +
 * the embedded sample-output map (OBOL.STUDY_FIXTURES).
 *
 * The conditional "study cell" is DERIVED, not hand-authored: every field maps to data the move
 * already carries — hypothesis / requires_* / produces / does_not_prove / commands[].note / refs —
 * plus two graph walks (what mints my prereqs, what my output opens). The one non-pack piece is the
 * sample output; a move with no fixture still produces a full cell (the Watch replay just shows no
 * streamed output yet). Each fixture pins the exact command its output came from (cmd/tool), so the
 * Watch replay always types the command that produced the result shown — command and output are one
 * coherent run, never a sample paired against a different command.
 *
 * Lanes are the methodology taxonomy: every move is auto-assigned to a lane from its source pack and
 * topologically ordered within it, so all 167 moves are navigable. Scenarios are curated cross-lane
 * paths. Command variants are ordered REMOTE-FIRST from each tool's ARSENAL os/class.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // --- the lane taxonomy: every move lands in exactly one lane, grouped by source pack ----------
  var LANE_DEFS = [
    { key: 'recon', name: 'Recon & Enumeration', short: 'Recon', packs: ['recon'], desc: 'Map the attack surface — ports, services, shares, and the web.' },
    { key: 'web', name: 'Web Exploitation', short: 'Web', packs: ['web', 'web_exploit_checks'], desc: 'Turn a web app into a shell — map it, find the injectable edge, land code execution.' },
    { key: 'checks', name: 'Service & Web Checks', short: 'Checks', packs: ['findings_checks'], desc: 'Fast, safe checks that surface misconfigurations and version leads.' },
    { key: 'ad', name: 'Active Directory', short: 'AD', packs: ['ad'], desc: 'From an anonymous foothold to owning the domain.' },
    { key: 'creds', name: 'Credentials & Cracking', short: 'Creds', packs: ['cracking', 'credential_access'], desc: 'Capture, relay, and crack credentials into usable access.' },
    { key: 'linux', name: 'Linux Privilege Escalation', short: 'Linux', packs: ['linux_privesc'], desc: 'From a low-priv shell to root.' },
    { key: 'windows', name: 'Windows Privilege Escalation', short: 'Windows', packs: ['windows_privesc'], desc: 'From a foothold to SYSTEM.' },
    { key: 'database', name: 'Databases', short: 'DB', packs: ['database'], desc: 'Enumerate and abuse database services.' },
    { key: 'shells', name: 'Shells & Transfer', short: 'Shells', packs: ['shells'], desc: 'Get a stable interactive shell and move files on and off the box.' },
    { key: 'pivot', name: 'Pivoting & Tunneling', short: 'Pivot', packs: ['pivoting', 'obol_local_pivot'], desc: 'Reach deeper networks through a compromised host.' },
    { key: 'proof', name: 'Flags & Proof', short: 'Proof', packs: ['obol_flag_hunt'], desc: 'Hunt the flags and capture the proof the report needs.' },
  ];
  var LANE_KEYS = LANE_DEFS.map(function (d) { return d.key; });

  function allMoves() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function arsenal() { return OBOL.ARSENAL || {}; }
  function fixtures() { return OBOL._studyFx || (OBOL._studyFx = Object.assign({}, OBOL.STUDY_FIXTURES || {})); }
  function byId(id) { var a = allMoves(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function reqSet(m) { return [].concat(m.requires_all || [], m.requires_any || []); }

  // id → pack basename (e.g. 'ad'), from the loaded pack bundle
  var _packOf = null;
  function packOf(id) {
    if (!_packOf) {
      _packOf = {};
      try {
        var pd = OBOL.packs.packData();
        Object.keys(pd).forEach(function (name) {
          var p = pd[name]; if (!p || !Array.isArray(p.actions)) return;
          var base = name.replace(/_\d{4}_\d{2}$/, '');
          p.actions.forEach(function (a) { _packOf[a.id] = base; });
        });
      } catch (e) {}
    }
    return _packOf[id] || '';
  }
  var _packToLane = null;
  function laneKeyForPack(base) {
    if (!_packToLane) { _packToLane = {}; LANE_DEFS.forEach(function (d) { d.packs.forEach(function (p) { _packToLane[p] = d.key; }); }); }
    return _packToLane[base] || 'recon';
  }
  // a few moves live in a pack that doesn't match their nature (nmap scans ship in the AD pack) —
  // reassign by id so the taxonomy reads right.
  function laneForMove(m) {
    if (/^nmap-/.test(m.id)) return 'recon';
    return laneKeyForPack(packOf(m.id));
  }

  // coarse stage label for a move, from the fact it mints (used as the phase chip at scale)
  function deriveStage(m) {
    if (m.phase) return cap1(m.phase);
    var p = (m.produces || [])[0] || '';
    if (/^access\.(admin|system|root)/.test(p) || p === 'access.admin' || p === 'access.system') return 'Escalate';
    if (/^(foothold\.|access\.shell)/.test(p)) return 'Foothold';
    if (/^(hash\.|credential\.)/.test(p)) return 'Credentials';
    if (/^(loot\.|proof|flag)/.test(p)) return 'Loot';
    if (/^ad\./.test(p)) return 'Active Directory';
    if (/^web\./.test(p)) return 'Web';
    if (/^(scan\.|host\.|ports|service\.)/.test(p) || /\.reachable$/.test(p)) return 'Recon';
    return '';
  }
  function cap1(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }

  // --- build the atlas lanes (all moves, topologically ordered within each lane) ----------------
  var _lanes = null;
  function buildLanes() {
    if (_lanes) return _lanes;
    var moves = allMoves();
    var buckets = {}; LANE_KEYS.forEach(function (k) { buckets[k] = []; });
    moves.forEach(function (m) { var k = laneForMove(m); (buckets[k] || buckets.recon).push(m); });
    _lanes = LANE_DEFS.map(function (d) {
      var ordered = topoOrder(buckets[d.key] || []);
      return {
        key: d.key, name: d.name, short: d.short, desc: d.desc,
        nodes: ordered.map(function (m) { return { id: m.id, title: m.title, phase: deriveStage(m), proves: m.produces || [], reqs: reqSet(m) }; }),
      };
    }).filter(function (L) { return L.nodes.length; });
    return _lanes;
  }
  // order so a move follows the in-lane moves that mint its prerequisites; stable on pack order otherwise
  function topoOrder(moves) {
    var produced = {}, out = [], remaining = moves.slice();
    var inLaneProducts = {};
    moves.forEach(function (m) { (m.produces || []).forEach(function (p) { inLaneProducts[p] = true; }); });
    function depsMet(m) {
      var reqs = reqSet(m);
      return reqs.every(function (r) { return !inLaneProducts[r] || produced[r]; });
    }
    var guard = 0;
    while (remaining.length && guard++ < 10000) {
      var picked = -1;
      for (var i = 0; i < remaining.length; i++) { if (depsMet(remaining[i])) { picked = i; break; } }
      if (picked < 0) picked = 0; // cycle / external-only deps: take next in pack order
      var m = remaining.splice(picked, 1)[0];
      out.push(m); (m.produces || []).forEach(function (p) { produced[p] = true; });
    }
    return out;
  }

  function lanes() { return buildLanes().map(function (L) { return { key: L.key, name: L.name, short: L.short, desc: L.desc, count: L.nodes.length, firstId: L.nodes[0].id }; }); }
  function lane(key) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) if (Ls[i].key === key) return Ls[i].nodes.map(function (n) { return { id: n.id, phase: n.phase, laneKey: key, title: n.title, proves: n.proves, reqs: n.reqs }; }); return []; }
  function laneOfId(id) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) for (var j = 0; j < Ls[i].nodes.length; j++) if (Ls[i].nodes[j].id === id) return { lane: Ls[i], idx: j }; return null; }
  function laneEntry(moveId) { var r = laneOfId(moveId); if (!r) return null; return { id: moveId, phase: r.lane.nodes[r.idx].phase, laneKey: r.lane.key }; }
  function laneEdges(key) {
    var N = lane(key), edges = [];
    N.forEach(function (a, ai) { N.forEach(function (b, bi) { if (bi <= ai) return; if (a.proves.some(function (p) { return b.reqs.indexOf(p) >= 0; })) edges.push({ from: a.id, to: b.id }); }); });
    return edges;
  }
  function laneNext(moveId) { var r = laneOfId(moveId); if (!r) return null; return r.idx < r.lane.nodes.length - 1 ? r.lane.nodes[r.idx + 1].id : null; }

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
  function producersOf(facts) { if (!facts || !facts.length) return []; return allMoves().filter(function (m) { return (m.produces || []).some(function (p) { return facts.indexOf(p) >= 0; }); }); }
  function opensNext(m) { var prod = m.produces || []; if (!prod.length) return []; return allMoves().filter(function (x) { return x.id !== m.id && reqSet(x).some(function (r) { return prod.indexOf(r) >= 0; }); }); }

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
    var ranked = (m.commands || []).map(function (c, i) { return { cmd: c, L: cmdLocus(c), i: i }; }).sort(function (a, b) { return a.L.rank - b.L.rank || a.i - b.i; });
    var seen = {}, commands = [];
    ranked.forEach(function (o) {
      var key = (o.cmd.tool || '?') + '|' + o.L.rank; if (seen[key]) return; seen[key] = 1;
      var run = (o.cmd.run || '').replace(/\{\{(\w+)\}\}/g, '<$1>');
      commands.push({ tool: o.cmd.tool || '', run: applyProfile(run, o.cmd.tool, profile), note: o.cmd.note || '', locus: o.L.label, tag: o.L.tag, rank: o.L.rank });
    });
    var fx = fixtures()[moveId] || null, prod = m.produces || [];
    return {
      id: m.id, title: m.title, phase: entry.phase || '', laneKey: entry.laneKey || '',
      scope: m.scope || '', locus: m.locus || '',
      whatItIs: m.hypothesis || '',
      prereqFacts: reqs,
      producedBy: producersOf(reqs).filter(function (x) { return x.id !== m.id; }).map(function (x) { return { id: x.id, title: x.title }; }),
      commands: commands,
      // A fixture pins the exact command its sample output came from (fx.cmd / fx.tool), so the Watch
      // replay types that command above its real result — command and output are one coherent run, never
      // a guess paired against the ranker. A multi-step fixture (fx.steps) models a tool that is set up
      // on BOTH your box and the target: each step carries its own `where` (local / host), command and
      // output, played in the real order. Single fixtures fall back to the move's remote-first command.
      output: buildFixtureOutput(fx),
      proves: prod,
      opens: opensNext(m).map(function (x) { return { id: x.id, title: x.title }; }),
      rulesOut: Array.isArray(m.does_not_prove) ? m.does_not_prove.join(' ; ') : (m.does_not_prove || ''),
      refs: m.refs || [],
    };
  }

  // Normalise a fixture's sample into a cell.output shape. A `steps` fixture keeps its ordered,
  // per-locus steps; a single fixture becomes a one-step sample. `text` is the concatenation used by
  // the static reference block; the Watch replay walks `steps`.
  function buildFixtureOutput(fx) {
    if (!fx) return null;
    if (fx.steps && fx.steps.length) {
      var text = fx.steps.map(function (s) { return s.output || ''; }).join('\n');
      return { text: text, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.steps[0].cmd || '', tool: fx.steps[0].tool || '', steps: fx.steps };
    }
    if (fx.output) return { text: fx.output, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.cmd || '', tool: fx.tool || '', steps: null };
    return null;
  }

  function stripPrompt(s) { return String(s || '').replace(/^\s*(kali\$|root@[^\s#]*[#$]|C:\\[^>]*>|[#$])\s*/, '').trim(); }
  function replayFor(moveId) {
    var cell = cellFor(moveId); if (!cell) return null;
    var primary = cell.commands[0] || null, out = cell.output;
    var steps = [];
    if (out && out.steps) {
      steps = out.steps.map(function (s) {
        var lines = String(s.output || '').split('\n');
        var cmd = s.cmd || '';
        if (lines.length && cmd && stripPrompt(lines[0]) === stripPrompt(cmd)) lines = lines.slice(1);
        return { where: s.where === 'host' ? 'host' : 'local', tool: s.tool || '', command: cmd, outputLines: lines, note: s.note || '' };
      });
    } else if (out) {
      var pcmd = out.cmd || (primary ? primary.run : '');
      var lines2 = out.text.split('\n');
      if (lines2.length && pcmd && stripPrompt(lines2[0]) === stripPrompt(pcmd)) lines2 = lines2.slice(1);
      var where = (primary && primary.locus === 'ON-TARGET') ? 'host' : 'local';
      steps = [{ where: where, tool: out.tool || (primary ? primary.tool : ''), command: pcmd, outputLines: lines2, note: primary ? primary.note : '' }];
    }
    var first = steps[0] || {};
    return {
      id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
      tool: first.tool || '', locus: primary ? primary.locus : '', tag: primary ? primary.tag : '',
      command: first.command || '', note: first.note || '',
      steps: steps, multi: steps.length > 1,
      outputLines: first.outputLines || [], hasOutput: !!(out && out.text),
      signal: out ? out.signal : '', teach: out ? out.teach : '',
      proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
    };
  }

  // --- the atlas: every lane as one layered graph, with cross-lane bridges ----------------------
  var BRIDGES = [
    { from: 'nmap-version-scripts', to: 'ad-dc-identify', note: 'a Windows/AD host → the AD lane' },
    { from: 'nmap-version-scripts', to: 'check-web-components', note: 'a web port → run the safe checks' },
    { from: 'recon-smb-anon', to: 'asrep-roast', note: 'anonymous SMB can leak the user list' },
    { from: 'recon-smb-anon', to: 'password-spray', note: 'a user list to spray' },
    { from: 'recon-web-triage', to: 'content-discovery', note: 'a live web app → map it' },
    { from: 'content-discovery', to: 'check-exposed-files', note: 'discovered paths → probe for leaks' },
    { from: 'web-shells', to: 'linux-enum', note: 'a web shell is a Linux foothold' },
    { from: 'web-shells', to: 'windows-enum', note: '…or a Windows foothold' },
    { from: 'web-shells', to: 'shell-pty-upgrade', note: 'a raw web shell → upgrade it to a real TTY' },
    { from: 'shell-revshell-linux', to: 'linux-enum', note: 'a caught shell → start Linux enumeration' },
    { from: 'shell-revshell-windows', to: 'windows-enum', note: 'a caught shell → start Windows enumeration' },
    { from: 'asrep-roast', to: 'crack-asrep-offline', note: 'an AS-REP hash to crack' },
    { from: 'kerberoast', to: 'crack-kerberoast', note: 'a service ticket to crack' },
    { from: 'dcsync', to: 'crack-ntlm', note: 'dumped NTLM hashes to crack' },
    { from: 'responder-poison', to: 'crack-netntlmv2', note: 'a captured NetNTLMv2 hash to crack' },
    { from: 'coerce-auth', to: 'ntlm-relay-attack', note: 'coerced auth → relay it to a second host' },
    { from: 'crack-netntlmv2', to: 'lateral-exec', note: 'a cracked password → move laterally' },
    { from: 'mssql-xp-cmdshell', to: 'windows-enum', note: 'a DB shell → escalate on the host' },
    { from: 'sudo-abuse', to: 'local-linux-interfaces', note: 'now root → pivot deeper' },
    { from: 'seimpersonate', to: 'local-windows-interfaces', note: 'now SYSTEM → pivot deeper' },
    { from: 'sudo-abuse', to: 'flag-hunt-linux', note: 'root → grab the proof' },
    { from: 'seimpersonate', to: 'flag-hunt-windows', note: 'SYSTEM → grab the proof' },
  ];
  function atlas() {
    var Ls = buildLanes(), nodes = [], index = {};
    Ls.forEach(function (L, row) { L.nodes.forEach(function (n, col) { var node = { id: n.id, title: n.title, lane: L.key, phase: n.phase, proves: n.proves, reqs: n.reqs, col: col, row: row }; nodes.push(node); index[n.id] = node; }); });
    var laneE = [], crossE = [];
    Ls.forEach(function (L) { for (var i = 1; i < L.nodes.length; i++) laneE.push({ from: L.nodes[i - 1].id, to: L.nodes[i].id }); });
    BRIDGES.forEach(function (b) { if (index[b.from] && index[b.to]) crossE.push({ from: b.from, to: b.to, note: b.note }); });
    return { nodes: nodes, laneEdges: laneE, crossEdges: crossE, laneOrder: Ls.map(function (L) { return L.key; }), lanes: Ls.map(function (L) { return { key: L.key, name: L.name, short: L.short, count: L.nodes.length }; }), cols: Math.max.apply(null, Ls.map(function (L) { return L.nodes.length; })) };
  }

  // --- scenarios: curated cross-lane paths ------------------------------------------------------
  var SCENARIOS = [
    { key: 'ad-classic', name: 'Classic AD: no creds → Domain Admin', desc: 'Anonymous foothold, roast a hash, crack it, walk an ACL path to DCSync.',
      steps: ['nmap-fast-open-ports', 'ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'ad-acl-abuse', 'dcsync'] },
    { key: 'web-linux', name: 'Web app → Linux root', desc: 'Map a web app, get a shell through it, then escalate to root.',
      steps: ['recon-web-triage', 'content-discovery', 'lfi-probe', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse'] },
    { key: 'web-windows', name: 'Web app → Windows SYSTEM', desc: 'Web foothold on a Windows host, then abuse a privilege to SYSTEM.',
      steps: ['recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'windows-enum', 'seimpersonate'] },
    { key: 'smb-spray', name: 'SMB foothold → spray → DA', desc: 'Pull a user list from anonymous SMB, spray for a login, escalate in the domain.',
      steps: ['recon-smb-anon', 'password-spray', 'ad-acl-abuse', 'dcsync'] },
    { key: 'recon-sweep', name: 'Full recon sweep', desc: 'The opening every engagement shares — ports, versions, SMB, and the web surface.',
      steps: ['nmap-fast-open-ports', 'nmap-version-scripts', 'recon-smb-anon', 'recon-web-triage'] },
    { key: 'web-root-proof', name: 'Web → root → proof', desc: 'The full exam arc: recon a web app, shell it, escalate to root, capture the flag.',
      steps: ['nmap-fast-open-ports', 'recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse', 'flag-hunt-linux'] },
    { key: 'mssql-system', name: 'MSSQL sysadmin → SYSTEM', desc: 'A database login with sysadmin becomes a shell, then SYSTEM on the host.',
      steps: ['nmap-version-scripts', 'mssql-login', 'mssql-xp-cmdshell', 'windows-enum', 'seimpersonate'] },
    { key: 'responder-lateral', name: 'Poison → crack → move laterally', desc: 'Capture a hash off the wire, crack it, and reuse it to own a second host.',
      steps: ['responder-poison', 'crack-netntlmv2', 'lateral-exec', 'windows-enum'] },
    { key: 'adcs-da', name: 'AD CS (ESC1) → Domain Admin', desc: 'Abuse a vulnerable certificate template to mint a DA credential, then DCSync.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'adcs-esc', 'cert-authenticate', 'dcsync'] },
    { key: 'web-pivot-deep', name: 'Web shell → loot → pivot', desc: 'Land through the web, loot creds, then tunnel into the network behind the box.',
      steps: ['recon-web-triage', 'content-discovery', 'web-shells', 'linux-enum', 'linux-loot-hunt', 'local-linux-interfaces', 'pivot-chisel-socks', 'pivot-scan-through'] },
  ];
  function scenarios() { return SCENARIOS.filter(function (s) { return s.steps.every(byId); }).map(function (s) { return { key: s.key, name: s.name, desc: s.desc, steps: s.steps.slice(), count: s.steps.length }; }); }
  function scenario(key) { for (var i = 0; i < SCENARIOS.length; i++) if (SCENARIOS[i].key === key) return { key: SCENARIOS[i].key, name: SCENARIOS[i].name, desc: SCENARIOS[i].desc, steps: SCENARIOS[i].steps.slice(), count: SCENARIOS[i].steps.length }; return null; }

  // --- "by open port" view: the way you actually operate — a port is open, so WHAT does it mean and
  //     WHICH moves does it unlock? This is signal recognition made literal. Curated port→moves map. ---
  var PORTS = [
    { port: 'scan', proto: '', service: 'No ports yet?', signal: 'Every engagement opens the same way: sweep the target so you know which doors exist before you touch any one of them.', moves: ['nmap-fast-open-ports', 'nmap-version-scripts', 'nmap-udp-top', 'nmap-vuln-scripts'] },
    { port: '21', proto: 'tcp', service: 'FTP', signal: 'File transfer. Test anonymous login first (it is free), then brute a known user — files on FTP routinely hold configs, source, or credentials.', moves: ['recon-ftp', 'online-brute-ftp'] },
    { port: '22', proto: 'tcp', service: 'SSH', signal: 'Remote shell. No RCE here, but a looted private key or a weak password is a stable foothold — and SSH is your cleanest pivot.', moves: ['ssh-key-login', 'online-brute-ssh', 'pivot-ssh-dynamic', 'pivot-sshuttle'] },
    { port: '25/110/143', proto: 'tcp', service: 'SMTP / POP3 / IMAP', signal: 'Mail. SMTP VRFY confirms real usernames; a mailbox credential lets you read mail for secrets and reset links. NTLM auth leaks the domain name.', moves: ['recon-smtp', 'recon-mail'] },
    { port: '53', proto: 'tcp/udp', service: 'DNS', signal: 'Name service. A zone transfer (AXFR) can hand you the whole internal host map in one request.', moves: ['recon-dns'] },
    { port: '79', proto: 'tcp', service: 'Finger', signal: 'Ancient, but when it is open it leaks real usernames and who is logged in — raw material for a spray or brute.', moves: ['recon-finger'] },
    { port: '80/443', proto: 'tcp', service: 'HTTP / HTTPS', signal: 'A web app — the single richest attack surface on the exam. Fingerprint the stack, map the content, then hunt the injectable edge.', moves: ['recon-web-triage', 'vhost-discovery', 'content-discovery', 'nikto-scan', 'wordpress', 'sqli-basics', 'command-injection', 'lfi-probe', 'file-upload', 'check-exposed-files'] },
    { port: '88', proto: 'tcp', service: 'Kerberos', signal: 'A Domain Controller. Kerberos (88) with LDAP (389) and SMB (445) is the AD fingerprint — name the domain, list users, then roast.', moves: ['ad-dc-identify', 'ad-user-enum', 'asrep-roast', 'kerberoast'] },
    { port: '111/2049', proto: 'tcp', service: 'NFS', signal: 'Network file shares. An export open to "*" is readable by anyone; no_root_squash turns it into a privesc.', moves: ['nfs-enum', 'nfs-squash'] },
    { port: '135/139/445', proto: 'tcp', service: 'SMB / RPC', signal: 'Windows file sharing and RPC. Try anonymous access, hunt readable shares, check for old SMBv1 (EternalBlue), and relay NTLM. The busiest port in AD.', moves: ['recon-smb-anon', 'smb-share-inventory', 'gpp-passwords', 'eternalblue', 'ntlm-relay-attack', 'lateral-exec', 'dump-secrets', 'own-domain-pth'] },
    { port: '161', proto: 'udp', service: 'SNMP', signal: 'A default "public" community string reads running processes, users, and sometimes credentials straight out of the host.', moves: ['recon-snmp'] },
    { port: '389/636/3268', proto: 'tcp', service: 'LDAP / Global Catalog', signal: 'The directory itself. Anonymous bind lists every user; with a credential you collect BloodHound, read LAPS, and find AD CS templates.', moves: ['ad-dc-identify', 'ad-anon-ldap-enum', 'bloodhound-collect', 'laps-read', 'adcs-esc'] },
    { port: '500', proto: 'udp', service: 'IKE / IPsec VPN', signal: 'A VPN endpoint. Aggressive Mode hands back a PSK hash you can crack offline — and a finding on its own.', moves: ['recon-ike-vpn'] },
    { port: '1433', proto: 'tcp', service: 'MSSQL', signal: 'Microsoft SQL. A login with sysadmin re-enables xp_cmdshell and runs OS commands — the database becomes a shell.', moves: ['mssql-login', 'mssql-xp-cmdshell'] },
    { port: '3306', proto: 'tcp', service: 'MySQL / MariaDB', signal: 'A login reads app secrets and the mysql.user hash table, and can write files to the web root.', moves: ['mysql-login', 'mysql-loot'] },
    { port: '3389', proto: 'tcp', service: 'RDP', signal: 'Remote desktop. Confirm which credentials log in; a weak password is a full GUI session as that user.', moves: ['rdp-enum', 'online-brute-rdp'] },
    { port: '5432', proto: 'tcp', service: 'PostgreSQL', signal: 'A session with the right role reads files and, via COPY ... FROM PROGRAM, runs commands.', moves: ['postgres-login'] },
    { port: '5900', proto: 'tcp', service: 'VNC', signal: 'Remote desktop. "None" security is an unauthenticated screen; even with a password, VNC passwords are short and crackable.', moves: ['recon-vnc'] },
    { port: '5985/5986', proto: 'tcp', service: 'WinRM', signal: 'Windows remote management. With a credential it is an interactive shell (evil-winrm) — your way onto and through Windows hosts.', moves: ['lateral-exec', 'local-windows-interfaces', 'local-windows-routes', 'local-windows-neighbors', 'local-windows-listeners'] },
    { port: '6379', proto: 'tcp', service: 'Redis', signal: 'Often unauthenticated. INFO reads the host; a writable Redis can drop an SSH key or web shell — a direct foothold.', moves: ['redis-enum'] },
    { port: '8080', proto: 'tcp', service: 'HTTP-alt (Tomcat / Jenkins)', signal: 'App servers. Tomcat Manager deploys a WAR; Jenkins\' script console runs Groovy — both are code execution with creds.', moves: ['tomcat-deploy', 'jenkins-access'] },
    { port: '27017', proto: 'tcp', service: 'MongoDB', signal: 'Historically no auth. If you can list databases, you can read them — hashes and API keys sit in plain collections.', moves: ['mongo-enum'] },
  ];
  function ports() {
    return PORTS.map(function (p) {
      var moves = (p.moves || []).filter(byId).map(function (id) { var m = byId(id); return { id: id, title: m.title, laneKey: (laneEntry(id) || {}).laneKey || '' }; });
      return { port: p.port, proto: p.proto, service: p.service, signal: p.signal, moves: moves };
    }).filter(function (p) { return p.moves.length; });
  }

  // --- "Your turn" practice --------------------------------------------------------------------
  function factsInHandAt(moveId, seq) {
    var have = {}, m = byId(moveId);
    if (m) reqSet(m).forEach(function (k) { have[k] = 1; });
    var order = seq && seq.length ? seq : lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    for (var i = 0; i < order.length; i++) { if (order[i] === moveId) break; var pm = byId(order[i]); if (pm) (pm.produces || []).forEach(function (k) { have[k] = 1; }); }
    return Object.keys(have);
  }
  function practiceFor(moveId, seq) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var have = factsInHandAt(moveId, seq);
    var ids = (fx.choices && fx.choices.length) ? fx.choices.slice() : autoChoices(moveId);
    if (ids.indexOf(moveId) < 0) ids.unshift(moveId);
    var coach = fx.coach || {};
    var choices = ids.map(function (id) {
      var d = byId(id); if (!d) return null;
      var verdict, missing = [];
      if (id === moveId) verdict = 'correct';
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
  // when a move has no authored choices, draw distractors from its lane neighbours
  function autoChoices(moveId) {
    var N = lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    var i = N.indexOf(moveId), out = [moveId];
    [i + 1, i - 1, i + 2].forEach(function (k) { if (k >= 0 && k < N.length && N[k] !== moveId && out.indexOf(N[k]) < 0) out.push(N[k]); });
    return out.slice(0, 4);
  }

  // --- mastery (per-browser) -------------------------------------------------------------------
  var MKEY = 'obol.study-mastery';
  function mastery() { try { return JSON.parse(localStorage.getItem(MKEY) || '{}') || {}; } catch (e) { return {}; } }
  function markStudied(id, kind) { try { var m = mastery(); m[id] = Object.assign({ studied: false, correct: false }, m[id]); if (kind === 'studied') m[id].studied = true; if (kind === 'correct') { m[id].studied = true; m[id].correct = true; } localStorage.setItem(MKEY, JSON.stringify(m)); } catch (e) {} }
  function laneProgress(key) { var ids = lane(key).map(function (n) { return n.id; }), m = mastery(); var s = 0, c = 0; ids.forEach(function (id) { if (m[id] && m[id].studied) s++; if (m[id] && m[id].correct) c++; }); return { total: ids.length, studied: s, correct: c }; }

  // --- path validation: does each step's prereqs hold given the steps before it? ----------------
  function validatePath(ids) {
    var have = {}, issues = [];
    ids.forEach(function (id, i) {
      var m = byId(id); if (!m) { issues.push({ idx: i, id: id, kind: 'unknown' }); return; }
      var all = m.requires_all || [], any = m.requires_any || [];
      var missAll = all.filter(function (r) { return !have[r] && !isExternal(r); });
      var anyOk = any.length === 0 || any.some(function (r) { return have[r] || isExternal(r); });
      if (missAll.length || !anyOk) issues.push({ idx: i, id: id, kind: 'prereq', missing: missAll.concat(anyOk ? [] : ['one of: ' + any.join(' / ')]) });
      (m.produces || []).forEach(function (p) { have[p] = 1; });
    });
    return { ok: !issues.length, issues: issues };
  }
  // facts an opening move needs that come "from the environment" (a target, reachability) — not from
  // another move — so a path that starts mid-stream isn't flagged for them.
  function isExternal(fact) { return /^(target\.|host\.up|ports\.open|port:|.*\.reachable$|http\.reachable|foothold\.)/.test(fact); }

  OBOL.study = {
    LANE_DEFS: LANE_DEFS, LANE_KEYS: LANE_KEYS,
    lanes: lanes, lane: lane, laneEdges: laneEdges, laneEntry: laneEntry, laneNext: laneNext,
    atlas: atlas, scenarios: scenarios, scenario: scenario, ports: ports,
    cmdLocus: cmdLocus, cellFor: cellFor, replayFor: replayFor, practiceFor: practiceFor,
    producersOf: producersOf, opensNext: opensNext,
    mastery: mastery, markStudied: markStudied, laneProgress: laneProgress, validatePath: validatePath,
    // back-compat for tests
    get AD_LANE() { return lane('ad'); },
    get LANE_ORDER() { return LANE_KEYS; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
