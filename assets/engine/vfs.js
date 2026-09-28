/*!
 * obol engine — vfs.js — the VIRTUAL WORKSPACE.
 * obol can't read the operator's Kali disk, but it knows a lot about what should be on it: the folder
 * skeleton it handed them (workspace.scaffold), the output path of every command it generated
 * (nmap -oN scans/…, a roast --asreproast loot/…, tee …), the flag files it tells them to read
 * (cat local.txt), and the content of whatever they pasted back. This module reconstructs that as a
 * file tree so the engagement screen can show the workspace filling up over time. It is a MODEL, not a
 * mirror — each file is one of a few honest states:
 *   captured   — obol has the content (pasted/attached output) and the facts it proved.
 *   expected   — obol handed OR is right now suggesting a command that writes this file; it assumes the
 *                operator is probably creating it, but hasn't received the content. Two origins:
 *                  'ran'       — the operator already dispatched the command (activity ledger).
 *                  'suggested' — the coach is recommending the move now; the file is anticipated.
 *                An expected file flips `confirmed` true once a later paste USES the path (proving it
 *                really landed on disk), and flips to captured the moment obol receives its content.
 *   scaffolded — an empty folder from the skeleton, nothing in it yet.
 * Pure + self-contained (window / worker / node). Suggested moves are read from the live engine when
 * present; when they are not (tests, worker), caller may pass opts.suggested instead.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var LAYOUT = (OBOL.workspace && OBOL.workspace.LAYOUT) || { scans: 'scans', loot: 'loot', exploit: 'exploit', www: 'www', proof: 'proof' };
  var FOLDER_ORDER = ['scans', 'loot', 'exploit', 'www', 'proof', 'other'];

  // Pull the output file path(s) out of a command string. Covers the flags obol's own packs use to
  // write files, plus a shell redirect / tee. Returns absolute-ish paths as the command wrote them.
  function outputPaths(cmd) {
    cmd = String(cmd || '');
    var out = [], m;
    var RES = [
      /-o[NXGoA]\s+(\S+)/g,                       // nmap -oN/-oX/-oG/-oA (and -o base)
      /--?(?:outfile|output|outputfile|out)[=\s]+(\S+)/g,
      /--asreproast\s+(\S+)/g,
      /--kerberoasting\s+(\S+)/g,
      /\/outfile:(\S+)/g,                          // Rubeus /outfile:x
      /(?:^|\s)-o\s+(\S+)/g,                        // gobuster/ffuf/nikto/curl -o file (nmap -oN has no space, so no clash)
      /(?:^|\s)tee\s+(?:-a\s+)?(\S+)/g,
      /(?:^|[^0-9>])>>?\s*(\S+)/g,                 // > file / >> file (not 2>… fd-redirect)
    ];
    RES.forEach(function (re) {
      while ((m = re.exec(cmd)) !== null) {
        var p = m[1];
        if (!p || p === '-' || p === '&1' || p === '&2' || /^\/dev\/(null|stdout|stderr)$/.test(p) || /^[&|]/.test(p)) continue;
        p = p.replace(/['";]+$/, '');
        if (p && out.indexOf(p) === -1) out.push(p);
      }
    });
    return out;
  }

  // The flag / proof files a command READS or is told to grab: `cat local.txt`, `type …\proof.txt`,
  // the flag-hunt spider, or an unresolved {{flag_path_*}} token. These are the OSCP objective files —
  // obol tells the operator to read them, assumes they are creating/saving them, and confirms the flag
  // from the paste that follows. Returns canonical proof-folder paths.
  // ONLY the exact objective filenames (optionally a digit, e.g. local1.txt) — never `users.txt`,
  // `rootkit.txt` or a generic list that merely starts with one of these words.
  var FLAG_TOKEN = /(?:^|[\/\\])((?:local|proof|user|root|flag)\d*\.txt)$/i;
  function flagPaths(cmd) {
    cmd = String(cmd || '');
    var out = [];
    function push(p) { if (p && out.indexOf(p) === -1) out.push(p); }
    // concrete flag-file tokens the operator will read (skip regex/glob tokens — no ()|*? in a real path).
    cmd.split(/\s+/).forEach(function (tok) {
      tok = tok.replace(/^['"]+/, '').replace(/['";]+$/, '');
      if (/[()|*?]/.test(tok)) return;                    // a --regex / --spider pattern, not a path
      var mm = tok.match(FLAG_TOKEN);
      if (mm) push(mm[1]);
    });
    // unresolved flag-path tokens → canonical proof files, so an anticipated flag still shows.
    if (/\{\{\s*flag_path_local\s*\}\}/.test(cmd) && !out.some(function (p) { return /(local|user)\.txt$/i.test(p); })) push('local.txt');
    if (/\{\{\s*flag_path_root\s*\}\}/.test(cmd) && !out.some(function (p) { return /(root|proof)\.txt$/i.test(p); })) push('proof.txt');
    return out;
  }

  function baseName(p) { p = String(p || '').replace(/[\/\\]+$/, ''); var i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\')); return i >= 0 ? p.slice(i + 1) : p; }

  // Normalize a path to the workspace root: strip a leading ./, a leading root/ prefix, and any
  // ~ home marker, so a command's `scans/x` and a `find`-manifest `scans/x` compare as the same file.
  function relOf(p, root) {
    p = String(p || '').replace(/^\.\//, '');
    root = String(root || '').replace(/\/+$/, '');
    if (root && root !== '.' && p.indexOf(root + '/') === 0) p = p.slice(root.length + 1);
    return p.replace(/^\/+/, '');
  }

  // Which skeleton folder a path belongs to (scans/loot/exploit/www/proof), else 'other'.
  function folderOf(p) {
    p = String(p || '');
    for (var k in LAYOUT) { if (Object.prototype.hasOwnProperty.call(LAYOUT, k) && new RegExp('(^|/)' + LAYOUT[k] + '/').test(p)) return k; }
    return 'other';
  }

  function toolOf(cmd) {
    var t = String(cmd || '').trim().split(/\s+/)[0] || '';
    t = t.split('/').pop().replace(/\.(py|exe|sh)$/, '');
    return t || 'tool';
  }

  // The moves the coach is recommending RIGHT NOW, filled and reduced to {command,title,tool}. Read
  // from the live engine only for the active engagement (nextActions ranks against its FactSet). Any
  // gap in the engine — or a non-active engagement — yields [], so the model degrades to run-only.
  function liveSuggestions(eng) {
    try {
      if (!OBOL.pack || !OBOL.packs || !OBOL.command || !OBOL.store || !OBOL.phases) return [];
      if (!OBOL.store.activeId || OBOL.store.activeId() !== eng.id) return [];
      var facts = OBOL.store.factSet();
      var pack = OBOL.packs.actions();
      var focus = (OBOL.profile && eng.profile) ? OBOL.profile.machineFocus(eng.profile.machine_type) : [];
      var ranked = OBOL.pack.nextActions(facts, pack, { focusPrefixes: focus });
      // only the on-flow frontier — the moves obol is actually telling the operator to run next.
      var onFlow = ranked.filter(function (a) { return OBOL.phases.prematurity(a, facts) === 0; }).slice(0, 8);
      var dirs = (OBOL.workspace && OBOL.workspace.dirs) ? OBOL.workspace.dirs(eng) : { root: '.' };
      var out = [];
      onFlow.forEach(function (a) {
        var variants = OBOL.command.fillAll(a, facts, { params: eng.params || {}, profile: eng.profile, workspace: dirs });
        var v = variants[0]; // the preferred variant — the next thing to do
        if (v) out.push({ command: v.filled || v.run || '', title: a.title || '', tool: v.tool || a.tool || '', id: a.id });
      });
      return out;
    } catch (e) { return []; }
  }

  // The FactSet to read values from: whatever the caller passed, else the live active engagement's
  // (values are only meaningful for the engagement currently loaded in the store).
  function activeFactset(eng) {
    try { if (OBOL.store && OBOL.store.activeId && OBOL.store.activeId() === eng.id && OBOL.store.factSet) return OBOL.store.factSet(); } catch (e) {}
    return null;
  }
  // Index a FactSet (or a raw fact array) by kind → [{scope, value, at}], SUPPORTED facts only.
  function indexFacts(factset) {
    var idx = {};
    if (!factset) return idx;
    var arr = factset.facts ? factset.facts : (Array.isArray(factset) ? factset : []);
    var SUP = (OBOL.facts && OBOL.facts.ProofState && OBOL.facts.ProofState.SUPPORTED);
    arr.forEach(function (f) {
      if (!f || !f.kind) return;
      if (SUP != null && f.state != null && f.state !== SUP) return;
      (idx[f.kind] = idx[f.kind] || []).push({ scope: f.scope || '', value: f.value || {}, at: f.created_at || 0 });
    });
    return idx;
  }

  // Build the virtual workspace model for an engagement.
  function build(eng, opts) {
    eng = eng || {}; opts = opts || {};
    var dirs = (OBOL.workspace && OBOL.workspace.dirs) ? OBOL.workspace.dirs(eng) : { root: '.' };
    var configured = !!(OBOL.workspace && OBOL.workspace.isConfigured && OBOL.workspace.isConfigured(eng));
    var proofdir = dirs.proofdir || dirs.proof || 'proof';
    var byPath = {}; // path -> file
    function file(path, patch) {
      var f = byPath[path] || (byPath[path] = { path: path, name: baseName(path), folder: folderOf(path),
        status: 'expected', origin: 'ran', confirmed: false, flag: false, manual: false, synced: false, unknown: false,
        actionId: '', size: 0, mtime: '', at: 0, facts: [], valMap: null, tool: '', output: '', image: null, command: '', title: '' });
      if (patch) for (var k in patch) if (Object.prototype.hasOwnProperty.call(patch, k)) f[k] = patch[k];
      return f;
    }
    // a flag/proof file lives under proof/ even when the read command names a bare local.txt.
    function flagFile(name) {
      var p = /[\/\\]/.test(name) ? name : (OBOL.workspace ? OBOL.workspace.join(proofdir, name) : proofdir + '/' + name);
      var f = file(p); f.folder = 'proof'; return f;
    }

    var flagCaptured = false; // did any paste actually prove a flag? then anticipated flag files are real.
    var referenced = {};      // basenames any activity command touched — used to CONFIRM expected files.

    // Fact VALUES, so a file can state what it actually proved ("5 open ports", "NTDS: 15 accounts").
    // Pull the active FactSet (or one the caller passed) and index it by kind; matched to a file by the
    // producing activity's kinds + scope + time. Absent → files fall back to generic counts, never guesses.
    var factset = opts.facts || activeFactset(eng);
    var factIdx = indexFacts(factset);
    // best value for a produced kind on a given scope near a time: prefer scope match, then time proximity.
    function valueFor(kind, scope, at) {
      var cands = factIdx[kind]; if (!cands || !cands.length) return null;
      var best = null, bestScore = -1;
      cands.forEach(function (c) {
        var score = (scope && c.scope === scope) ? 1000 : (c.scope && scope && c.scope.split(':')[0] === scope.split(':')[0]) ? 100 : 0;
        score -= Math.min(999, Math.abs((c.at || 0) - (at || 0)) / 1000); // nearer in time wins the tie
        if (score > bestScore) { bestScore = score; best = c; }
      });
      return best ? best.value : null;
    }
    function attachValues(f, a) {
      (a.produced || []).forEach(function (k) {
        if (f.valMap && f.valMap[k]) return;
        var v = valueFor(k, a.scope || (a.target ? ('host:' + a.target) : ''), a.at);
        if (v && typeof v === 'object') { f.valMap = f.valMap || {}; f.valMap[k] = v; }
      });
    }

    // 1) files implied by the commands the operator actually ran (the activity ledger).
    (eng.activities || []).forEach(function (a) {
      if (!a) return;
      var content = (typeof a.stdout === 'string' && a.stdout.trim()) ? a.stdout : '';
      var produced = a.produced || [];
      var provedFlag = produced.some(function (k) { return /^objective\./.test(k); });
      if (provedFlag) flagCaptured = true;
      String(a.command || '').split(/\s+/).forEach(function (t) { var b = baseName(t.replace(/['";]+$/, '')); if (b) referenced[b] = true; });

      outputPaths(a.command).forEach(function (p) {
        var f = file(p);
        f.command = f.command || a.command || '';
        f.tool = f.tool || toolOf(a.command);
        f.origin = 'ran';
        if ((a.at || 0) > f.at) f.at = a.at || 0;
        produced.forEach(function (k) { if (f.facts.indexOf(k) === -1) f.facts.push(k); });
        if (content) { f.status = 'captured'; if (content.length > f.output.length) f.output = content; }
        else if (a.file) { f.status = 'captured'; }
        attachValues(f, a);
      });
      flagPaths(a.command).forEach(function (nm) {
        var f = flagFile(nm);
        f.command = f.command || a.command || '';
        f.tool = f.tool || toolOf(a.command);
        f.origin = 'ran'; f.flag = true;
        if ((a.at || 0) > f.at) f.at = a.at || 0;
        produced.forEach(function (k) { if (f.facts.indexOf(k) === -1) f.facts.push(k); });
        if (provedFlag && content) { f.status = 'captured'; if (content.length > f.output.length) f.output = content; }
        else if (provedFlag) { f.status = 'captured'; }
      });
    });

    // 2) proof screenshots live in proof/ and are always captured evidence.
    (eng.screenshots || []).forEach(function (s, i) {
      if (!s || !s.data_uri) return;
      var nm = (s.caption ? OBOL.workspace.slugify(s.caption) : (s.slot || ('shot-' + (i + 1)))) + '.png';
      var p = OBOL.workspace.join(proofdir, nm);
      file(p, { status: 'captured', at: s.at || 0, image: s.data_uri, tool: 'screenshot', name: nm, folder: 'proof', origin: 'ran' });
    });

    // 2b) files the operator added by hand OR that a disk-sync turned up, to keep the picture in step
    // with their real disk. They are asserted-present (obol has no body), so they read as on-disk until a
    // paste captures one. A synced file obol has no move for is flagged 'unknown' — obol stays on the same
    // page for it and simply invites the contents.
    var ov = (eng.workspace && eng.workspace.overrides) || {};
    (ov.added || []).forEach(function (a) {
      var p = (typeof a === 'string') ? a : (a && a.path);
      if (!p || byPath[p]) return; // never let a hand-add shadow a real captured run
      var synced = a && a.source === 'synced';
      file(p, { origin: synced ? 'synced' : 'manual', manual: !synced, synced: synced, unknown: !!(a && a.unknown),
        confirmed: true, at: (a && a.at) || 0, size: (a && a.size) || 0, mtime: (a && a.mtime) || '' });
    });

    // 3) the moves the coach is recommending RIGHT NOW. obol assumes the operator is probably about to
    // create these files, so they show as expected/anticipated — unless a real run already owns the path
    // (a run always wins). Confirmed later when a paste uses the file; captured when its output arrives.
    var suggestions = opts.suggested || liveSuggestions(eng);
    suggestions.forEach(function (s) {
      if (!s || !s.command) return;
      outputPaths(s.command).forEach(function (p) {
        if (byPath[p]) return; // a real run already owns this file
        file(p, { origin: 'suggested', command: s.command, tool: s.tool || toolOf(s.command), title: s.title || '', actionId: s.id || '' });
      });
      flagPaths(s.command).forEach(function (nm) {
        var p = /[\/\\]/.test(nm) ? nm : (OBOL.workspace ? OBOL.workspace.join(proofdir, nm) : proofdir + '/' + nm);
        if (byPath[p]) return;
        file(p, { origin: 'suggested', flag: true, folder: 'proof', command: s.command, tool: s.tool || toolOf(s.command), title: s.title || '', actionId: s.id || '' });
      });
    });

    // 4) confirmation pass. An expected file is confirmed to exist on disk — the honest middle state
    // between "obol suggested this" and "obol has it" — when: the operator USED its path in a later command
    // (the ledger), a disk-sync SAW it (ov.onDisk), or it is an anticipated flag file and a flag was proven.
    var onDisk = ov.onDisk || {};
    Object.keys(byPath).forEach(function (p) {
      var f = byPath[p];
      var rel = relOf(p, dirs.root);
      if (onDisk[rel]) { f.confirmed = true; if (!f.size && onDisk[rel].size) f.size = onDisk[rel].size; if (!f.mtime && onDisk[rel].mtime) f.mtime = onDisk[rel].mtime; }
      if (f.status === 'captured') return;
      if (referenced[f.name]) f.confirmed = true;
      if (f.flag && flagCaptured) f.confirmed = true;
    });

    // 5) removals: the operator can hide any path to keep the picture honest with their disk. Removing a
    // path also removes it from a future render even when the coach would re-suggest it.
    var removed = ov.removed || {};
    Object.keys(byPath).forEach(function (p) { if (removed[relOf(p, dirs.root)] || removed[p]) delete byPath[p]; });

    // group by skeleton folder, keeping every scaffold folder present even when empty.
    var folders = {}; FOLDER_ORDER.forEach(function (k) { folders[k] = []; });
    Object.keys(byPath).forEach(function (p) { var f = byPath[p]; (folders[f.folder] = folders[f.folder] || []).push(f); });
    var out = FOLDER_ORDER.filter(function (k) { return LAYOUT[k] || (folders[k] && folders[k].length); }).map(function (k) {
      var list = (folders[k] || []).sort(function (a, b) { return (a.at || 0) - (b.at || 0) || a.name.localeCompare(b.name); });
      return { key: k, label: (LAYOUT[k] || k) + '/', dir: (dirs[k + 'dir'] || dirs[k] || (LAYOUT[k] || k)), files: list };
    });

    var all = Object.keys(byPath).map(function (p) { return byPath[p]; });
    return {
      root: dirs.root || '.', configured: configured, folders: out, files: all,
      captured: all.filter(function (f) { return f.status === 'captured'; }).length,
      expected: all.filter(function (f) { return f.status === 'expected'; }).length,
      anticipated: all.filter(function (f) { return f.status === 'expected' && f.origin === 'suggested'; }).length,
      total: all.length,
    };
  }

  // A human one-liner for a file — its PURPOSE (from the tool / kind / extension) plus one honest
  // metric (facts proved, lines captured, or measured size). Never fabricates a fact from a name; it
  // only names what obol can already see. Feeds the hover preview and the report's workspace appendix.
  var TOOL_PURPOSE = [
    [/^(nmap|rustscan|masscan)/i, 'Port & Service Scan'],
    [/^(gobuster|feroxbuster|ffuf|dirb|dirsearch|wfuzz)/i, 'Content Discovery'],
    [/^(nikto|nuclei|whatweb|wpscan|httpx)/i, 'Web Vuln Scan'],
    [/secretsdump/i, 'Credential / NTDS Dump'],
    [/getnpusers|asrep/i, 'AS-REP Roast'],
    [/getuserspns|kerberoast/i, 'Kerberoast'],
    [/certipy/i, 'ADCS Enumeration'],
    [/(bloodhound|sharphound)/i, 'BloodHound Collection'],
    [/^(nxc|netexec|crackmapexec|cme)/i, 'SMB / LDAP Sweep'],
    [/^(smbclient|smbmap|rpcclient|enum4linux)/i, 'SMB Share / RPC Enum'],
    [/ldapsearch|bloodyad/i, 'LDAP / Directory Dump'],
    [/^(hashcat|john)/i, 'Hash Cracking'],
    [/^(hydra|medusa)/i, 'Credential Brute Force'],
    [/snmpwalk|onesixtyone/i, 'SNMP Enumeration'],
    [/^screenshot$/i, 'Proof Screenshot'],
  ];
  var EXT_PURPOSE = { xml: 'XML Output', json: 'JSON Output', csv: 'CSV Output', py: 'Python Script', sh: 'Shell Script',
    ps1: 'PowerShell Script', txt: 'Text Output', log: 'Session Log', pcap: 'Packet Capture', pcapng: 'Packet Capture',
    dit: 'NTDS Database', ntds: 'NTDS Database', kirbi: 'Kerberos Ticket', ccache: 'Kerberos Ticket', pfx: 'Certificate (PFX)',
    zip: 'Archive', gz: 'Archive', tar: 'Archive', png: 'Image', jpg: 'Image', jpeg: 'Image', gif: 'Image' };
  function purposeOf(f) {
    if (f.flag) return 'Flag / Proof File';
    var t = f.tool || '';
    for (var i = 0; i < TOOL_PURPOSE.length; i++) if (TOOL_PURPOSE[i][0].test(t)) return TOOL_PURPOSE[i][1];
    if (!f.tool && f.command) { var lead = String(f.command).trim().split(/\s+/)[0] || ''; for (var j = 0; j < TOOL_PURPOSE.length; j++) if (TOOL_PURPOSE[j][0].test(lead)) return TOOL_PURPOSE[j][1]; }
    var ext = (f.name.split('.').pop() || '').toLowerCase();
    return EXT_PURPOSE[ext] || (f.tool ? (f.tool + ' Output') : 'File');
  }
  // Count with an EXPLICIT plural so no word is mangled ("3 NTLM Hashes", never "3 NTLM Hashs").
  // These read as labels, so they are Title Case; acronyms keep their exact stylization (NTLM, AS-REP, gMSA…).
  function cnt(n, sing, plur) { return n + ' ' + (n === 1 ? sing : plur); }
  // credential.candidate value.kind → [singular, plural], all cased deliberately.
  var CAND_LABEL = {
    ntlm_hash: ['NTLM Hash', 'NTLM Hashes'], asrep_hash: ['AS-REP Hash', 'AS-REP Hashes'],
    tgs_hash: ['TGS Hash', 'TGS Hashes'], gpp_cpassword: ['GPP Password', 'GPP Passwords'],
    gmsa_ntlm_hash: ['gMSA Hash', 'gMSA Hashes'], source_secret: ['Source Secret', 'Source Secrets'],
    database_dump_secret: ['Database Secret', 'Database Secrets'], machine_account: ['Machine Account', 'Machine Accounts'],
  };
  // The richest honest metric obol can state from the PARSED VALUES a file proved — the real "5 open
  // ports (22, 80, 445)", "NTDS: 15 accounts", "3 NTLM hashes". Values come straight from the FactSet,
  // never inferred from the filename. Returns '' when no value-bearing fact is linked to the file.
  function richMetric(vm) {
    if (!vm) return '';
    var v;
    if ((v = vm['ports.open']) && (v.ports || []).length) {
      var ps = v.ports.slice(0, 6).join(', ');
      return cnt(v.ports.length, 'Open Port', 'Open Ports') + ' (' + ps + (v.ports.length > 6 ? ', …' : '') + ')';
    }
    if ((v = vm['loot.ntds'])) { var na = v.count || (v.entries || []).length; return na ? ('NTDS: ' + cnt(na, 'Account', 'Accounts')) : 'NTDS Dump'; }
    if ((v = vm['hash.ntlm'])) { var nh = v.count || (v.entries || []).length; return nh ? cnt(nh, 'NTLM Hash', 'NTLM Hashes') : 'NTLM Hashes'; }
    if ((v = vm['ad.user_list'])) { var nu = v.count || (v.users || []).length; return nu ? cnt(nu, 'Username', 'Usernames') : 'Usernames'; }
    if ((v = vm['credential.candidate'])) { var lbl = CAND_LABEL[v.kind]; var nc = v.count || 1; return lbl ? cnt(nc, lbl[0], lbl[1]) : cnt(nc, 'Credential Lead', 'Credential Leads'); }
    if ((v = vm['credential.available'])) { var who = v.user ? (v.user + (v.domain ? ('@' + v.domain) : '')) : ''; return who ? ('Credential: ' + who) : 'Validated Credential'; }
    if ((v = vm['ad.control_paths'])) { return 'Domain Control Path'; }
    return '';
  }
  function metricOf(f) {
    var rich = richMetric(f.valMap); if (rich) return rich;
    if (f.facts && f.facts.length) return cnt(f.facts.length, 'Fact', 'Facts');
    if (f.output) { var n = String(f.output).replace(/\s+$/, '').split(/\n/).length; return cnt(n, 'Line', 'Lines'); }
    if (f.size) { var b = f.size; return b < 1024 ? (b + ' B') : b < 1048576 ? ((b / 1024).toFixed(1) + ' kB') : ((b / 1048576).toFixed(1) + ' MB'); }
    return '';
  }
  function describe(f) {
    f = f || {};
    var parts = [purposeOf(f)];
    var m = metricOf(f); if (m) parts.push(m);
    return parts.join(' · ');
  }

  // Parse a pasted `find` manifest (the snapshotCmd output) into [{path,size,mtime}]. Tolerant: skips the
  // marker lines and any shell prompt, accepts a bare path or a tab/whitespace-separated path+size+mtime,
  // and ignores directory-only or junk lines. Paths come back relative, leading ./ stripped.
  function parseSnapshot(text) {
    var out = [], seen = {};
    String(text || '').split(/\r?\n/).forEach(function (line) {
      var t = line.replace(/\s+$/, '');
      if (!t) return;
      if (/OBOL-WS-SNAPSHOT|### END|^#\s|^\$\s|^find\s|^cd\s/.test(t)) return; // markers / prompt / the command echo
      // strip a shell prompt sigil if the paste kept it
      t = t.replace(/^.*?[$#]\s+/, function (m) { return /[$#]\s+$/.test(m) && /find|cd/.test(m) ? '' : m; });
      var parts = t.split(/\t/);
      var p = (parts[0] || '').trim().replace(/^\.\//, '');
      if (!p || /[<>]/.test(p) || /\/$/.test(p)) return; // not a file
      if (!/[./]/.test(p) && parts.length < 2) return;   // a bare word with no path/size — probably prose
      if (seen[p]) return; seen[p] = true;
      var size = parseInt(parts[1], 10); if (isNaN(size)) size = 0;
      out.push({ path: p, size: size, mtime: (parts[2] || '').trim() });
    });
    return out;
  }

  // Reconcile a parsed manifest against what obol already tracks. Returns the NEW overrides object to
  // persist plus counts. Pure: it reads the engagement's current model, never mutates it.
  //   confirmed — a path obol predicted/ran that the manifest proves is on disk.
  //   adopted   — a path obol had no idea about; kept as a synced 'unknown' file inviting its contents.
  //   missing   — a path obol expected that the manifest did NOT show (informational only; not removed).
  function reconcile(eng, entries) {
    eng = eng || {};
    var root = ((eng.workspace && eng.workspace.root) || '.');
    var prev = (eng.workspace && eng.workspace.overrides) || {};
    // what obol GENUINELY knows = runs + suggestions + HAND-added, but NOT files a prior sync adopted
    // (those must be re-adopted from this manifest, or dropped when they vanish from disk).
    var baseOv = { added: (prev.added || []).filter(function (a) { return a && a.source !== 'synced'; }),
      removed: prev.removed || {}, onDisk: prev.onDisk || {} };
    var model = build(Object.assign({}, eng, { workspace: Object.assign({}, eng.workspace, { overrides: baseOv }) }));
    var known = {}; // rel -> file
    model.files.forEach(function (f) { known[relOf(f.path, root)] = f; });
    var removed = prev.removed || {};
    var onDisk = {}, added = [], manifestRel = {};
    var confirmed = 0, adopted = 0;
    // keep any prior HAND-added files (source manual); synced ones are rebuilt from this manifest.
    (prev.added || []).forEach(function (a) { if (a && a.source !== 'synced') added.push(a); });
    var now = Date.now();
    (entries || []).forEach(function (e) {
      var rel = relOf(e.path, root);
      if (!rel || manifestRel[rel]) return; manifestRel[rel] = true;
      if (removed[rel]) return; // the operator hid this; honor that over a re-sync
      onDisk[rel] = { size: e.size || 0, mtime: e.mtime || '' };
      if (known[rel]) { confirmed++; return; }
      if (added.some(function (a) { return relOf((typeof a === 'string' ? a : a.path), root) === rel; })) return;
      adopted++;
      added.push({ path: e.path, source: 'synced', unknown: true, size: e.size || 0, mtime: e.mtime || '', at: now });
    });
    var missing = model.files.filter(function (f) {
      return f.status !== 'captured' && !f.image && !manifestRel[relOf(f.path, root)];
    }).length;
    var overrides = { added: added, removed: removed, onDisk: onDisk, syncedAt: now };
    return { overrides: overrides, confirmed: confirmed, adopted: adopted, missing: missing, total: (entries || []).length };
  }

  OBOL.vfs = { build: build, outputPaths: outputPaths, flagPaths: flagPaths, folderOf: folderOf, relOf: relOf, describe: describe, parseSnapshot: parseSnapshot, reconcile: reconcile };
})(typeof globalThis !== 'undefined' ? globalThis : this);
