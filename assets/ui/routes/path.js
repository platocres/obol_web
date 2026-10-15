/*!
 * obol ui — routes/path.js — THE COACH (Next Path).
 * A pure proof-gated coach: ranked next moves from the engine, each with its *why*, its
 * copy-ready command variant(s), its *does-not-prove* honesty line, and what it *produces*.
 * NO toggles/switches here — command *building* lives in the Tools route. Blocked moves are
 * listed with their unmet-prereq reason; adding the unlocking fact promotes them live.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  function esc(s) { return U.esc(s); }

  // Scope lens (teaching filter, orthogonal to fact-gating): narrow the visible moves to a syllabus level
  // so a newcomer isn't handed the whole arsenal at once. Default 'oscp+' hides only the handful of
  // genuinely out-of-scope edge CVEs (zerologon/noPac/PrintNightmare/MS14-068/SCCM/WSUS); the operator
  // flips it any time. Persisted per-browser; a read in a private window simply falls back to the default.
  var LENS_KEY = 'obol.scope-lens', LENS_ORDER = { oscp: 0, 'oscp+': 1, beyond: 2, all: 2 };
  function lensGet() { try { var v = localStorage.getItem(LENS_KEY); return (v === 'oscp' || v === 'oscp+' || v === 'all') ? v : 'oscp+'; } catch (e) { return 'oscp+'; } }
  function lensSet(v) { try { localStorage.setItem(LENS_KEY, v); } catch (e) {} }
  function scopeAllowed(scope, lens) { if (lens === 'all') return true; return LENS_ORDER[scope || 'oscp'] <= LENS_ORDER[lens]; }

  var CAMPAIGN_KEY = 'obol.campaign';
  function campaignGet() { try { var v = sessionStorage.getItem(CAMPAIGN_KEY) || 'all'; return v; } catch (e) { return 'all'; } }
  function campaignSet(v) { try { sessionStorage.setItem(CAMPAIGN_KEY, v); } catch (e) {} }

  // A slim one-line status strip linking to the global Loadout: not-set-up CTA, or a synced summary that
  // nudges a re-sync once the box snapshot is stale. Reads the per-browser profile straight from
  // localStorage (no dependency on the lazy arsenal.js), so it renders on the coach without loading it.
  var ARSENAL_STALE_DAYS = 21;
  function arsenalProfile() { try { return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { return null; } }
  // Commands ALWAYS render as authored — we never gate a move on what we think the box has. But once the box
  // is synced, if a command's tool isn't present, add a quiet "install it" nudge beneath it (never hiding it).
  // Only nudge for tools obol actually PROVISIONS (apt/pipx/git/release/material/staged) — never for base Kali
  // tools (class 'kali') or shell builtins. Those ship by default, so flagging nmap as "missing" would just
  // look broken, and there's no install command to offer anyway; the Loadout band handles any true Kali gap.
  function missingToolHint(action, v) {
    var prof = arsenalProfile(); if (!prof) return '';
    var A = (OBOL.ARSENAL) || {};
    var names = []; if (v && v.tool) names.push(v.tool);
    if (action && action.tools) names = names.concat(action.tools); if (action && action.tool) names.push(action.tool);
    var seen = {}, miss = [];
    names.forEach(function (t) {
      if (!t) return; var e = A[String(t).toLowerCase()];
      if (!e || e.class === 'builtin' || e.class === 'kali' || seen[e.key]) return; seen[e.key] = 1;
      var rec = (prof.tools || {})[e.key];
      var present = (rec && rec.present) || (prof.cloned && prof.cloned[e.key]) || (prof.digests && prof.digests[e.key])
        || ((prof.staged || []).indexOf(e.dest || '\0') >= 0);
      if (!present) miss.push(e);
    });
    if (!miss.length) return '';
    return '<div class="cmd-missing">⚠ Not On Your Box: ' + miss.map(function (e) {
      var how = e.install ? '<code class="cmd-miss-cmd" data-copy="' + U.attr(e.install) + '" title="Click to copy">' + esc(e.install) + '</code>'
        : (e.manual_url ? '<a href="' + U.attr(e.manual_url) + '" target="_blank" rel="noopener">get it ↗</a>' : 'see Loadout');
      return '<b>' + esc(e.label || e.key) + '</b> ' + how;
    }).join(' · ') + ' · <a href="#/loadout">Loadout →</a></div>';
  }
  function arsenalStrip() {
    var p = arsenalProfile();
    if (!p) {
      return '<a class="lo-strip lo-strip-cta" href="#/loadout"><span class="lo-strip-ico">' + OBOL.ic('gear') + '</span>'
        + '<span class="lo-strip-txt">Set up your attack box, obol tailors every command to the tools you have</span>'
        + '<span class="lo-strip-go">Loadout →</span></a>';
    }
    var present = 0; try { Object.keys(p.tools || {}).forEach(function (k) { if (p.tools[k] && p.tools[k].present) present++; }); } catch (e) {}
    var ageDays = p.savedAt ? (Date.now() - p.savedAt) / 86400000 : 0;
    var stale = ageDays > ARSENAL_STALE_DAYS;
    var txt = stale
      ? ('Loadout synced ' + Math.round(ageDays) + 'd ago, re-sync your box?')
      : ('Loadout: ' + present + ' tools · ' + (p.staged || []).length + ' staged ready');
    return '<a class="lo-strip ' + (stale ? 'lo-strip-stale' : 'lo-strip-ok') + '" href="#/loadout">'
      + '<span class="lo-strip-ico">' + (stale ? '⚠' : '✓') + '</span>'
      + '<span class="lo-strip-txt">' + esc(txt) + '</span><span class="lo-strip-go">Loadout →</span></a>';
  }

  function arsenalHeroBadge() {
    var p = arsenalProfile();
    if (!p) {
      return '<a class="hero-loadout-badge lo-cta" href="#/loadout" title="Set up your attack box, obol tailors every command">'
        + '<span class="lo-badge-ico">' + (OBOL.ic ? OBOL.ic('gear') : '') + '</span>'
        + '<span class="lo-badge-txt">Setup Attack Box</span>'
        + '<span class="lo-badge-go">Loadout →</span></a>';
    }
    var present = 0; try { Object.keys(p.tools || {}).forEach(function (k) { if (p.tools[k] && p.tools[k].present) present++; }); } catch (e) {}
    var ageDays = p.savedAt ? (Date.now() - p.savedAt) / 86400000 : 0;
    var stale = ageDays > ARSENAL_STALE_DAYS;
    var txt = stale
      ? ('Loadout: Sync Stale (' + Math.round(ageDays) + 'd)')
      : ('Loadout: ' + present + ' Tools Ready');
    return '<a class="hero-loadout-badge ' + (stale ? 'lo-stale' : 'lo-ok') + '" href="#/loadout" title="' + esc(txt) + '">'
      + '<span class="lo-badge-ico">' + (stale ? '⚠' : '✓') + '</span>'
      + '<span class="lo-badge-txt">' + esc(txt) + '</span>'
      + '<span class="lo-badge-go">→</span></a>';
  }

  // When defense-enum has proven endpoint controls, warn the operator (remote-first) rather than nudging
  // them onto a monitored host. Detection only — obol surfaces the posture, it does not evade anything.
  function defenseAdvisory(facts) {
    if (!facts.has('defense.control')) return '';
    var v = {}; try { v = (facts.values('defense.control') || [])[0] || {}; } catch (e) {}
    var bits = [];
    if (v.clm) bits.push('Constrained Language Mode');
    if (v.applocker) bits.push('AppLocker enforced');
    if (v.defender) bits.push('Defender real-time on');
    if (v.exclusion_count) bits.push(v.exclusion_count + ' Defender exclusion' + (v.exclusion_count === 1 ? '' : 's'));
    var what = bits.length ? bits.join(' · ') : 'endpoint controls active';
    return '<div class="coach-defense"><span class="coach-defense-ico">' + OBOL.ic('shield') + '</span>'
      + '<span>Endpoint defenses detected, <strong>' + esc(what) + '</strong>. Prefer remote-first moves; on-host tooling may be seen.</span></div>';
  }

  // Tokens that come from proven facts, the engagement params, or the workspace — the operator fills
  // these on the sidebar or by pasting evidence, so they stay a "needs:" hint, not a text box.
  var DERIVED_TOKENS = {
    target: 1, domain: 1, basedn: 1, dc: 1, user: 1, password: 1, nthash: 1, lhost: 1, lport: 1,
    userlist: 1, hashfile: 1, wordlist: 1, dc_netbios: 1, dc_account: 1, domain_sid: 1,
    target_sam: 1, group: 1, ca_name: 1, template: 1, pfx: 1, nmap_ports: 1, krbtgt_hash: 1,
  };
  // Ad-hoc, operator-supplied free-text tokens get an inline fill box right on the card (the coach
  // stays a builder-free surface — this only completes a placeholder, no toggles). Nice labels/hints:
  var FILL_LABEL = { command: 'run on host', cmd: 'command', lport: 'listener port', rport: 'remote port', payload: 'payload', outfile: 'output file', url: 'URL', share: 'share', file: 'file', listener: 'listener',
    // privesc / cloud module tokens (values you discover from the previous step)
    suid_bin: 'SUID binary path', hijack_name: 'hijacked name', dll_name: 'DLL name', dll_path: 'writable DLL dir', task_target: 'task target path', task_name: 'task name', service: 'service name',
    sid: 'Oracle SID', sudo_command: 'allowed sudo command', kernel: 'kernel version', access_key: 'AWS access key', secret_key: 'AWS secret key', token: 'AWS session token', instance: 'EC2 instance id',
    // phase-B module tokens (values you discover from the previous step)
    clsid: 'hijackable CLSID', writable_dir: 'writable directory', unit: 'systemd unit', unit_path: 'unit file path', resource_group: 'Azure resource group', vm_name: 'Azure VM name', bearer: 'bearer token', dc_fqdn: 'DC FQDN', ca_name: 'CA name', nthash: 'NT hash',
    // discover-from-previous-step values swept out of <angle-bracket> dead text
    gmsa_account: 'gMSA account', forest_root_sid: 'forest root SID', database: 'database name', index: 'index name', internal_cidr: 'internal CIDR', internal_host: 'internal host', export: 'NFS export path', module: 'rsync module', masterkey_file: 'masterkey file', user_sid: 'user SID', credential_blob: 'credential blob', masterkey_hex: 'unwrapped masterkey (hex)', blob: 'credential blob file',
    // phase-E module tokens
    spoofed_name: 'spoofed DNS name', victim_fqdn: 'victim FQDN', wordlist: 'wordlist path', rid: 'computer RID', iface: 'your interface', project: 'GCP project id', secret: 'secret name',
    // phase-F module tokens
    endpoint: 'API endpoint path', cookie: 'session cookie',
    // phase-G module tokens
    exploit_src: 'exploit source file', script_path: 'root script path', script_dir: 'script directory' };
  var FILL_PH = { command: 'e.g. whoami /all', cmd: 'e.g. id', lport: '4444', payload: 'windows/x64/…', outfile: 'out.txt', url: 'http://…', share: 'C$', file: 'C:\\path\\file',
    suid_bin: '/usr/local/bin/backup', hijack_name: 'backup', dll_name: 'config', dll_path: 'C:\\Program Files\\App', task_target: 'C:\\Scripts\\backup.bat', task_name: '\\VulnBackup', service: 'VulnAppSvc',
    sid: 'ORCL', sudo_command: '/usr/sbin/apache2ctl', kernel: '5.8.0', access_key: 'ASIA…', secret_key: 'wJalr…', token: 'IQoJb…', instance: 'i-0abc123',
    clsid: '{0ABCD...}', writable_dir: '/opt/backups', unit: 'backup.service', unit_path: '/etc/systemd/system/backup.service', resource_group: 'rg-prod', vm_name: 'web-vm', bearer: 'eyJ0eXA…', dc_fqdn: 'dc01.acme.internal', ca_name: 'acme-DC01-CA', nthash: 'aad3b…' };

  // "Set up the file this move reads" — obol proved the user list / hashes, so it hands back a
  // copy-paste heredoc that writes the exact file {{userlist}}/{{hashfile}} now points at. This is
  // the browser stand-in for obol materializing loot/users.txt on disk: obol can't write the
  // operator's box, so it gives them the one command that does, with the names it already parsed.
  // A stable short id for a prep step, keyed by WHAT it writes AND the exact bytes it writes, so a dismissed
  // step stays gone while its content is unchanged but RE-APPEARS the moment the content changes (you proved
  // more users, so the file obol would write is different and worth re-running). djb2 over the command text.
  function prepHash(s) { var h = 5381; s = String(s || ''); for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return (h >>> 0).toString(36); }
  function prepDoneMap() { var e = OBOL.store.active(); return (e && e.ui && e.ui.prepDone) || {}; }

  // One "Set Up First" step. obol can't see the operator's disk, so a prep step can't auto-detect "done";
  // instead it carries a "Got It" control that collapses it to a single line (persisted per engagement), and
  // a "Show" to bring it back. This keeps the big heredoc from eating the card once the file has been written.
  function prepStep(tag, variant, cmd, note, key, done) {
    if (done) {
      return '<div class="cmd cmd-prep is-prep-done">'
        + '<div class="cmd-head"><span class="cmd-tag">Done</span>'
        + '<span class="cmd-variant">' + esc(String(variant).replace(/^creates /, '')) + ' written</span>'
        + '<button class="btn-ghost prep-undo" data-prep="' + esc(key) + '" title="Show this step again">Show</button></div></div>';
    }
    return '<div class="cmd cmd-prep">'
      + '<div class="cmd-head"><span class="cmd-tag">' + esc(tag) + '</span>'
      + '<span class="cmd-variant">' + esc(variant) + '</span>'
      + '<button class="btn-copy" data-copy="' + U.attr(cmd) + '" title="Copy command">Copy</button>'
      + '<button class="btn-ghost prep-done" data-prep="' + esc(key) + '" title="Hide this once you have run it">Got It</button></div>'
      + '<pre class="cmd-run"><code>' + esc(cmd) + '</code></pre>'
      + (note ? '<div class="cmd-note">' + esc(note) + '</div>' : '') + '</div>';
  }

  function prepBlock(action, facts, dirs) {
    if (!OBOL.loot) return '';
    var steps = '', doneMap = prepDoneMap();
    // {{userlist}} — the move reads it and obol has proven users to write into it.
    if (OBOL.loot.actionUsesToken(action, 'userlist')) {
      var users = OBOL.loot.usernames(facts);
      var ulCmd = OBOL.loot.userlistCommand(facts, dirs);
      if (users.length && ulCmd) {
        var ulKey = 'ul:' + prepHash(ulCmd);
        steps += prepStep('Write', 'creates ' + OBOL.loot.userlistPath(dirs),
          ulCmd, 'Run once, the ' + users.length + ' users obol proved, written where every command below reads them.', ulKey, !!doneMap[ulKey]);
      }
    }
    // {{hashfile}} as an INPUT (a crack move) — obol holds the roasted hashes as facts but no file
    // was written (a stdout roast), so give the operator the line that lays them down for cracking.
    var reqs = [].concat(action.requires_all || []);
    var cracksHashes = reqs.some(function (r) { return /^hash\./.test(r); });
    if (cracksHashes && OBOL.loot.actionUsesToken(action, 'hashfile')) {
      var hfCmd = OBOL.loot.hashfileCommand(facts, action, dirs);
      if (hfCmd) {
        var hfKey = 'hf:' + prepHash(hfCmd);
        steps += prepStep('Write', 'creates ' + OBOL.loot.hashfilePath(dirs, action),
          hfCmd, 'Lay the roasted hashes obol captured into the file the crack reads.', hfKey, !!doneMap[hfKey]);
      }
    }
    // /etc/hosts domain resolution prep step: prevents Kerberos "Temporary failure in name resolution"
    var domFacts = (facts && facts.values) ? facts.values('ad.domain_known') : [];
    var domName = (domFacts[0] && (domFacts[0].name || domFacts[0].domain)) || ((dirs || {}).domain) || '';
    var tgtIp = (dirs && dirs.target) || (((OBOL.store && OBOL.store.active && OBOL.store.active()) || {}).params || {}).target || '';
    if (domName && tgtIp && action.id && /kerberoast|asrep-roast|bloodhound|win-interactive-shell/i.test(action.id)) {
      var hostsCmd = 'echo "' + tgtIp + ' ' + domName + '" | sudo tee -a /etc/hosts';
      var hostsKey = 'hosts:' + prepHash(hostsCmd);
      steps += prepStep('Add /etc/hosts', 'maps ' + domName + ' to ' + tgtIp,
        hostsCmd, 'Crucial for Kerberos and LDAP: prevents "Temporary failure in name resolution" errors.', hostsKey, !!doneMap[hostsKey]);
    }
    return steps ? '<div class="move-prep"><span class="mini-label">Set Up First</span>' + steps + '</div>' : '';
  }

  // ---- pivot staging guide: multi-stage moves (tunnels and pivots) only make sense as a sequence
  //      across TWO machines, and single commands out of context mislead. For these, show an authored
  //      field-notes guide: ordered, machine-labelled, copy-ready, and tickable so you track where you
  //      are in the setup. Authored here (presentation) rather than in the packs, like the Learn field
  //      notes. Gated by move id so it never guesses a machine label it is not sure of. ----
  // The tunnel-setup field notes come from the shared catalog (data/tunnels.js), keyed by move id,
  // so the coach guide and the connectivity-panel chooser never drift.
  function tunnelFor(moveId) { var ts = OBOL.TUNNELS || []; for (var i = 0; i < ts.length; i++) if (ts[i].moveId === moveId) return ts[i]; return null; }
  // The step list itself is rendered by the shared OBOL.renderTunnelSteps (data/tunnels.js), so the
  // coach's Setup guide and the hub's tunnel chooser can never drift. Here we only wrap it in the
  // collapsible <details> and add the when / before-you-start intro.
  function stagingGuide(action, params) {
    var s = tunnelFor(action.id); if (!s || !OBOL.renderTunnelSteps) return '';
    var intro = (s.when || s.summary ? '<p class="stage-intro">' + esc(s.when || s.summary) + '</p>' : '')
      + (s.prereq ? '<p class="stage-prereq"><span class="stage-prereq-l">Before You Start:</span> ' + esc(s.prereq) + '</p>' : '');
    return '<details class="move-staging"><summary><span class="stage-sum-l">Setup Guide</span>'
      + '<span class="stage-sum-d">Step by step, on your box and the host</span></summary>'
      + intro + OBOL.renderTunnelSteps(s, params) + '</details>';
  }

  // ===================================================================================================
  // Next Steps redesign — a ranked card grid (left) + a field-notes canvas (right). Cards are compact and
  // scannable; selecting one morphs it wider, reveals its commands with a Remote/On-Host toggle, and loads
  // the field notes for the selected command into the canvas. Glow follows selection; #1 keeps a persistent
  // "Suggested Start" tag. See docs/mockups/next-steps-redesign.html for the agreed design.
  // ===================================================================================================

  // Which card is open, which command inside it, which locus tab. Module-level so it survives the route's
  // full re-renders (a fact change re-renders the whole coach); validated against the live set each render.
  var nsSel = { id: null, idx: 0, locus: null };
  // Multi-open (owner-requested, default OFF): when on, clicking a card toggles it and leaves the others
  // open, so you can read several side by side; nsSel stays the FOCUSED card that drives the field-notes
  // canvas. nsOpen is the set of expanded card ids (it always contains nsSel.id). The default single-focus
  // behaviour is unchanged. The preference persists per engagement in eng.ui.nsMultiOpen.
  var nsOpen = {};
  function nsMultiOpen() { try { return !!(((OBOL.store.active() || {}).ui || {}).nsMultiOpen); } catch (e) { return false; } }
  var NS_INFRA = { 'target.configured': 1, 'host.up': 1, 'ports.open': 1, 'scan.nmap.quick': 1 };

  // Inline formatting for an authored note line: a `backtick` span renders as a monospace, click-to-copy
  // <code> chip, so an error string reads as code and a fix command lifts in one click. Everything outside
  // the backticks is escaped as plain text; the chip carries the RAW text in data-copy for an exact copy.
  function fmtNote(s) {
    s = String(s == null ? '' : s);
    var out = '', re = /`([^`]+)`/g, last = 0, m;
    while ((m = re.exec(s)) !== null) {
      out += esc(s.slice(last, m.index));
      out += '<code class="ns-ic" data-copy="' + U.attr(m[1]) + '" title="Click to copy">' + esc(m[1]) + '</code>';
      last = m.index + m[0].length;
    }
    return out + esc(s.slice(last));
  }

  // Tokens that come from an EARNED fact (you discover them on the box): the domain, the base DN, a
  // credential, a captured hash, the scanned ports. These GATE a command, because until the fact is proven
  // the command cannot run. Operator config (target, lhost, lport, wordlist) is deliberately NOT here: the
  // user sets those, so a command that only needs config still shows with its fill box.
  var GATE_TOKENS = (OBOL.command && OBOL.command.EARNED_TOKENS) || { domain: 1, basedn: 1, dc: 1, dc_netbios: 1, dc_account: 1, user: 1, password: 1,
    nthash: 1, userlist: 1, hashfile: 1, domain_sid: 1, target_sam: 1, group: 1, ca_name: 1, template: 1,
    pfx: 1, nmap_ports: 1, krbtgt_hash: 1, dahash: 1, dauser: 1, flag_path_local: 1, flag_path_root: 1, share: 1, cpassword: 1 };
  // Human phrasing for the "unlocks once you have ..." affordance (deduped). user/password both read as
  // "a credential" so a command needing both reads once.
  var GATE_LABEL = { domain: 'the domain', basedn: 'the base DN', dc: 'the DC', dc_netbios: 'the DC name',
    dc_account: 'the DC account', user: 'a credential', password: 'a credential', nthash: 'an NT hash',
    userlist: 'a user list', hashfile: 'a captured hash', domain_sid: 'the domain SID', group: 'a group',
    ca_name: 'the CA name', template: 'a cert template', pfx: 'a certificate', nmap_ports: 'a port scan',
    krbtgt_hash: 'the krbtgt hash', target_sam: 'the SAM', flag_path_local: 'the located user flag',
    flag_path_root: 'the located root flag', share: 'a readable share', cpassword: 'a GPP cpassword' };
  // A command is GATED when, after filling from the engagement's facts/params, it still carries an unfilled
  // EARNED token: a value meant to come from a proven fact the operator has not earned yet. Its time has not
  // come, so the coach hides it rather than showing a dead "Needs: basedn" line, and it reappears, filled,
  // the moment the fact that feeds it is proven.
  function cmdUnmetGates(v) {
    return OBOL.command.unfilledTokens((v && v.filled) || '').filter(function (t) { return GATE_TOKENS[t]; });
  }
  function cmdGated(v) { return cmdUnmetGates(v).length > 0; }

  // The default command for a move at a locus: the house-toolkit (nxc) pick, a switchless probe first, never
  // a command already settled by a held fact, and never one still gated on an unearned fact. Fills the
  // move's commands so the gate check sees what actually resolved, then delegates the toolkit/probe/settle
  // ranking to the engine so the coach and any test share one rule.
  function firstCmdIndexForLocus(move, locus, facts) {
    if (!move) return 0;
    var eng = OBOL.store.active() || {};
    var filled = OBOL.command.fillAll(move, facts, { params: eng.params || {}, profile: eng.profile, workspace: OBOL.workspace.tokens(eng) });
    return OBOL.pack.preferredCommandIndex(move, locus, facts || null, function (cmd, i) { return cmdGated(filled[i]); });
  }
  // "Because <held gate> → expect <first payoff>" — the attack-graph cause/effect in one plain line.
  function nsNarrative(a, facts) {
    var because = '', gates = (a.requires_all || []).concat(a.requires_any || []);
    for (var i = 0; i < gates.length; i++) {
      var g = gates[i];
      if (facts.has(g) && !NS_INFRA[g] && g.indexOf('port:') !== 0) { because = OBOL.pack.chipLabel(g); break; }
    }
    var expect = (a.produces && a.produces.length) ? OBOL.pack.chipLabel(a.produces[0]) : '';
    var out = '';
    if (because) out += 'Because <span class="ns-k">' + esc(because) + '</span>';
    if (expect) out += (out ? ' <span class="ns-arrow">→</span> ' : '') + 'expect <span class="ns-k">' + esc(expect) + '</span>';
    return out || esc(U.firstSentence(a.hypothesis || ''));
  }

  // The command rows inside an expanded card: flush-left commands (no tool badge), each selectable and
  // tagged with its own locus + original index so the canvas and the toggle can address it. Reuses the
  // token-fill / "Needs:" / missing-tool logic from commandsBlock.
  function nsCommandRows(action, filled, selLocus, selIdx, spansBoth, facts) {
    var eng = OBOL.store.active() || {}, acts = eng.activities || [], params = eng.params || {};
    var gatedNeeds = {};   // earned-token -> 1, union across all hidden (gated) commands, for the affordance
    var rows = (action.commands || []).map(function (cmdObj, i) {
      // A command that has done its job drops out: a run-once probe (the switchless null-session check)
      // disappears once the fact it was there to prove is held, so you never re-run a question you answered.
      if (OBOL.pack.commandSettled(cmdObj, facts)) return '';
      if (OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmdObj, facts)) return '';
      var v = filled[i] || {};
      // A command whose time has not come drops out too: it still needs an EARNED fact (base DN, domain, a
      // credential) the operator has not proven yet. Collect what it waits on, then hide it; it returns,
      // filled, once that fact is minted. (Config tokens like lhost are not gates, see GATE_TOKENS.)
      var gates = cmdUnmetGates(v);
      if (gates.length) { gates.forEach(function (t) { gatedNeeds[GATE_LABEL[t] || t] = 1; }); return ''; }
      var locus = OBOL.pack.commandLocus(cmdObj);
      var hidden = spansBoth && locus !== selLocus;
      var ran = OBOL.command.commandWasRun(v.run || v.filled, acts, params);
      var unfilled = OBOL.command.unfilledTokens(v.filled || '');
      var fillable = unfilled.filter(function (t) { return !DERIVED_TOKENS[t]; });
      var fillRow = fillable.length
        ? '<div class="cmd-fill-row">' + fillable.map(function (t) {
            return '<label class="cmd-fill-lbl"><span>' + esc(FILL_LABEL[t] || t) + '</span>'
              + '<input class="cmd-fill" data-tok="' + esc(t) + '" placeholder="' + esc(FILL_PH[t] || ('value for ' + t)) + '" autocomplete="off" spellcheck="false"></label>';
          }).join('') + '</div>' : '';
      var step = action.sequence ? ('<span class="ns-cmd-step">' + (i + 1) + '</span>') : '';
      var ranTag = ran ? '<span class="ns-cmd-ran" title="obol saw this in your run ledger">Ran</span>' : '';
      return '<div class="ns-cmd' + (i === selIdx ? ' active' : '') + (fillable.length ? ' cmd-fillable' : '') + '"'
        + ' tabindex="0" role="group" aria-label="' + U.attr('Command ' + (i + 1) + ', ' + locus) + '"'
        + ' data-cmd-index="' + i + '" data-locus="' + locus + '"' + (hidden ? ' hidden' : '')
        + (fillable.length ? ' data-tmpl="' + U.attr(v.filled || '') + '"' : '') + '>'
        + '<div class="ns-cmd-line">' + step
        + '<code class="cmd-run-code">' + esc(v.filled || '') + '</code>' + ranTag
        + '<button class="btn-copy ns-cmd-copy" data-copy="' + U.attr(v.filled || '') + '" title="Copy command" aria-label="Copy command">' + OBOL.ic('clip') + '</button></div>'
        + fillRow + missingToolHint(action, v) + '</div>';
    }).join('');
    // Progressive disclosure: one quiet line for the commands still waiting on a fact, so the user knows
    // more unlocks here without seeing commands they cannot run yet.
    var needs = Object.keys(gatedNeeds);
    if (needs.length) {
      rows += '<div class="ns-cmd-locked" role="note">' + OBOL.ic('lock')
        + '<span>More unlocks once you have ' + esc(humanList(needs)) + '.</span></div>';
    }
    return rows;
  }
  // "a, b and c" from a short list, for the unlocks affordance.
  function humanList(a) {
    if (a.length <= 1) return a[0] || '';
    if (a.length === 2) return a[0] + ' and ' + a[1];
    return a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1];
  }

  function actionTargetLabel(action, facts, eng, focusedTarget) {
    // 1. If currently focused on a specific target:
    if (focusedTarget) return focusedTarget;

    // 2. If in Engagement-Wide mode (or no target focused):
    var gates = (action.requires_all || []).concat(action.requires_any || []);
    var rawFacts = (facts && facts.all) ? facts.all() : ((eng && eng.facts) || []);
    var hostScopes = {};
    rawFacts.forEach(function (f) {
      if (!f || !f.scope) return;
      var m = /^host:([^\s:]+)/.exec(f.scope);
      if (m && gates.indexOf(f.kind) >= 0) {
        hostScopes[m[1]] = (hostScopes[m[1]] || 0) + 1;
      }
    });
    var matchedIps = Object.keys(hostScopes);
    if (matchedIps.length === 1) return matchedIps[0];
    if (matchedIps.length > 1) return matchedIps.join(', ');

    // 3. Check if domain-scoped
    var isDomain = rawFacts.some(function (f) {
      return f && f.scope && (f.scope.indexOf('domain:') === 0) && gates.indexOf(f.kind) >= 0;
    });
    if (isDomain) return 'Domain';

    // 4. Fallback to engagement active/default target IP if known
    var defaultIp = (eng && eng.params && eng.params.target) || ((eng && eng.targets && eng.targets[0]) ? (eng.targets[0].ip || eng.targets[0].id) : '');
    if (defaultIp) return defaultIp;

    return null;
  }

  // One ranked card. opts: { rank, selected, suggested, targetBadge }. The expanded body is always in the DOM (shown via
  // CSS when .selected) so the delegated fill / paste-back / copy listeners work without a re-render.
  function nsCard(action, facts, params, opts) {
    opts = opts || {};
    var famClass = ' ns-ph-' + OBOL.phases.phaseOfAction(action);
    var dirs = OBOL.workspace.tokens(OBOL.store.active());
    var filled = OBOL.command.fillAll(action, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: dirs });
    var loci = OBOL.pack.moveCommandLoci(action, facts);
    var selLocus = opts.selected ? (nsSel.locus || OBOL.pack.defaultCommandLocus(action)) : OBOL.pack.defaultCommandLocus(action);
    if (!loci.both) {
      selLocus = loci.onhost ? 'onhost' : (loci.remote ? 'remote' : selLocus);
    }
    var selIdx = opts.selected ? nsSel.idx : firstCmdIndexForLocus(action, selLocus, facts);
    var nCmd = (action.commands || []).length;
    var toggle = loci.both
      ? '<div class="ns-toggle" role="group" aria-label="Where to run this">'
        + '<button type="button" data-locus="remote" class="' + (selLocus === 'remote' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'remote') + '">Remote</button>'
        + '<button type="button" data-locus="onhost" class="' + (selLocus === 'onhost' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'onhost') + '">On-Host</button>'
        + '</div>' : '';
    var body = '<div class="ns-body">'
      + toggle
      + prepBlock(action, facts, dirs)
      + '<div class="ns-cmds">' + nsCommandRows(action, filled, selLocus, selIdx, loci.both, facts) + '</div>'
      + '<div class="ns-card-actions">'
      + '<button class="btn-ghost btn-pasteback" data-action="' + esc(action.id) + '" aria-expanded="false">Paste Output</button>'
      + '<button class="btn-ghost btn-done" data-action="' + esc(action.id) + '">Mark Done</button>'
      + ((action.tool || (action.tools && action.tools[0])) ? '<a class="btn-ghost" href="#/tools/' + esc(action.tool || action.tools[0]) + '">Build In Tools</a>' : '')
      + '</div>'
      + '<div class="move-ingest" data-action="' + esc(action.id) + '" data-cmd="' + U.attr((filled[0] && filled[0].filled) || '') + '" hidden>'
      + '<textarea class="mi-text" placeholder="Paste this command\'s full output here, prompt and all. The coach reads it, mints only what it proves, and advances." spellcheck="false"></textarea>'
      + '<div class="mi-row"><button class="btn-primary mi-go" data-action="' + esc(action.id) + '">Ingest to Facts</button>'
      + '<a class="mi-evlink" href="#/evidence/' + esc(action.id) + '">Big output or a screenshot? Full Evidence</a>'
      + '<span class="mi-result" role="status"></span></div></div>'
      + '</div>';
    // Not role="button" — the expanded body holds real buttons/inputs, which must not nest inside a
    // button for screen readers. It is a focusable region with an aria-label and Enter/Space handling.
    return '<article class="ns-card' + famClass + (opts.selected ? ' selected is-glow' : '') + '" tabindex="0"'
      + ' aria-expanded="' + (opts.selected ? 'true' : 'false') + '"'
      + ' aria-label="' + U.attr(action.title + ' — press Enter to open its commands and field notes') + '" data-action="' + esc(action.id) + '">'
      + (opts.rank ? '<span class="ns-rank">#' + opts.rank + '</span>' : '')
      + '<div class="ns-card-head">'
      + (opts.suggested ? '<span class="ns-suggested">Suggested Start</span>' : '')
      + '<span class="ns-chip ns-phase ph-' + esc(OBOL.phases.phaseOfAction(action)) + '">' + esc(U.titleCase(OBOL.phases.phaseOfAction(action))) + '</span>'
      + (opts.targetBadge ? '<span class="ns-chip ns-chip-target">' + esc(opts.targetBadge) + '</span>' : '')
      + '</div>'
      + '<h3 class="ns-title">' + esc(action.title) + '</h3>'
      + '<p class="ns-narr">' + nsNarrative(action, facts) + '</p>'
      + body
      + '<div class="ns-foot">' + nCmd + ' Command' + (nCmd === 1 ? '' : 's') + '</div>'
      + '</article>';
  }

  // The field-notes canvas for a (move, command): reactive doctors on top (if a pasted error minted a
  // blocker), then the command echo, How To Land It, You'll Know It Worked, Common Mistakes, an authored
  // per-command doctor, and the pivot setup guide for tunnel moves.
  function nsLiveDoctors(facts) {
    var docs = OBOL.FIELD_DOCTORS || {}, out = [];
    Object.keys(docs).forEach(function (k) {
      if (facts.has(k)) {
        // Guard: access_denied diagnostic is only relevant if credentials/accounts or authenticated operations exist
        if (k === 'blocker.access_denied') {
          // On a Domain Controller, --local-auth is impossible and invalid
          var isDC = facts.has('ad.dc_candidate') || facts.has('ad.domain_controller');
          if (isDC) return;
          // Must have valid credentials or an authenticated session, not an uncracked hash candidate
          var hasAuthContext = facts.has('credential.available') || facts.has('credential.validated') || facts.has('smb.authenticated') || facts.has('smb.session');
          if (!hasAuthContext) return;
        }
        var d = Object.assign({ factKind: k }, docs[k]);
        out.push(d);
      }
    });
    return out;
  }

  function renderCoachFixCards(facts) {
    var live = nsLiveDoctors(facts);
    if (!live.length) return '';
    return '<div class="fix-cards-container coach-fix-cards">'
      + live.map(function (d) {
          return '<div class="fix-card" data-blocker="' + esc(d.factKind || '') + '">'
            + '<div class="fix-card-header">'
            + '<div class="fix-card-title-group">'
            + '<span class="fix-card-badge">DIAGNOSTIC DETECTED</span>'
            + '<h3 class="fix-card-title">' + esc(d.title || d.factKind) + '</h3>'
            + '</div>'
            + (d.factKind ? ('<button type="button" class="fix-card-dismiss" data-dismiss-blocker="' + esc(d.factKind) + '" title="Dismiss this diagnostic">✓ Resolved</button>') : '')
            + '</div>'
            + '<div class="fix-card-body">'
            + (d.why ? ('<div class="fix-card-why"><strong>Root Cause:</strong> ' + esc(d.why) + '</div>') : '')
            + (d.body ? ('<p class="fix-card-desc">' + esc(d.body) + '</p>') : '')
            + (d.code ? ('<div class="fix-card-cmd-wrap">'
                + '<pre class="fix-card-code"><code>' + esc(d.code) + '</code></pre>'
                + '<button type="button" class="btn-copy fix-card-copy" data-copy="' + U.attr(d.code) + '" title="Copy fix command">Copy Fix</button>'
                + '</div>') : '')
            + (d.gotcha ? ('<div class="fix-card-gotcha"><strong>Gotcha / Trap:</strong> ' + esc(d.gotcha) + '</div>') : '')
            + '</div>'
            + '</div>';
        }).join('')
      + '</div>';
  }
  // Fill a companion-command template through the real pipeline (tokens + Loadout arsenal rewrite), so a
  // field-note setup command carries the operator's actual IP / wordlist paths / tool invocations.
  function nsFill(tmpl, facts, params) {
    try {
      return OBOL.command.fillCommand({ commands: [{ run: String(tmpl && tmpl.cmd || tmpl) }] }, facts,
        { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) }, 0).filled;
    } catch (e) { return String(tmpl && tmpl.cmd || tmpl); }
  }
  // One "Set Up First" row: a labelled, copy-ready command. srcTag marks a command surfaced from another
  // move (so the learner knows it is reused from a canonical place, not re-stated here).
  function nsSetupStep(label, cmd, srcTag) {
    return '<div class="ns-setup-step">'
      + (label ? '<div class="ns-setup-l">' + esc(label) + (srcTag ? ' <span class="ns-setup-src">' + esc(srcTag) + '</span>' : '') + '</div>' : '')
      + '<div class="ns-setup-cmd"><code>' + esc(cmd) + '</code>'
      + '<button class="btn-copy ns-setup-copy" data-copy="' + U.attr(cmd) + '" title="Copy" aria-label="Copy command">' + OBOL.ic('clip') + '</button></div></div>';
  }
  // Surface another move's command(s) as prerequisite steps, pulled live from the loaded packs and filled
  // through the real pipeline. This is how a field note reuses the Shells lane's catcher / reverse-shell /
  // transfer one-liners instead of re-authoring them, so there is one source of truth.
  function nsReuseSteps(refId, facts, params) {
    var pack; try { pack = OBOL.packs.actions(); } catch (e) { return ''; }
    var m = null; for (var i = 0; i < pack.length; i++) { if (pack[i].id === refId) { m = pack[i]; break; } }
    if (!m) return '';
    var filled;
    try { filled = OBOL.command.fillAll(m, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) }); }
    catch (e) { filled = (m.commands || []).map(function (c) { return { filled: c.run }; }); }
    var cmd = (filled[0] && filled[0].filled) || ((m.commands || [])[0] || {}).run || '';
    return cmd ? nsSetupStep(m.title, cmd, 'reused') : '';
  }
  // The automatic post-success block. Two distinct cases, because the right orientation differs:
  //   - a NEW shell (foothold / access.shell): get your bearings and fix the half-broken shell; or
  //   - an ELEVATION to root / SYSTEM (access.admin/root/system, no new shell): confirm the new identity and
  //     grab the proof flag in the same window.
  // Derived from the move's produces, so it covers every lane with no per-move authoring, and a privesc move
  // never wrongly tells a root user to fix their PTY.
  var NEW_SHELL_RE = /^foothold\.|^access\.shell$/;
  var ELEVATED_RE = /^access\.(admin|system|root)$/;
  function nsOnceYouAreIn(move, facts, params) {
    if (!move) return '';
    var p = move.produces || [];
    var newShell = p.some(function (k) { return NEW_SHELL_RE.test(k); });
    var elevated = !newShell && p.some(function (k) { return ELEVATED_RE.test(k); });
    if (!newShell && !elevated) return '';
    var O = OBOL.ORIENT || {};

    if (newShell) {
      var isWin = p.indexOf('foothold.windows') >= 0;
      var isLin = p.indexOf('foothold.linux') >= 0 || p.indexOf('access.shell') >= 0;
      if (!isWin && !isLin) isLin = true;
      var orient = '';
      if (isLin && O.linux) orient += nsSetupStep(O.linux.label, O.linux.cmd);
      if (isWin && O.windows) orient += nsSetupStep(O.windows.label, O.windows.cmd);
      var html = '<p class="ns-cn-h">Once You Are In</p>'
        + '<p class="ns-oyi-lead">You have a shell. Get your bearings first, then the coach ranks your next moves. Do not forget to grab the flag.</p>';
      if (orient) html += '<div class="ns-setup">' + orient + '</div>';
      // The PTY stabilization is a real multi-step, two-machine sequence, so it is NOT crammed into one copy
      // box: it renders as ordered, machine-labelled steps (Linux shells only; Windows needs no PTY fix).
      if (isLin && OBOL.renderPtySteps) html += OBOL.renderPtySteps();
      return html;
    }
    // Elevation: you already have a working shell and just became root/SYSTEM. No PTY to fix. Reuse the
    // proof-flag move, whose command confirms the new identity and reads the flag in one frame.
    var win = p.indexOf('access.system') >= 0;
    var flagMove = win ? 'flag-hunt-root-windows' : 'flag-hunt-root-linux';
    return '<p class="ns-cn-h">You Have ' + (win ? 'SYSTEM' : 'Root') + ' Now</p>'
      + '<p class="ns-oyi-lead">Capture the proof flag with your new identity in the same window. One screenshot proves all of it, and that is what the exam grades.</p>'
      + '<div class="ns-setup">' + nsReuseSteps(flagMove, facts, params) + '</div>';
  }
  // "Learn More": the canonical, comprehensive source for the whole technique family, so a learner is never
  // left with just the one example command. Reuses the pack's own `refs` (the same links the Learn tab uses,
  // one source of truth) plus a curated best-pick per move (OBOL.FIELD_MOVE[id].refs), including the
  // interactive "back ends" that beat any static command (revshells.com, CrackStation, GTFOBins).
  var REF_HOSTS = {
    'gtfobins.github.io': 'GTFOBins', 'book.hacktricks.wiki': 'HackTricks', 'hacktricks.wiki': 'HackTricks',
    'portswigger.net': 'PortSwigger Academy', 'swisskyrepo.github.io': 'PayloadsAllTheThings',
    'github.com': 'GitHub', 'thehacker.recipes': 'The Hacker Recipes', 'netexec.wiki': 'NetExec Wiki',
    'hashcat.net': 'hashcat', 'crackstation.net': 'CrackStation', 'revshells.com': 'revshells.com',
    'owasp.org': 'OWASP', 'ired.team': 'ired.team', '0xdf.gitlab.io': '0xdf', 'ippsec.rocks': 'IppSec',
    'exploit-db.com': 'Exploit-DB', 'attack.mitre.org': 'MITRE ATT&CK',
  };
  function refLabel(url) {
    try { var h = new URL(url).hostname.replace(/^www\./, ''); return REF_HOSTS[h] || h; } catch (e) { return 'reference'; }
  }
  // GTFOBins resolver block: for the sudo / SUID moves, surface the EXACT escape for each binary the parser
  // already identified from pasted output, pre-filled and copy-ready, with the deep link to the exact page.
  // Also a live lookup box so a learner can type any binary and get the escape, even before a fact exists.
  function nsGtfoRow(it) {
    var head = '<div class="ns-gtfo-bin">' + esc(it.bin)
      + '<a class="ns-gtfo-link" href="' + U.attr(it.url) + '" target="_blank" rel="noopener noreferrer">GTFOBins <span aria-hidden="true">↗</span></a></div>';
    var body = it.command
      ? '<div class="ns-setup-cmd"><code>' + esc(it.command) + '</code>'
        + '<button class="btn-copy ns-setup-copy" data-copy="' + U.attr(it.command) + '" title="Copy" aria-label="Copy command">' + OBOL.ic('clip') + '</button></div>'
      : '<div class="ns-gtfo-none">GTFOBins lists an escape for this one. Open the page for the exact command (it wraps another tool, so it is best read there).</div>';
    return '<div class="ns-gtfo-row">' + head + body + '</div>';
  }
  function nsGtfobins(move, facts) {
    if (!move || !OBOL.resolve || !OBOL.resolve.gtfobinsForMove) return '';
    var r = OBOL.resolve.gtfobinsForMove(move.id, facts);
    if (!r) return '';
    var ctxLabel = r.context === 'suid' ? 'SUID' : 'Sudo';
    var rows = r.items.map(nsGtfoRow).join('');
    var intro = r.items.length
      ? '<p class="ns-oyi-lead">obol found ' + r.items.length + ' that GTFOBins can turn into a root shell. Here ' + (r.items.length === 1 ? 'is' : 'are') + ' the exact escape' + (r.items.length === 1 ? '' : 's') + ':</p>'
      : '<p class="ns-oyi-lead">Paste your ' + (r.context === 'suid' ? 'SUID list' : '<code>sudo -l</code>') + ' output on Evidence and obol fills the exact escape here. Or look one up now:</p>';
    var lookup = '<div class="ns-gtfo-lookup"><label class="cmd-fill-lbl"><span>Look Up A Binary</span>'
      + '<input class="ns-gtfo-input" data-ctx="' + r.context + '" placeholder="e.g. find, awk, vim, less" autocomplete="off" spellcheck="false"></label>'
      + '<div class="ns-gtfo-result" aria-live="polite"></div></div>';
    return '<p class="ns-cn-h">GTFOBins: Exact ' + ctxLabel + ' Escape</p>' + intro
      + (rows ? '<div class="ns-setup">' + rows + '</div>' : '') + lookup;
  }
  // "Build In Workbench": deep links from a move to the Workbench tool that helps with it. Presentation
  // only, it never changes which command the coach ranks. Classify by what the move PRODUCES and the tools
  // it uses (both authored in the pack), so it stays correct as the pack evolves.
  var WB_DIR_TOOLS = { gobuster: 1, ffuf: 1, feroxbuster: 1, dirb: 1, dirbuster: 1, wfuzz: 1 };
  function nsWorkbenchTargets(move) {
    if (!move) return [];
    var tools = {}; if (move.tool) tools[String(move.tool).toLowerCase()] = 1;
    (move.tools || []).forEach(function (t) { if (t) tools[String(t).toLowerCase()] = 1; });
    var produces = (move.produces || []).join(' ');
    var idt = (move.id || '') + ' ' + (move.title || '');
    var out = [], seen = {};
    function add(tab, label) { if (!seen[tab]) { seen[tab] = 1; out.push({ tab: tab, label: label }); } }

    // a hash to crack or identify
    if (/\bhash\./.test(produces) || tools.hashcat || tools.john || /roast|ntds|secretsdump|lsass|\bsam\b|dcsync|hashdump/i.test(idt)) {
      add('hashid', 'Identify / Crack In Workbench');
    }
    // a sudo / SUID escape
    if (move.id === 'sudo-abuse' || move.id === 'suid-gtfobins' || /gtfobins/i.test(idt)) {
      add('gtfobins', 'Open GTFOBins Browser');
    }
    // WEB content discovery / vhosts only. Gate on the actual tools (gobuster/ffuf/feroxbuster/dirb/
    // wfuzz), or a title that is unambiguously about web fuzzing. NOT a bare "discovery" (that matched
    // "Nmap Fast TCP Open-Port Discovery" and wrongly offered a wordlist on the first scan).
    var usesDirTool = Object.keys(tools).some(function (k) { return WB_DIR_TOOLS[k]; });
    if (usesDirTool || /content discovery|directory brute|directory fuzz|web.?fuzz|virtual host|vhost|subdomain enum/i.test(idt)) {
      var wlTask = /vhost|virtual host|subdomain/i.test(idt) ? 'subdomains' : 'dirs';
      add('wordlists/' + wlTask, 'Pick A Wordlist');
    }
    // a reverse shell / listener
    if (/foothold\.|access\.shell/.test(produces) || tools.nc || tools.ncat || tools.socat || tools.msfvenom || /reverse shell|listener|\brevshell\b/i.test(idt)) {
      add('revshell', 'Build A Reverse Shell');
    }
    // JWT
    if (/\bjwt\b|json web token/i.test(idt)) add('jwt', 'Decode The JWT');
    // manual SQL injection: the Workbench builds the payloads step by step
    if (/sql injection|sqli|sql-inj/i.test(idt)) add('sqli', 'Build The SQLi');
    // payloads that often need encoding or evasion (LFI/traversal, command injection, XSS)
    if (/command inj|cmdi|local file inclusion|\blfi\b|traversal|\bxss\b|cross-site script/i.test(idt)) add('encoder', 'Encode A Payload');
    return out.slice(0, 2);
  }
  function nsWorkbench(move) {
    var targets = nsWorkbenchTargets(move);
    if (!targets.length) return '';
    return '<div class="ns-wb"><span class="ns-wb-l">Build In Workbench</span>'
      + targets.map(function (t) {
          return '<a class="ns-wb-link" href="#/workbench/' + esc(t.tab) + '">' + esc(t.label)
            + '<span class="ns-wb-arrow" aria-hidden="true">→</span></a>';
        }).join('') + '</div>';
  }

  function nsLearnMore(move) {
    if (!move) return '';
    var out = [], seen = {};
    var curated = ((OBOL.FIELD_MOVE || {})[move.id] || {}).refs || [];
    curated.forEach(function (r) { var u = r.url || r; var l = r.label || refLabel(u); if (u && !seen[u]) { seen[u] = 1; out.push({ url: u, label: l }); } });
    (move.refs || []).forEach(function (u) { if (u && !seen[u]) { seen[u] = 1; out.push({ url: u, label: refLabel(u) }); } });
    if (!out.length) return '';
    out = out.slice(0, 5);
    return '<p class="ns-cn-h">Learn More</p><div class="ns-learn">'
      + out.map(function (r) {
          return '<a class="ns-learn-link" href="' + U.attr(r.url) + '" target="_blank" rel="noopener noreferrer">'
            + esc(r.label) + '<span class="ns-learn-ext" aria-hidden="true">↗</span></a>';
        }).join('')
      + '</div>';
  }
  function dynamicPivots(move) {
    if (!move) return [];
    var prod = move.produces || [];
    var out = [];
    if (prod.indexOf('hash.tgs') >= 0 || prod.indexOf('hash.asrep') >= 0) {
      out.push({ trigger: 'Kerberos Hash Recovered', action: 'Feed hash to Hashcat (-m 13100 for TGS, -m 18200 for AS-REP) against rockyou.txt wordlist.' });
    }
    if (prod.indexOf('credential.validated') >= 0 || prod.indexOf('smb.authenticated') >= 0) {
      out.push({ trigger: 'Validated Domain Credential', action: 'Test administrative shares (C$, ADMIN$) with NetExec for (Pwn3d!) status, or collect domain graph with BloodHound.' });
    }
    if (prod.indexOf('ad.user_list') >= 0) {
      out.push({ trigger: 'Usernames Enumerated', action: 'Sweep for pre-authentication disabled accounts (GetNPUsers.py) and spray known passwords with NetExec.' });
    }
    if (prod.indexOf('ad.attack_paths') >= 0 || prod.indexOf('ad.acl_lead') >= 0) {
      out.push({ trigger: 'Control Path Identified', action: 'Abuse target ACL (GenericAll / WriteDacl) via bloodyAD to force password reset or grant DCSync rights.' });
    }
    if (prod.indexOf('loot.ntds') >= 0 || prod.indexOf('access.admin') >= 0 || prod.indexOf('access.system') >= 0) {
      out.push({ trigger: 'Administrative Compromise', action: 'Replicate domain hashes with secretsdump DCSync or Pass-the-Hash (PtH) across internal segment.' });
    }
    if (prod.some(function (k) { return /^foothold\./.test(k); })) {
      out.push({ trigger: 'Initial Shell Landed', action: 'Stabilize PTY session, run situational awareness (whoami /priv), and locate user.txt flag.' });
    }
    if (!out.length && prod.length) {
      out.push({ trigger: 'Move Completed', action: 'Minted facts advance the coach frontier; check Ready Now for the next unlocked commands.' });
    }
    return out;
  }

  function nsDoctorBlock(d, facts) {
    var code = d.code || '';
    if (code && OBOL.command && OBOL.command.buildContext) {
      var act = OBOL.store ? OBOL.store.active() : null;
      var f = facts || (act && act.facts) || [];
      var ctx = OBOL.command.buildContext(f, { params: (act && act.params), profile: (act && act.profile), workspace: (OBOL.workspace && act) ? OBOL.workspace.tokens(act) : {} });
      if (ctx.target) code = code.replace(/<target(?:-ip)?>/g, ctx.target);
      if (ctx.domain) code = code.replace(/<domain>/g, ctx.domain);
      if (ctx.share) code = code.replace(/<share>/g, ctx.share);
      if (ctx.user) code = code.replace(/<user(?:name)?>/g, ctx.user);
    }
    return '<div class="ns-doctor"><div class="ns-doctor-h">' + OBOL.ic('shield') + ' ' + esc(d.title) + '</div>'
      + (d.why ? ('<div class="ns-doctor-why"><strong>Root Cause:</strong> ' + esc(d.why) + '</div>') : '')
      + '<p>' + esc(d.body) + '</p>' + (code ? '<pre class="ns-doctor-code"><code>' + esc(code) + '</code></pre>'
        + '<div class="ns-doctor-actions"><button type="button" class="btn-copy" data-copy="' + U.attr(code) + '">Copy Fix</button></div>' : '')
      + (d.gotcha ? ('<div class="ns-doctor-gotcha"><strong>Gotcha / Trap:</strong> ' + esc(d.gotcha) + '</div>') : '')
      + '</div>';
  }

  // "See It Run": the Learn-style command + sample output, inline on the field-note card and toggleable.
  // Reuses OBOL.study.replayFor (the exact invocation + captured output the Learn Watch pane shows), so a
  // learner sees what the command looks like run and the output to expect, without leaving Next Steps. The
  // on/off choice persists (localStorage), so once you turn it on it stays on across every move.
  function exampleOn() { try { var v = localStorage.getItem('obol.show-example'); return v === null ? true : v === '1'; } catch (e) { return true; } }
  function nsExampleBlock(move) {
    if (!move || !OBOL.study || !OBOL.study.replayFor) return '';
    var rp = null; try { rp = OBOL.study.replayFor(move.id); } catch (e) { rp = null; }
    if (!rp || !rp.hasOutput || !rp.steps || !rp.steps.length) return ''; // only promise it where real output exists
    var open = exampleOn();
    var promptFor = function (where) { return where === 'host' ? 'C:\\>' : 'kali$'; };
    var body = rp.steps.map(function (s) {
      var head = rp.multi ? ('<div class="ns-ex-step">' + (s.where === 'host' ? 'On the target' : 'On your box') + '</div>') : '';
      var cmdLine = '<div class="rp-line rp-cmd"><span class="rp-prompt' + (s.where === 'host' ? ' host' : '') + '">' + promptFor(s.where) + '</span> ' + esc(s.command) + '</div>';
      var outs = (s.outputLines || []).map(function (ln) {
        var hot = rp.signal && String(ln).indexOf(rp.signal) >= 0;
        return '<div class="rp-line rp-out' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</div>'
          + (hot && rp.teach ? '<div class="rp-cap">\u2190 ' + esc(rp.teach) + '</div>' : '');
      }).join('');
      return head + cmdLine + outs;
    }).join('');
    return '<div class="ns-ex' + (open ? ' open' : '') + '">'
      + '<button type="button" class="ns-ex-toggle" data-ex-toggle aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<span class="ns-ex-caret" aria-hidden="true">\u25B8</span> See It Run'
      + '<span class="ns-ex-sub">a real run of this command and the output you would see</span></button>'
      + '<div class="ns-ex-term rp-term"' + (open ? '' : ' hidden') + '>' + body + '</div>'
      + '</div>';
  }

  function nsCanvasHtml(move, idx, facts, params) {
    if (!move) return '<div class="ns-canvas-head"><span class="ns-canvas-kick">Field Notes</span></div>'
      + '<div class="ns-canvas-empty">Pick a move on the left to see how to land it, step by step.</div>';
    var filled = OBOL.command.fillAll(move, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) });
    var cmdText = (filled[idx] && filled[idx].filled) || '';
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, idx) : null;
    var live = nsLiveDoctors(facts);
    var html = '<div class="ns-canvas-head"><span class="ns-canvas-kick">Field Notes</span>'
      + '<span class="ns-canvas-sep">·</span>'
      + '<span class="ns-canvas-move" title="' + U.attr(move.title) + '">' + esc(move.title) + '</span></div>'
      + '<div class="ns-canvas-body">';

    live.forEach(function (d) { html += nsDoctorBlock(d, facts); });

    // Staged command display
    if (cmdText) html += '<div class="ns-canvas-cmd"><code>' + esc(cmdText) + '</code></div>';

    // "See It Run": toggleable Learn-style example run + expected output for this move.
    html += nsExampleBlock(move);

    var flagsExpl = (OBOL.command && OBOL.command.explainFlags) ? OBOL.command.explainFlags(cmdText) : [];
    var mistakes = (note && note.mistakes) || [];
    var lookSignals = (note && note.look) || [];
    var hasDoctor = (note && note.doctor) || (live && live.length > 0);

    // Active tab preference (default: p1 for zero-scroll focused view)
    var activeTab = 'p1';
    try {
      var savedTab = sessionStorage.getItem('obol.pillar-tab');
      if (savedTab && ['p1', 'p2', 'p3', 'p4', 'all'].indexOf(savedTab) >= 0) {
        activeTab = savedTab;
      }
    } catch (e) {}

    // Segmented Pillar Tab Bar (keyboard navigable, zero-scroll)
    html += '<div class="anatomy-tabs" role="tablist" aria-label="Anatomy Pillars">'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p1' ? ' on' : '') + '" data-pillar-tab="p1" aria-selected="' + (activeTab === 'p1' ? 'true' : 'false') + '"><span class="tab-badge badge-p1">1</span> Goal</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p2' ? ' on' : '') + '" data-pillar-tab="p2" aria-selected="' + (activeTab === 'p2' ? 'true' : 'false') + '"><span class="tab-badge badge-p2">2</span> Syntax' + (flagsExpl.length ? ' <span class="tab-count">' + flagsExpl.length + '</span>' : '') + '</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p3' ? ' on' : '') + '" data-pillar-tab="p3" aria-selected="' + (activeTab === 'p3' ? 'true' : 'false') + '"><span class="tab-badge badge-p3">3</span> Gotchas' + (mistakes.length || hasDoctor ? ' <span class="tab-warn-dot" title="Gotchas or diagnostic tips available">!</span>' : '') + '</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p4' ? ' on' : '') + '" data-pillar-tab="p4" aria-selected="' + (activeTab === 'p4' ? 'true' : 'false') + '"><span class="tab-badge badge-p4">4</span> Pivot</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn anatomy-tab-all' + (activeTab === 'all' ? ' on' : '') + '" data-pillar-tab="all" aria-selected="' + (activeTab === 'all' ? 'true' : 'false') + '">Show All</button>'
      + '</div>';

    // ---- PILLAR 1: THE GOAL ----
    var goalText = (note && note.what) || move.hypothesis || move.description || move.title;
    var whenText = (note && note.when) || '';
    var winText = (note && note.win) || '';

    html += '<section class="anatomy-pillar pillar-goal" data-pillar-section="p1"' + (activeTab !== 'all' && activeTab !== 'p1' ? ' hidden' : '') + '>'
      + '<div class="pillar-header">'
      + '<span class="pillar-badge badge-p1">Pillar 1</span>'
      + '<h4 class="pillar-title">The Goal</h4>'
      + '</div>'
      + '<div class="pillar-content">'
      + '<p class="pillar-text"><strong>Objective:</strong> ' + esc(goalText) + '</p>'
      + (whenText ? ('<div class="pillar-subtext"><strong>When To Run:</strong> ' + esc(whenText) + '</div>') : '')
      + (winText ? ('<div class="ns-cn-win"><span class="ns-tick" aria-hidden="true">✓</span><span><strong>Expected Proof:</strong> ' + fmtNote(winText) + '</span></div>') : '')
      + '<div class="anatomy-pill-nav"><button type="button" class="anatomy-next-pill-btn" data-pillar-tab="p2">Next: 2. Syntax & Flags →</button></div>'
      + '</div></section>';

    // ---- PILLAR 2: SYNTAX & FLAG ANATOMY ----
    html += '<section class="anatomy-pillar pillar-syntax" data-pillar-section="p2"' + (activeTab !== 'all' && activeTab !== 'p2' ? ' hidden' : '') + '>'
      + '<div class="pillar-header">'
      + '<span class="pillar-badge badge-p2">Pillar 2</span>'
      + '<h4 class="pillar-title">Syntax & Flag Anatomy</h4>'
      + '</div>'
      + '<div class="pillar-content">';

    if (flagsExpl.length) {
      html += '<div class="anatomy-flags"><span class="anatomy-flags-head">Flag Deconstruction</span><div class="anatomy-flag-list">'
        + flagsExpl.map(function (f) {
            var fullVal = f.fullValue || f.value || '';
            var valHtml = f.value ? ('<code class="anatomy-flag-val" title="' + U.attr(fullVal) + '">' + esc(f.value) + '</code>') : '';
            return '<div class="anatomy-flag-row">'
              + '<div class="anatomy-flag-label"><span class="anatomy-flag-pill"><code>' + esc(f.flag) + '</code></span>' + valHtml + '</div>'
              + '<span class="anatomy-flag-desc">' + esc(f.meaning) + '</span>'
              + '</div>';
          }).join('')
        + '</div></div>';
    }

    var selCmd = (move.commands || [])[idx] || {};
    var stage = (OBOL.stagingFor && OBOL.pack.commandIsOnHost(selCmd)) ? OBOL.stagingFor(selCmd.tool) : null;
    if (stage && OBOL.renderToolStaging) html += OBOL.renderToolStaging(stage, params);

    if (note) {
      var setupSteps = '', setupCmds = [];
      var isCmdOnHost = OBOL.pack.commandIsOnHost(selCmd);
      var hasHostAccess = facts.has('access.shell') || facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('access.admin') || facts.has('access.system');
      if (isCmdOnHost && !hasHostAccess) {
        var connCmd = '';
        if (facts.has('port:5985') && facts.has('credential.available')) {
          connCmd = nsFill({ cmd: "evil-winrm -i {{target}} -u '{{user}}' -p '{{password}}'" }, facts, params);
        } else if (facts.has('port:22') && facts.has('credential.available')) {
          connCmd = nsFill({ cmd: "ssh {{user}}@{{target}}" }, facts, params);
        } else if (facts.has('credential.available')) {
          connCmd = nsFill({ cmd: "evil-winrm -i {{target}} -u '{{user}}' -p '{{password}}'" }, facts, params);
        }
        if (connCmd) {
          setupCmds.unshift(connCmd);
          setupSteps = nsSetupStep('Connect to Host First (You are not in a shell yet)', connCmd) + setupSteps;
        }
      }
      (note.setup || []).forEach(function (s) {
        var cmd = nsFill(s.cmd || s, facts, params);
        if (cmd) setupCmds.push(cmd);
        setupSteps += nsSetupStep(s.label || '', cmd);
      });
      (note.use || []).forEach(function (refId) {
        setupSteps += nsReuseSteps(refId, facts, params);
      });
      if (setupSteps) {
        var allBtn = setupCmds.length >= 2
          ? '<button type="button" class="btn-copy ns-setup-all" data-copy="' + U.attr(setupCmds.join('\n')) + '" title="Copy all setup commands as one block">Copy All ' + setupCmds.length + ' Steps</button>'
          : '';
        html += '<p class="ns-cn-h">Set Up First' + allBtn + '</p><div class="ns-setup">' + setupSteps + '</div>';
      }
      if (note.land && note.land.length) {
        html += '<div class="anatomy-land"><span class="anatomy-subhead">Execution Steps</span><ul class="ns-cn-list">'
          + note.land.map(function (l) { return '<li>' + fmtNote(l) + '</li>'; }).join('') + '</ul></div>';
      }
    }
    html += '<div class="anatomy-pill-nav">'
      + '<button type="button" class="anatomy-prev-pill-btn" data-pillar-tab="p1">← 1. Goal</button>'
      + '<button type="button" class="anatomy-next-pill-btn" data-pillar-tab="p3">Next: 3. Gotchas →</button>'
      + '</div>'
      + '</div></section>';

    // ---- PILLAR 3: THE GOTCHAS ----
    html += '<section class="anatomy-pillar pillar-gotchas" data-pillar-section="p3"' + (activeTab !== 'all' && activeTab !== 'p3' ? ' hidden' : '') + '>'
      + '<div class="pillar-header">'
      + '<span class="pillar-badge badge-p3">Pillar 3</span>'
      + '<h4 class="pillar-title">Gotchas & Traps</h4>'
      + '</div>'
      + '<div class="pillar-content">';

    if (mistakes.length) {
      html += '<div class="anatomy-mistakes"><span class="anatomy-subhead">Common Mistakes</span><ul class="ns-cn-list warn">'
        + mistakes.map(function (l) { return '<li>' + fmtNote(l) + '</li>'; }).join('') + '</ul></div>';
    } else {
      html += '<p class="pillar-text-dim">Escape special bash characters like <code>$</code> and <code>!</code> with single quotes. Confirm domain controller name resolves in <code>/etc/hosts</code>.</p>';
    }

    if (lookSignals.length) {
      html += '<div class="anatomy-look"><span class="anatomy-subhead">What To Look For</span><ul class="ns-cn-list look">'
        + lookSignals.map(function (l) { return '<li>' + fmtNote(l) + '</li>'; }).join('') + '</ul></div>';
    }

    if (note && note.doctor) html += nsDoctorBlock(note.doctor, facts);

    html += '<div class="anatomy-pill-nav">'
      + '<button type="button" class="anatomy-prev-pill-btn" data-pillar-tab="p2">← 2. Syntax</button>'
      + '<button type="button" class="anatomy-next-pill-btn" data-pillar-tab="p4">Next: 4. The Pivot →</button>'
      + '</div>'
      + '</div></section>';

    // ---- PILLAR 4: THE PIVOT ----
    html += '<section class="anatomy-pillar pillar-pivot" data-pillar-section="p4"' + (activeTab !== 'all' && activeTab !== 'p4' ? ' hidden' : '') + '>'
      + '<div class="pillar-header">'
      + '<span class="pillar-badge badge-p4">Pillar 4</span>'
      + '<h4 class="pillar-title">The Pivot (Next Move)</h4>'
      + '</div>'
      + '<div class="pillar-content">';

    var pivots = dynamicPivots(move);
    if (pivots.length) {
      html += '<ul class="pillar-pivot-list">'
        + pivots.map(function (p) { return '<li><strong>' + esc(p.trigger) + ':</strong> ' + esc(p.action) + '</li>'; }).join('')
        + '</ul>';
    }

    var yields = (move.produces || []).map(function (k) { return OBOL.pack.chipLabel ? OBOL.pack.chipLabel(k) : k; });
    if (yields.length) {
      html += '<div class="pillar-yields"><span>Yields Proven Facts:</span> '
        + yields.map(function (y) { return '<span class="ns-factchip">' + esc(y) + '</span>'; }).join(' ')
        + '</div>';
    }

    html += nsGtfobins(move, facts);
    html += nsOnceYouAreIn(move, facts, params);
    html += stagingGuide(move, params);
    html += nsWorkbench(move);
    html += nsLearnMore(move);

    html += '<div class="anatomy-pill-nav">'
      + '<button type="button" class="anatomy-prev-pill-btn" data-pillar-tab="p3">← 3. Gotchas</button>'
      + '<button type="button" class="anatomy-next-pill-btn" data-pillar-tab="all">Show All 4 Pillars ≡</button>'
      + '</div>'
      + '</div></section>';

    html += '</div>';
    return html;
  }

  // The aspirational "Opens Up Next" strip: capability-unlocks only, nearest first, each with its fact
  // chips. Capped to a peek with a "+N more" expander so it invites rather than overwhelms.
  function nsOpensStrip(opens) {
    if (!opens.length) return '';
    var CAP = 8;
    function card(o) {
      var famClass = ' ns-ph-' + OBOL.phases.phaseOfAction(o.action);
      var chips = o.needs.slice(0, 3).map(function (k) { var lbl = OBOL.pack.chipLabel(k); return '<span class="ns-factchip" title="' + U.attr(lbl) + '">' + esc(lbl) + '</span>'; }).join('');
      return '<div class="ns-ocard' + famClass + '">' + OBOL.ic('lock')
        + '<div class="ns-ocard-t">' + esc(o.action.title) + '</div>'
        + '<div class="ns-needs"><span class="ns-needs-l">Needs</span>' + chips + '</div>'
        + '<div class="ns-ocard-near">' + o.steps + ' Step' + (o.steps === 1 ? '' : 's') + ' Away</div></div>';
    }
    var peek = opens.slice(0, CAP), more = opens.slice(CAP);
    return '<section class="ns-opens"><div class="ns-opens-head">'
      + '<span class="ns-opens-kick">Opens Up Next</span>'
      + '<span class="ns-opens-sub">What a little more progress unlocks, closest first.</span>'
      + '<span class="ns-opens-n">' + opens.length + '</span></div>'
      + '<div class="ns-opens-peek">' + peek.map(card).join('') + '</div>'
      + (more.length ? '<details class="ns-opens-more"><summary>' + more.length + ' more, further out</summary>'
          + '<div class="ns-opens-peek">' + more.map(card).join('') + '</div></details>' : '')
      + '</section>';
  }

  // The live context rail (wide screens): access level, next move, flags, creds, recent evidence.
  // Shared with the per-target page via OBOL.rail.html.
  function railCard(title, inner) { return '<div class="rail-card"><div class="rail-h">' + esc(title) + '</div>' + inner + '</div>'; }
  function buildRail(eng, facts, topMove) {
    var access = facts.has('access.system') ? ['SYSTEM', 'sys'] : facts.has('access.admin') ? ['Admin / root', 'adm']
      : (facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('access.shell')) ? ['Foothold', 'fh']
      : facts.has('credential.available') ? ['Credentialed', 'cred'] : ['Recon', 'recon'];
    var objFacts = (facts.facts || []).filter(function (f) { return String(f.kind).indexOf('objective.') === 0 && f.state !== 'refuted'; });
    var flags = objFacts.filter(function (f) { return f.kind !== 'objective.flag_located'; });
    // Located-but-not-captured: found remotely (nxc/smb), still to be read from an on-host shell for the
    // report. Hide any whose value we have already captured on-host.
    var capturedVals = {}, capturedSlots = {};
    flags.forEach(function (f) { var v = f.value || {}; if (v.flag) capturedVals[v.flag] = 1; if (v.slot) capturedSlots[v.slot] = 1; });
    var locSeen = {};
    var located = objFacts.filter(function (f) {
      if (f.kind !== 'objective.flag_located') return false;
      var v = f.value || {};
      if ((v.flag && capturedVals[v.flag]) || (v.slot && capturedSlots[v.slot])) return false; // already captured on-host
      var key = v.path || v.flag || v.slot || ''; if (locSeen[key]) return false; locSeen[key] = 1; return true;
    });
    // Use the same deduped gather as the left switcher, so one recovered credential proven on two scopes
    // (e.g. host:10.x and host:10.y) shows ONCE here, not twice.
    var creds = [];
    try { creds = (OBOL.creds && OBOL.creds.gather) ? OBOL.creds.gather(eng, facts) : (facts.values('credential.available') || []); } catch (e) { creds = []; }
    var acts = (eng && eng.activities || []).slice(0, 4);
    return '<aside class="context-rail" aria-label="Live context">'
      + railCard('Access', '<div class="rail-access ra-' + access[1] + '">' + esc(access[0]) + '</div>')
      + railCard('Next Move', topMove ? ('<div class="rail-move">' + esc(topMove.title) + '</div>') : '<div class="rail-empty">Log evidence to unlock moves.</div>')
      + railCard('Flags (' + flags.length + ')', (flags.length || located.length)
        ? '<ul class="rail-list rail-flags">' + flags.map(function (f) {
            var v = f.value || {}; var SL = { root: 'Root Flag', local: 'Local Flag', user: 'Local Flag' };
            var label = SL[v.slot] || U.titleCase(f.kind.split('.').pop().replace('_', ' '));
            var val = v.flag || '';
            // Show the WHOLE flag (wrapped, selectable, click-to-copy) — a captured flag is the deliverable.
            return '<li class="rail-flag"><div class="rail-flag-h"><span>' + OBOL.ic('flag') + ' ' + esc(label) + '</span>'
              + (v.name ? '<span class="rail-flag-file" title="' + U.attr(v.path || v.name) + '">' + esc(v.name) + '</span>' : '') + '</div>'
              + (val ? '<code class="rail-flag-val" data-copy="' + U.attr(val) + '" title="Click to copy">' + esc(val) + '</code>' : '') + '</li>';
          }).join('')
          + located.map(function (f) {
            var v = f.value || {}; var SL = { root: 'Root Flag', local: 'Local Flag', user: 'Local Flag' };
            var label = SL[v.slot] || 'Flag';
            return '<li class="rail-located" title="' + U.attr('located remotely at ' + (v.path || v.name || '') + ', read it from an on-host shell for the report') + '"><span>' + OBOL.ic('pin') + ' ' + esc(label) + ' <em>Located</em></span><span class="rail-produced">Capture On-Host</span></li>';
          }).join('')
          + '</ul>' + (located.length ? '<div class="rail-note">' + OBOL.ic('pin') + ' located remotely, read on the host (interactive shell) so it counts for the report.</div>' : '')
        : '<div class="rail-empty">None captured yet.</div>')
      + railCard('Credentials (' + creds.length + ')', creds.length
        ? '<ul class="rail-list">' + creds.slice(0, 6).map(function (c) {
            var secret = c.secret || c.password || c.nthash || c.hash || '';
            var redact = !!((eng || {}).ui || {}).reportRedact;
            var shown = !secret ? '' : (redact ? '••••••••' : (secret.length > 22 ? secret.slice(0, 22) + '…' : secret));
            return '<li><span>' + esc(c.user || c.username || 'user') + (c.domain ? '@' + esc(c.domain) : '') + '</span>'
              + (shown ? '<span class="rail-secret"' + (redact ? '' : ' title="' + U.attr(secret) + '"') + '>' + esc(shown) + '</span>' : '') + '</li>';
          }).join('') + '</ul>'
        : '<div class="rail-empty">None validated yet.</div>')
      + railCard('Recent Evidence', (acts.length
        ? '<ul class="rail-list rail-acts">' + acts.map(function (a) { var c = a.command || (a.file ? a.file : 'pasted output'); return '<li title="' + U.attr(c) + '"><code>' + esc(c.length > 30 ? c.slice(0, 30) + '…' : c) + '</code><span class="rail-produced">' + ((a.produced || []).length) + '</span></li>'; }).join('') + '</ul>'
        : '<div class="rail-empty">Paste tool output on Evidence.</div>')
        + '<a class="rail-link" href="#/history">View Full Run Log →</a>')
      + '</aside>';
  }
  OBOL.rail = { html: buildRail };

  // Shared coach computation — the SINGLE source of truth for "what's next". Used by this coach AND by
  // the engagement Hub's "Your Next Move" anchor, the Hub's per-target cards, and the Evidence summary,
  // so every screen shows the same move instead of disagreeing (the Hub used to call the old v1 ranker
  // while the coach called v2). Report-only writeup checks (OBOL.pack.isReportOnly) are pulled out of the
  // live ready/coming-up lists into their own group, so an info-severity finding (SPF/DMARC, headers, …)
  // can never headline a box you're actively working.
  function computeCoach(overrideTarget) {
    var eng = OBOL.store.active();
    var targetIp = (overrideTarget !== undefined) ? overrideTarget : (OBOL.store.activeTarget ? OBOL.store.activeTarget() : null);
    var facts = (targetIp && OBOL.store.factSetForTarget) ? OBOL.store.factSetForTarget(targetIp) : OBOL.store.factSet();
    return rankFor(facts, { target: targetIp });
  }
  // rankFor(facts, opts) is computeCoach generalized to ANY factset — the engagement-wide one for this coach and
  // the Hub anchor, or a single host's (factSetForTarget) for the per-target "Next Steps for this box"
  // panel — so every surface ranks moves the same way and shows the same prep steps. Report-only writeup
  // checks are split out; the frontier/phase are computed from the passed facts (correct per scope).
  function rankFor(facts, opts) {
    opts = opts || {};
    var eng = OBOL.store.active();
    var params = Object.assign({}, (eng && eng.params) || {});
    if (opts.target) params.target = opts.target;
    var pack = OBOL.packs.actions();
    var doneIds = {};
    // 'done' = the operator ticked it; 'empty' = its tool ran and proved nothing (a useless path RIGHT NOW,
    // e.g. no SCCM in this environment). Both retire the move from the ready list. The un-retire test is per
    // MOVE, not per fact-KIND: a move stays retired only while NONE of its OWN runs ever produced a fact.
    function moveEverProduced(actionId) {
      return (eng && eng.activities || []).some(function (a) { return a && a.action_id === actionId && (a.produced || []).length > 0; });
    }
    Object.keys((eng && eng.checklist) || {}).forEach(function (k) {
      var st = eng.checklist[k];
      if (st === 'done') { doneIds[k] = true; return; }
      if (st === 'empty' && !moveEverProduced(k)) doneIds[k] = true; // never paid off → stay retired
    });

    var focus = (OBOL.profile && eng && eng.profile) ? OBOL.profile.profileFocus(eng.profile) : [];
    var ranked = (OBOL.pack.rankActions || OBOL.pack.nextActions)(facts, pack, { doneIds: doneIds, focusPrefixes: focus });
    var frontier = OBOL.phases.frontierIndex(facts);
    var onFlow = [], comingUp = [], reportChecks = [];
    function reportOnly(a) { return !!(OBOL.pack.isReportOnly && OBOL.pack.isReportOnly(a, pack)); }
    // Trap-doctor moves (gated on a pasted-error blocker.* fact, or producing only advice.*) are NOT cards
    // in the rail — their fix surfaces reactively in the field-notes canvas the moment the blocker mints.
    // Keeping them out of the grid is the de-clutter the redesign calls for; real exploit moves that happen
    // to key on a vuln.* fingerprint stay, because running them IS the next attack step.
    function isCanvasDoctor(a) {
      var gates = (a.requires_all || []).concat(a.requires_any || []);
      if (gates.some(function (k) { return /^blocker\./.test(k); })) return true;
      var prod = a.produces || [];
      return prod.length > 0 && prod.every(function (k) { return /^advice\./.test(k); });
    }
    // A move is actionable NOW only if it has a command you can actually run now: one that is neither
    // settled (already done) nor gated on a fact you have not earned. A move whose every command still
    // waits on an unearned fact (e.g. a zone transfer that needs the domain) is eligible but not ready, so
    // it drops to Coming Up until one of its commands unlocks, rather than taking a Ready Now slot with
    // nothing you can do. A move with no commands at all is left where it is.
    function hasRunnableCommand(a) {
      var cmds = a.commands || []; if (!cmds.length) return true;
      var eng = OBOL.store.active() || {};
      var filled = OBOL.command.fillAll(a, facts, { params: eng.params || {}, profile: eng.profile, workspace: OBOL.workspace.tokens(eng) });
      for (var i = 0; i < cmds.length; i++) {
        if (OBOL.pack.commandSettled(cmds[i], facts)) continue;
        if (cmdGated(filled[i])) continue;
        return true;
      }
      return false;
    }
    ranked.forEach(function (a) {
      if (isCanvasDoctor(a)) return;                                       // doctor → canvas only, never a card
      if (reportOnly(a)) { reportChecks.push(a); return; }                 // writeup check → own group, never headlines
      if (OBOL.phases.prematurity(a, facts) === 0 && hasRunnableCommand(a)) onFlow.push(a); else comingUp.push(a);
    });
    var locked = OBOL.pack.lockedActions(facts, pack);

    // Scope lens: filter the visible moves to the chosen syllabus level. Count what the lens hides so the
    // operator always knows there's more one click away (never a silent disappearance).
    var lens = lensGet();
    function inLens(a) { return scopeAllowed(a.scope, lens); }
    var hiddenBy = 0;
    function applyLens(arr) { var kept = arr.filter(inLens); hiddenBy += arr.length - kept.length; return kept; }
    onFlow = applyLens(onFlow);
    comingUp = applyLens(comingUp);
    reportChecks = applyLens(reportChecks);
    locked = locked.filter(function (p) { if (inLens(p.action)) return true; hiddenBy++; return false; });

    // Campaign filter: focus moves aligned to the selected scenario attack path
    var campId = campaignGet();
    var campTrack = (OBOL.CAMPAIGN_TRACKS || {})[campId] || null;
    var hiddenByCamp = 0;
    if (campTrack) {
      var campActions = {};
      (campTrack.phases || []).forEach(function (ph) {
        (ph.actions || []).forEach(function (aid) { campActions[aid] = true; });
      });
      function inCamp(a) { return !!campActions[a.id]; }
      var filterCamp = function (arr) {
        var kept = arr.filter(inCamp);
        hiddenByCamp += arr.length - kept.length;
        return kept;
      };
      onFlow = filterCamp(onFlow);
      comingUp = filterCamp(comingUp);
      reportChecks = filterCamp(reportChecks);
      locked = locked.filter(function (p) { if (inCamp(p.action)) return true; hiddenByCamp++; return false; });
    }

    var factCount = Object.keys(facts.kinds()).length;
    var phaseName = OBOL.phases.PHASES[frontier] || 'recon';
    return { eng: eng, facts: facts, params: params, target: opts.target || null, pack: pack, frontier: frontier,
      onFlow: onFlow, comingUp: comingUp, reportChecks: reportChecks, locked: locked,
      lens: lens, hiddenBy: hiddenBy, factCount: factCount, phaseName: phaseName,
      campId: campId, campTrack: campTrack, hiddenByCamp: hiddenByCamp };
  }
  // The authoritative ranking every screen shares, plus the renderers (prep step + full move card) so the
  // per-target panel can show the exact same "Set Up First" steps and cards the coach does.
  OBOL.coach = {
    compute: computeCoach,
    rankFor: rankFor,
    topMove: function () { return computeCoach().onFlow[0] || null; },
    topMoveFor: function (facts) { return rankFor(facts).onFlow[0] || null; },
    prepBlock: prepBlock,
    pasteSummary: pasteSummary,
  };

  // ── Positive feedback on paste ───────────────────────────────────────────────────────────────
  // After a paste mints facts, the old feedback was a 2-second toast ("Minted 9 facts, recomputing")
  // and a silent re-render, so for this audience it read as "nothing happened" even when the engine
  // learned plenty. pasteSummary turns the recognized facts into a plain-language, value-aware line of
  // what obol LEARNED (the flag captured, the credential validated, the writable groups found) plus the
  // next move it unlocked, so the tool visibly says what it did. Presentation only, no new facts.
  // _pasteFlash carries that summary across the ingest-triggered re-render (the toast element is wiped);
  // render() emits it once at the top of the coach, then clears it.
  var _pasteFlash = null;
  // Rank a fact kind by how much the operator cares to hear it announced (0 = loudest).
  function flashRank(k) {
    if (/^objective\.(root_flag|local_flag|flag)$/.test(k)) return 0;
    if (k === 'objective.flag_located') return 1;
    if (/^access\.(admin|system|root)$/.test(k)) return 2;
    if (k === 'loot.ntds' || /^hash\.(krbtgt|ntlm|asrep|tgs)$/.test(k)) return 3;
    if (/^credential\.(validated|available)$/.test(k)) return 4;
    if (/^(ad\.acl_lead|ad\.control_paths|ad\.attack_paths|ad\.group_joined|loot\.)/.test(k)) return 5;
    if (/^foothold\.|^access\.shell$/.test(k)) return 6;
    if (/^(ad\.user_list|ad\.domain_known|ad\.dc_candidate|ad\.anonymous_bind|smb\.null_session|smb\.guest_session)/.test(k)) return 7;
    if (/^(host\.|ad\.base_dn)/.test(k)) return 8;
    if (/^(service\.|port:|ports\.)/.test(k)) return 10;
    return 9;
  }
  // A short, value-aware phrase for one newly learned fact. Reads the fact's own value, never invents.
  function flashPhrase(f) {
    var k = String(f.kind || ''), v = f.value || {};
    var who = v.user || v.username || v.account || '';
    if (k === 'objective.root_flag') return 'Captured the root flag';
    if (k === 'objective.local_flag') return 'Captured the user flag';
    if (k === 'objective.flag') return 'Captured a flag';
    if (k === 'objective.flag_located') return 'Located the ' + (v.slot === 'root' ? 'root' : (v.slot === 'local' ? 'user' : '')) + ' flag' + (v.path ? (' at ' + v.path) : '');
    if (k === 'access.admin' || k === 'access.system' || k === 'access.root') return 'Gained administrative access';
    if (k === 'loot.ntds') return 'Dumped the NTDS (every domain hash)';
    if (k === 'hash.krbtgt') return 'Recovered the krbtgt hash (golden-ticket key)';
    if (k === 'hash.ntlm') return 'Recovered an NTLM hash' + (who ? (' for ' + who) : '');
    if (k === 'hash.asrep') return 'Captured an AS-REP roastable hash' + (who ? (' for ' + who) : '');
    if (k === 'hash.tgs') return 'Captured a Kerberoast hash' + (who ? (' for ' + who) : '');
    if (k === 'credential.validated') return 'Validated the credential' + (who ? (' for ' + who) : '') + ' (it works here)';
    if (k === 'credential.available') return 'A working credential' + (who ? (' for ' + who) : '');
    if (k === 'ad.acl_lead') {
      var tg = (v.targets || []).slice(0, 3);
      return 'Found writable objects' + (tg.length ? (': ' + tg.join(', ') + ((v.targets || []).length > tg.length ? (', +' + ((v.targets || []).length - tg.length) + ' more') : '')) : '');
    }
    if (k === 'ad.control_paths') return 'Gained a control path' + ((v.rights || []).length ? (' (' + (v.rights || []).join(', ') + ')') : '');
    if (k === 'ad.attack_paths') return 'Mapped an attack path to Domain Admin';
    if (k === 'ad.group_joined') return 'Joined the group ' + (v.group || '(a group)');
    if (k === 'ad.user_list') return 'Enumerated the domain user list' + (v.count ? (' (' + v.count + ' users)') : '');
    if (k === 'ad.domain_known') return 'Confirmed the domain ' + (v.name || v.domain || '');
    if (k === 'ad.dc_candidate') return 'Identified the domain controller';
    if (k === 'ad.anonymous_bind') return 'Confirmed an anonymous LDAP bind';
    if (k === 'ad.base_dn') return 'Derived the LDAP base DN';
    if (k === 'smb.null_session') return 'Confirmed an anonymous (null) SMB session';
    if (k === 'smb.guest_session') return 'Confirmed guest SMB access';
    if (/^foothold\.|^access\.shell$/.test(k)) return 'Landed a foothold on the target';
    if (k === 'blocker.acl_reauth') return 'Hit an access-denied wall on the ACL write (the fix is below: re-authenticate)';
    if (/^blocker\./.test(k)) { try { return 'Hit a known wall: ' + (OBOL.pack.friendly(k) || 'see the fix below'); } catch (e) { return 'Hit a known wall (see the fix below)'; } }
    if (k === 'host.hostname') return 'Learned the hostname ' + (v.name || v.hostname || '');
    // generic fallback: the friendly noun phrase for the kind, Title Cased
    try { if (OBOL.pack && OBOL.pack.friendly) return U.titleCase(OBOL.pack.friendly(k) || k.replace(/[._]/g, ' ')); } catch (e) {}
    return k.replace(/[._]/g, ' ');
  }
  // Build the summary object from the recognized facts of a paste. Dedup by kind (one line per kind,
  // keeping the richest value), rank, take the top few. Returns null when there is nothing worth saying.
  function pasteSummary(facts) {
    if (!facts || !facts.length) return null;
    var byKind = {};
    facts.forEach(function (f) {
      var k = f.kind; if (!k) return;
      // keep the value with the most targets/richest, else the first
      if (!byKind[k]) byKind[k] = f;
      else {
        var a = (byKind[k].value && (byKind[k].value.targets || []).length) || 0;
        var b = (f.value && (f.value.targets || []).length) || 0;
        if (b > a) byKind[k] = f;
      }
    });
    var uniq = Object.keys(byKind).map(function (k) { return byKind[k]; });
    uniq.sort(function (a, b) { return flashRank(a.kind) - flashRank(b.kind); });
    var top = uniq.slice(0, 4).map(flashPhrase).filter(Boolean);
    if (!top.length) return null;
    var extra = uniq.length - top.length;
    var next = '';
    try { var m = computeCoach().onFlow[0]; next = m ? m.title : ''; } catch (e) {}
    return { phrases: top, extra: extra > 0 ? extra : 0, total: facts.length, next: next };
  }

  function renderCampaignProgression(facts, campaignId) {
    var state = (OBOL.phases && OBOL.phases.evaluateEngagementState) ? OBOL.phases.evaluateEngagementState(facts) : {};
    var track = (OBOL.CAMPAIGN_TRACKS || {})[campaignId];

    var steps = [
      { id: 'foothold', label: '1. Initial Foothold' },
      { id: 'enum', label: '2. Internal Enumeration' },
      { id: 'creds', label: '3. Credential Harvesting' },
      { id: 'lateral', label: '4. Lateral & Domain Admin' }
    ];

    if (track && track.phases) {
      steps = track.phases.map(function (ph, idx) {
        return { id: ph.id, label: (idx + 1) + '. ' + ph.name };
      });
    }

    var activeIdx = 0;
    if (campaignId === 'ad-chain') {
      if (state.accessLevel === 'system' || state.credTier === 'admin_cred') activeIdx = 3;
      else if (state.adPosture === 'paths_mapped' || state.adPosture === 'dcsync_ready') activeIdx = 2;
      else if (state.credTier === 'crackable_hash' || state.credTier === 'domain_user') activeIdx = 1;
      else activeIdx = 0;
    } else {
      if (state.accessLevel === 'system') activeIdx = 3;
      else if (state.credTier === 'admin_cred' || state.credTier === 'domain_user' || state.credTier === 'crackable_hash') activeIdx = 2;
      else if (state.accessLevel === 'foothold' || state.adPosture === 'users_known' || state.adPosture === 'dc_identified') activeIdx = 1;
      else activeIdx = 0;
    }

    var html = '<div class="campaign-progression-bar" role="navigation" aria-label="Campaign phase progression">';
    html += '<div class="campaign-prog-track">';
    steps.forEach(function (step, i) {
      var cls = 'campaign-step';
      var stateIcon = '';
      if (i < activeIdx) {
        cls += ' done';
        stateIcon = '<span class="step-check">✓</span> ';
      } else if (i === activeIdx) {
        cls += ' active';
        stateIcon = '<span class="step-dot">●</span> ';
      } else {
        cls += ' pending';
        stateIcon = '<span class="step-num">' + (i + 1) + '</span> ';
      }
      html += '<div class="' + cls + '">'
        + '<span class="step-label">' + stateIcon + esc(step.label) + '</span>'
        + '</div>';
      if (i < steps.length - 1) {
        html += '<span class="campaign-step-arrow" aria-hidden="true">→</span>';
      }
    });
    html += '</div></div>';
    return html;
  }

  function renderHeroScopeLens(lens, hiddenBy) {
    return '<div class="coach-hero-lens" role="group" aria-label="Syllabus scope filter">'
      + '<span class="hero-lens-label">Scope</span>'
      + ['oscp', 'oscp+', 'all'].map(function (v) {
          var txt = v === 'oscp' ? 'OSCP' : (v === 'oscp+' ? 'OSCP+' : 'All');
          return '<button type="button" class="hero-lens-opt lens-opt' + (lens === v ? ' on' : '') + '" data-lens="' + v + '"'
            + ' aria-pressed="' + (lens === v ? 'true' : 'false') + '">' + txt + '</button>';
        }).join('')
      + (hiddenBy ? '<span class="hero-lens-hint" title="' + hiddenBy + ' move' + (hiddenBy === 1 ? '' : 's') + ' above this level">(' + hiddenBy + ' hidden)</span>' : '')
      + '</div>';
  }

  function renderHeroTargetSelector(eng, activeIp) {
    var tgts = (eng && eng.targets) || [];
    var curParam = (eng && eng.params && eng.params.target) || '';
    var allTgts = tgts.slice();
    if (!allTgts.length && curParam) {
      allTgts.push({ ip: curParam });
    }
    if (!allTgts.length) return '';
    var html = '<div class="coach-hero-target">'
      + '<label class="ctx-pill ctx-target" title="Focus Next Steps on a specific target or view engagement-wide">'
      + '<span class="ctx-ic" aria-hidden="true">' + (OBOL.ic ? OBOL.ic('crosshair') : '') + '</span>'
      + '<span class="ctx-k">Target</span>'
      + '<select id="coach-target-select" class="coach-target-select" aria-label="Target Filter">'
      + '<option value=""' + (!activeIp ? ' selected' : '') + '>All Targets (' + allTgts.length + ')</option>';
    allTgts.forEach(function (t) {
      var ip = t.ip || t.id;
      var name = t.hostname ? (ip + ' (' + t.hostname + ')') : ip;
      html += '<option value="' + U.attr(ip) + '"' + (activeIp === ip ? ' selected' : '') + '>' + esc(name) + '</option>';
    });
    html += '</select></label>';
    if (allTgts.length > 1) {
      html += '<div class="coach-target-pills" role="tablist" aria-label="Quick Target Selection">';
      var allActive = !activeIp ? ' active' : '';
      html += '<button type="button" class="btn-target-pill' + allActive + '" data-tid="">All Targets (' + allTgts.length + ')</button>';
      allTgts.forEach(function (t) {
        var ip = t.ip || t.id;
        var name = t.hostname ? (ip + ' (' + t.hostname + ')') : ip;
        var isAct = (activeIp === ip) ? ' active' : '';
        html += '<button type="button" class="btn-target-pill' + isAct + '" data-tid="' + esc(ip) + '">' + esc(name) + '</button>';
      });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  function render(ctx) {
    var c = computeCoach();
    var eng = c.eng, facts = c.facts, params = c.params, pack = c.pack;
    var onFlow = c.onFlow, comingUp = c.comingUp, reportChecks = c.reportChecks, locked = c.locked;
    var frontier = c.frontier, lens = c.lens, hiddenBy = c.hiddenBy, factCount = c.factCount, phaseName = c.phaseName;

    var opensCount = OBOL.pack.opensUpNext ? OBOL.pack.opensUpNext(facts, pack).length : locked.length;
    var html = '<section class="coach ns-coach-wrap">';
    // Positive feedback: a plain-language banner of what the last paste LEARNED + the move it unlocked,
    // so a paste that minted facts never reads as "nothing happened". Shown once, then cleared.
    if (_pasteFlash) {
      var fl = _pasteFlash; _pasteFlash = null;
      html += '<div class="coach-flash" role="status">'
        + '<div class="coach-flash-h">' + OBOL.ic('flag') + '<span>Parsed ' + fl.total + ' fact' + (fl.total === 1 ? '' : 's') + '. Here is what obol learned:</span>'
        + '<button class="coach-flash-x" aria-label="Dismiss">×</button></div>'
        + '<ul class="coach-flash-list">' + fl.phrases.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('')
        + (fl.extra ? ('<li class="coach-flash-more">and ' + fl.extra + ' more detail' + (fl.extra === 1 ? '' : 's') + '</li>') : '') + '</ul>'
        + (fl.next ? ('<div class="coach-flash-next">Next move: <strong>' + esc(fl.next) + '</strong></div>') : '') + '</div>';
    }

    // hero
    var targetSelectorHtml = renderHeroTargetSelector(eng, c.target);
    var scopeLensHtml = renderHeroScopeLens(lens, hiddenBy);
    html += '<div class="coach-hero">'
      + '<div class="coach-hero-main">'
      + '<div class="coach-hero-top">'
      + '<div class="coach-kicker">Next Move · Frontier: <strong>' + esc(U.titleCase(phaseName)) + '</strong>'
      + '<span class="kicker-sep">·</span>'
      + '<span class="hero-ready-tag"><span class="ready-pulse">●</span> Ready Now: <strong>' + onFlow.length + ' move' + (onFlow.length === 1 ? '' : 's') + '</strong></span>'
      + '</div>'
      + '<div class="coach-hero-controls">' + targetSelectorHtml + scopeLensHtml + '</div>'
      + '</div>'
      + '<h1 class="coach-h1">' + (onFlow.length ? esc(onFlow[0].title) : 'Log evidence to unlock moves') + '</h1>'
      + '<p class="coach-sub">' + (onFlow.length ? esc(U.firstSentence(onFlow[0].hypothesis || '')) : 'Paste tool output on the Evidence route (or add a fact) and the coach ranks your next commands.') + '</p>'
      + '</div>'
      + '<div class="coach-hero-aside">'
      + '<div class="coach-hero-aside-top">' + arsenalHeroBadge() + '</div>'
      + '<div class="coach-metrics">'
      + '<div class="metric"><span class="metric-n">' + onFlow.length + '</span><span class="metric-l">Ready</span></div>'
      + '<div class="metric"><span class="metric-n">' + comingUp.length + '</span><span class="metric-l">Coming Up</span></div>'
      + '<div class="metric"><span class="metric-n">' + opensCount + '</span><span class="metric-l">Opens Up Next</span></div>'
      + '<div class="metric"><span class="metric-n">' + factCount + '</span><span class="metric-l">Facts</span></div>'
      + '</div></div></div>';

    var campId = c.campId || 'all';
    var campTrack = c.campTrack || null;
    var hiddenByCamp = c.hiddenByCamp || 0;
    html += '<div class="coach-campaign-bar" id="coach-campaign-bar">'
      + '<div class="campaign-bar-inner">'
      + '<div class="campaign-selector-wrap">'
      + '<span class="campaign-label"><span class="campaign-icon" aria-hidden="true">' + (OBOL.ic ? OBOL.ic('crosshair') : '') + '</span> Playbook:</span>'
      + '<select id="coach-campaign-select" class="campaign-select" aria-label="Campaign Playbook Filter">'
      + '<option value="all"' + (campId === 'all' ? ' selected' : '') + '>All Campaigns (Full Arsenal)</option>'
      + '<option value="ad-chain"' + (campId === 'ad-chain' ? ' selected' : '') + '>Active Directory Attack Path</option>'
      + '<option value="web-foothold"' + (campId === 'web-foothold' ? ' selected' : '') + '>Web to Initial Foothold</option>'
      + '<option value="win-privesc"' + (campId === 'win-privesc' ? ' selected' : '') + '>Windows Privilege Escalation</option>'
      + '<option value="linux-privesc"' + (campId === 'linux-privesc' ? ' selected' : '') + '>Linux Privilege Escalation</option>'
      + '<option value="lateral-pivot"' + (campId === 'lateral-pivot' ? ' selected' : '') + '>Lateral Movement & Pivoting</option>'
      + '</select>'
      + '</div>'
      + renderCampaignProgression(facts, campId)
      + '</div>'
      + (campTrack ? ('<div class="campaign-desc">' + esc(campTrack.description) + '</div>') : '')
      + (hiddenByCamp ? ('<div class="campaign-filter-hint">Showing moves for <strong>' + esc(campTrack.name) + '</strong> (' + hiddenByCamp + ' other moves filtered). Select <strong>All Campaigns</strong> to see full arsenal.</div>') : '')
      + '</div>';

    html += defenseAdvisory(facts);

    // Planned route to the objective: the planner's lowest-cost dependable path from what's proven to
    // the goal. Re-planned on every render as evidence accrues. A plausible route, not a promise — the
    // box decides which steps actually land; this sharpens as you capture more.
    var hasEvidence = false;
    if (facts && facts.facts) {
      for (var fki = 0; fki < facts.facts.length; fki++) {
        if (OBOL.pack.isEvidenceFact && OBOL.pack.isEvidenceFact(facts.facts[fki].kind)) {
          hasEvidence = true;
          break;
        }
      }
    }
    var route = (hasEvidence && OBOL.pack.planPath) ? OBOL.pack.planPath(facts, pack, {}) : null;
    if (route && route.reachable && route.path && route.path.length > 1 && factCount > 1) {
      html += '<details class="coach-route"><summary class="coach-sec-h">Planned Route To The Objective'
        + ' <span class="coach-route-n">' + route.path.length + ' steps</span></summary>'
        + '<ol class="coach-route-list">'
        + route.path.map(function (id, i) {
          var a = pack.filter(function (x) { return x.id === id; })[0];
          return '<li class="coach-route-step' + (i === 0 ? ' next' : '') + '">' + esc(a ? a.title : id) + '</li>';
        }).join('')
        + '</ol>'
        + '<div class="coach-route-note">The shortest dependable path from what you’ve proven to the goal, it re-plans as you capture evidence. A plausible route, not a guarantee.</div>'
        + '</details>';
    }

    // one-time workspace scaffold: create the output tree once, then every command below writes
    // into it and tells you which file to attach. Dismissible; auto-hides once you're rolling.
    if (OBOL.workspace.isConfigured(eng) && !((eng.ui || {}).wsScaffoldDone) && factCount < 3) {
      var scaffold = OBOL.workspace.scaffold(eng);
      var scandir = OBOL.workspace.tokens(eng).scandir;
      var stamp = OBOL.workspace.promptStamp ? OBOL.workspace.promptStamp((params || {}).lhost_iface || '') : (OBOL.workspace.PROMPT_STAMP_ZSH || '');
      html += '<div class="ws-banner">'
        + '<div class="ws-banner-h">' + OBOL.ic('folder') + ' Set up your working directory, run this once on your Kali box:</div>'
        + '<pre class="cmd-run"><code>' + esc(scaffold) + '</code></pre>'
        + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(scaffold) + '">copy</button>'
        + '<button class="btn-ghost ws-done">Got It</button></div>'
        + '<div class="ws-banner-note">Commands below write into <code>' + esc(scandir) + '</code>, run one, then attach its output file in Evidence.</div>'
        + (stamp
          ? ('<details class="ws-stamp"><summary>Optional: stamp your prompt with the time + VPN IP <span class="ev-import-tag">Recommended</span></summary>'
            + '<div class="ws-banner-note">Paste this into <code>~/.zshrc</code> once. It prints a dim <code>[UTC time] [tun0:IP]</code> line before each prompt (your prompt is untouched), so later you can paste your <strong>whole session</strong> into Evidence and obol orders it correctly and auto-fills your <code>{{lhost}}</code>.</div>'
            + '<pre class="cmd-run"><code>' + esc(stamp) + '</code></pre>'
            + '<div class="ws-banner-actions"><button class="btn-copy" data-copy="' + U.attr(stamp) + '">copy</button></div>'
            + '</details>')
          : '')
        + '</div>';
    }

    // ---- the two-column coach: ranked card grid (left) + field-notes canvas (right) ----
    // Resolve the open card from the persisted selection, validating it against the live set; default to
    // the #1 ready move so the canvas is never empty and the recommended path is zero-click.
    var selectable = onFlow.concat(comingUp).concat(reportChecks);
    var selMove = nsSel.id ? selectable.filter(function (a) { return a.id === nsSel.id; })[0] : null;
    if (!selMove) {
      selMove = onFlow[0] || selectable[0] || null;
      nsSel.id = selMove ? selMove.id : null;
      nsSel.locus = selMove ? OBOL.pack.defaultCommandLocus(selMove) : null;
      nsSel.idx = selMove ? firstCmdIndexForLocus(selMove, nsSel.locus, facts) : 0;
    } else {
      if (!nsSel.locus) nsSel.locus = OBOL.pack.defaultCommandLocus(selMove);
      // Re-point a stale selection: out of range, OR a command that has since settled (a run-once probe now
      // hidden), OR one still gated on an unearned fact (now hidden), OR one that no longer matches the
      // active locus. Without this the canvas would keep showing a command the card no longer offers, and
      // the selected card would show no active row.
      var selCmds = selMove.commands || [], selCur = selCmds[nsSel.idx];
      var selFilled = OBOL.command.fillAll(selMove, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) });
      if (nsSel.idx >= selCmds.length || OBOL.pack.commandSettled(selCur, facts) || cmdGated(selFilled[nsSel.idx]) || OBOL.pack.commandLocus(selCur) !== nsSel.locus) {
        nsSel.idx = firstCmdIndexForLocus(selMove, nsSel.locus, facts);
      }
    }
    var mOpen = nsMultiOpen();
    if (mOpen && nsSel.id) nsOpen[nsSel.id] = true;   // the focused card is always one of the open set
    function cardOpts(a, i, section) {
      var badge = actionTargetLabel(a, facts, eng, c.target);
      var open = mOpen ? (!!nsOpen[a.id] || a.id === nsSel.id) : (a.id === nsSel.id);
      return { rank: section === 'ready' ? (i + 1) : 0, selected: open, suggested: section === 'ready' && i === 0, targetBadge: badge };
    }

    // Narrow screens are best-effort: the two-column coach + canvas really wants width. Say so plainly
    // (shown only under the single-column breakpoint) and tell a phone user where the field notes land.
    html += '<p class="ns-mobile-note">The coach is designed for a larger screen. On a phone it still works: tap a move to expand its commands, and its full field notes appear lower down.</p>';

    html += '<div class="ns-coach"><div class="ns-main">';

    // Diagnostic Fix Cards for active blocker.* errors
    var coachFixCards = renderCoachFixCards(facts);
    if (coachFixCards) {
      html += coachFixCards;
    }

    // Multi-open toggle: default OFF keeps the single-focus coach (open one card at a time); ON lets you
    // keep several cards open to compare. Only shown when there is more than one card to compare.
    if (onFlow.length > 1) {
      html += '<div class="ns-controls"><label class="ns-multi-toggle"><input type="checkbox" id="ns-multiopen"' + (mOpen ? ' checked' : '') + '>'
        + '<span>Keep Cards Open</span></label>'
        + (mOpen ? '<button type="button" class="ns-collapse-others" data-ns-collapse>Collapse To One</button>' : '') + '</div>';
    }

    var READY_CAP = 8;
    if (onFlow.length) {
      var top = onFlow.slice(0, READY_CAP), rest = onFlow.slice(READY_CAP);
      html += '<div class="ns-grid">';
      top.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'ready')); });
      html += '</div>';
      if (rest.length) {
        html += '<details class="ns-more"' + (rest.some(function (a) { return a.id === nsSel.id; }) ? ' open' : '') + '><summary>' + rest.length + ' more ready, lower priority right now</summary><div class="ns-grid">';
        rest.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i + READY_CAP, 'ready-rest')); });
        html += '</div></details>';
      }
    } else {
      html += '<div class="ns-empty">No ready moves yet. Paste a scan on the Evidence route, or add a target fact, and the coach will rank your next commands here.</div>';
    }

    if (comingUp.length) {
      html += '<details class="ns-section ns-comingup"' + (comingUp.some(function (a) { return a.id === nsSel.id; }) ? ' open' : '') + '><summary>Coming Up, eligible but ahead of your frontier (' + comingUp.length + ')</summary><div class="ns-grid">';
      comingUp.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'coming')); });
      html += '</div></details>';
    }

    if (reportChecks.length) {
      html += '<details class="ns-section ns-reportchecks"' + (reportChecks.some(function (a) { return a.id === nsSel.id; }) ? ' open' : '') + '><summary>Report Checks, for the writeup (' + reportChecks.length + ')</summary>'
        + '<p class="ns-section-note">Info-only checks that do not move the box forward (SPF/DMARC, security headers, TLS, CORS). Run them when you are tidying up the report.</p><div class="ns-grid">';
      reportChecks.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'report')); });
      html += '</div></details>';
    }

    // the aspirational roadmap of capability-unlocks (contingency doctors/vulns excluded by the engine)
    html += nsOpensStrip(OBOL.pack.opensUpNext(facts, pack));

    html += '</div>'; // .ns-main
    html += '<aside class="ns-canvas" id="ns-canvas" aria-label="Field notes for the selected move" aria-live="polite">'
      + nsCanvasHtml(selMove, nsSel.idx, facts, params) + '</aside>';
    html += '</div>'; // .ns-coach

    html += '</section>';
    return html;
  }

  function mounted(ctx) {
    // The router replaces #view's innerHTML each render but REUSES the #view element, so delegated
    // listeners bound on it would stack on every re-render — the Paste-Output toggle would then fire
    // an even number of times (open→closed = no-op) and ingests would duplicate. Bind on the coach's
    // own container instead: it's recreated on each render, so its listeners die with the old DOM.
    var mount = ctx.mount.querySelector('.coach') || ctx.mount;

    // Background-load the ~1MB sample-output fixtures (off the critical boot path) so "See It Run" can
    // show a real example run and its output in the field notes. When they land, repaint the open card.
    if (!(OBOL.study && OBOL.study.replayFor) && OBOL.lazy && OBOL.lazy.loadGroup) {
      OBOL.lazy.loadGroup('studydata').then(function () {
        try { if (OBOL.study && OBOL.study.replayFor && nsSel && nsSel.id) repaintCanvas(); } catch (e) {}
      });
    }

    // ---- Next Steps card grid: select a card (glow follows), toggle Remote/On-Host, pick a command.
    // These update the DOM and the canvas IN PLACE (no full re-render) so scroll and focus are preserved.
    function freshCtx() {
      return { facts: OBOL.store.factSet(), pack: OBOL.packs.actions(), params: (OBOL.store.active() || {}).params || {} };
    }
    function moveById(pack, id) { return pack.filter(function (a) { return a.id === id; })[0]; }
    function repaintCanvas() {
      var el = mount.querySelector('#ns-canvas'); if (!el) return;
      var fx = freshCtx(); var m = moveById(fx.pack, nsSel.id);
      el.innerHTML = nsCanvasHtml(m, nsSel.idx, fx.facts, fx.params);
    }
    function selectCard(card) {
      var id = card.getAttribute('data-action'); if (!id) return;
      var fx = freshCtx(); var m = moveById(fx.pack, id); if (!m) return;
      nsSel.id = id;
      nsSel.locus = OBOL.pack.defaultCommandLocus(m);
      nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus, fx.facts);
      // glow + expand follow the selection
      Array.prototype.forEach.call(mount.querySelectorAll('.ns-card.selected'), function (o) {
        o.classList.remove('selected', 'is-glow', 'ns-bloom'); o.setAttribute('aria-expanded', 'false');
      });
      card.classList.add('selected', 'is-glow'); card.setAttribute('aria-expanded', 'true');
      // one-shot bloom shimmer ONLY on an explicit open — never on toggle/command clicks or re-render
      card.classList.remove('ns-bloom'); void card.offsetWidth; card.classList.add('ns-bloom');
      setTimeout(function () { card.classList.remove('ns-bloom'); }, 3600);
      // apply the move's default locus to its command rows + mark the first active
      syncCardLocus(card, nsSel.locus);
      repaintCanvas();
    }
    function syncCardLocus(card, locus) {
      var tgl = card.querySelector('.ns-toggle');
      if (tgl) Array.prototype.forEach.call(tgl.querySelectorAll('button'), function (b) {
        var on = b.getAttribute('data-locus') === locus;
        b.classList.toggle('on', on); b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      var spans = !!tgl, first = -1;
      Array.prototype.forEach.call(card.querySelectorAll('.ns-cmd'), function (row) {
        var rl = row.getAttribute('data-locus');
        var show = !spans || rl === locus;
        if (show) { row.removeAttribute('hidden'); if (first < 0) first = parseInt(row.getAttribute('data-cmd-index'), 10); }
        else row.setAttribute('hidden', '');
        row.classList.remove('active');
      });
      if (first >= 0) {
        nsSel.idx = first;
        var active = card.querySelector('.ns-cmd[data-cmd-index="' + first + '"]');
        if (active) active.classList.add('active');
      }
    }
    // dismiss the "what obol learned" flash banner
    U.on(mount, 'click', '.coach-flash-x', function (e, t) {
      var fl = t.closest('.coach-flash'); if (fl) fl.remove();
    });
    // Open the clicked card and make it the focus, WITHOUT closing the other open cards (multi-open mode).
    function openCardKeepOthers(card) {
      var id = card.getAttribute('data-action'); if (!id) return;
      var fx = freshCtx(); var m = moveById(fx.pack, id); if (!m) return;
      nsOpen[id] = true; nsSel.id = id; nsSel.locus = OBOL.pack.defaultCommandLocus(m);
      nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus, fx.facts);
      Array.prototype.forEach.call(mount.querySelectorAll('.ns-card.selected'), function (o) { o.classList.remove('is-glow'); });
      card.classList.add('selected', 'is-glow'); card.setAttribute('aria-expanded', 'true');
      card.classList.remove('ns-bloom'); void card.offsetWidth; card.classList.add('ns-bloom');
      setTimeout(function () { card.classList.remove('ns-bloom'); }, 3600);
      syncCardLocus(card, nsSel.locus); repaintCanvas();
    }
    // Collapse one open card (multi-open mode). If it was the focused card, move focus to another open one.
    function collapseCard(card) {
      var id = card.getAttribute('data-action');
      card.classList.remove('selected', 'is-glow', 'ns-bloom'); card.setAttribute('aria-expanded', 'false');
      if (id) delete nsOpen[id];
      if (id === nsSel.id) {
        var nextId = Object.keys(nsOpen)[0];
        var nextCard = nextId ? mount.querySelector('.ns-card[data-action="' + nextId + '"]') : null;
        if (nextCard) openCardKeepOthers(nextCard);
      }
    }
    // click a card (but not an interactive control inside it) to open it
    U.on(mount, 'click', '.ns-card', function (e, t) {
      if (e.target.closest('.ns-cmd') || e.target.closest('.ns-toggle') || e.target.closest('button') || e.target.closest('a') || e.target.closest('input') || e.target.closest('textarea')) return;
      if (nsMultiOpen()) { if (t.classList.contains('selected')) collapseCard(t); else openCardKeepOthers(t); }
      else if (!t.classList.contains('selected')) selectCard(t);
    });
    U.on(mount, 'keydown', '.ns-card', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, a, input, textarea')) {
        e.preventDefault();
        if (nsMultiOpen()) { if (t.classList.contains('selected')) collapseCard(t); else openCardKeepOthers(t); }
        else if (!t.classList.contains('selected')) selectCard(t);
      }
    });
    // multi-open toggle + "collapse to one"
    U.on(mount, 'click', '#ns-multiopen', function (e, t) {
      var on = !!t.checked;
      if (!on) nsOpen = nsSel.id ? (function () { var o = {}; o[nsSel.id] = true; return o; })() : {};
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.nsMultiOpen = on; }, 'ui');
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-ns-collapse]', function () {
      nsOpen = nsSel.id ? (function () { var o = {}; o[nsSel.id] = true; return o; })() : {};
      OBOL.router.render();
    });
    // Remote / On-Host toggle inside the open card
    U.on(mount, 'click', '.ns-toggle button', function (e, t) {
      var card = t.closest('.ns-card'); if (!card) return;
      nsSel.locus = t.getAttribute('data-locus');
      syncCardLocus(card, nsSel.locus);
      repaintCanvas();
    });
    // pick a command row → it drives the canvas field notes (mouse or keyboard)
    function pickCmd(t) {
      var card = t.closest('.ns-card'); if (!card) return;
      Array.prototype.forEach.call(card.querySelectorAll('.ns-cmd'), function (x) { x.classList.remove('active'); });
      t.classList.add('active');
      nsSel.idx = parseInt(t.getAttribute('data-cmd-index'), 10) || 0;
      repaintCanvas();
    }
    U.on(mount, 'click', '.ns-cmd', function (e, t) {
      if (e.target.closest('.btn-copy') || e.target.closest('.cmd-fill')) return;
      pickCmd(t);
    });
    U.on(mount, 'keydown', '.ns-cmd', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, input')) { e.preventDefault(); pickCmd(t); }
    });

    // Target focus selector (multi-target engagements: dropdown + pills)
    U.on(mount, 'change', '#coach-target-select', function (e, t) {
      var tid = t.value ? t.value.trim() : null;
      if (OBOL.store.setActiveTarget) OBOL.store.setActiveTarget(tid);
      if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
      OBOL.router.render();
    });
    U.on(mount, 'click', '.btn-target-pill', function (e, t) {
      var tid = t.getAttribute('data-tid') || null;
      if (OBOL.store.setActiveTarget) OBOL.store.setActiveTarget(tid);
      if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
      OBOL.router.render();
    });

    // copy buttons
    U.on(mount, 'click', '.rail-flag-val', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Flag copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // pivot staging guide: tick a step done (in place, so the open guide and scroll are preserved)
    U.on(mount, 'click', '[data-stage]', function (e, t) {
      var id = t.getAttribute('data-stage'), i = t.getAttribute('data-stage-i'), key = 'obol.stage:' + id + ':' + i;
      var was; try { was = localStorage.getItem(key) === '1'; localStorage.setItem(key, was ? '0' : '1'); } catch (x) { was = false; }
      var on = !was;
      t.setAttribute('aria-checked', on ? 'true' : 'false');
      t.innerHTML = on ? '✓' : '';
      var li = t.closest('.stage-step'); if (li) li.classList.toggle('done', on);
    });
    U.on(mount, 'click', '.cmd-miss-cmd', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Install command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // inline code chips inside a field note (fmtNote `backtick` spans): click to copy the exact text.
    U.on(mount, 'click', '.ns-ic', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // inline free-text token fill ({{command}} etc.): substitute live into the command + copy button.
    U.on(mount, 'input', '.cmd-fill', function (e, t) {
      var cmd = t.closest('.ns-cmd') || t.closest('.cmd'); if (!cmd) return;
      var out = cmd.getAttribute('data-tmpl') || '';
      Array.prototype.forEach.call(cmd.querySelectorAll('.cmd-fill'), function (inp) {
        var val = (inp.value || '').trim();
        if (val) out = out.split('{{' + inp.getAttribute('data-tok') + '}}').join(val);
      });
      var code = cmd.querySelector('.cmd-run-code') || cmd.querySelector('.cmd-run code'); if (code) code.textContent = out;
      var copy = cmd.querySelector('.btn-copy'); if (copy) copy.setAttribute('data-copy', out);
    });
    // GTFOBins live lookup: type a binary, get its exact escape for this move's context (sudo / SUID).
    U.on(mount, 'input', '.ns-gtfo-input', function (e, t) {
      var box = t.closest('.ns-gtfo-lookup'); box = box && box.querySelector('.ns-gtfo-result'); if (!box) return;
      var val = (t.value || '').trim(), ctx = t.getAttribute('data-ctx') || 'sudo';
      if (!val) { box.innerHTML = ''; return; }
      var r = OBOL.resolve && OBOL.resolve.gtfoLookup ? OBOL.resolve.gtfoLookup(val, ctx) : null;
      box.innerHTML = (r && r.known) ? nsGtfoRow(r)
        : '<div class="ns-gtfo-none">GTFOBins has no entry for <code>' + esc(val) + '</code>. Check the spelling, or this one may escalate a different way.</div>';
    });
    // scope lens: persist the choice and re-render the coach at the new syllabus level
    U.on(mount, 'click', '.lens-opt', function (e, t) {
      var v = t.getAttribute('data-lens'); if (!v) return;
      lensSet(v);
      OBOL.router.render();
    });
    // campaign playbook selector
    var campSel = mount.querySelector('#coach-campaign-select');
    if (campSel) {
      campSel.addEventListener('change', function () {
        campaignSet(campSel.value);
        OBOL.router.render();
      });
    }
    // Anatomy pillar tab switcher (zero-scroll neurodivergent navigation)
    // "See It Run" toggle: flip this card's example terminal and remember the choice for every card.
    U.on(mount, 'click', '[data-ex-toggle]', function (e, t) {
      var wrap = t.closest('.ns-ex'); if (!wrap) return;
      var term = wrap.querySelector('.ns-ex-term');
      var open = !wrap.classList.contains('open');
      wrap.classList.toggle('open', open);
      if (term) { if (open) term.removeAttribute('hidden'); else term.setAttribute('hidden', ''); }
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
      try { localStorage.setItem('obol.show-example', open ? '1' : '0'); } catch (x) {}
      // apply the new preference to any other example blocks on screen without a full re-render
      Array.prototype.forEach.call(mount.querySelectorAll('.ns-ex'), function (w) {
        if (w === wrap) return;
        var tm = w.querySelector('.ns-ex-term'), bt = w.querySelector('.ns-ex-toggle');
        w.classList.toggle('open', open);
        if (tm) { if (open) tm.removeAttribute('hidden'); else tm.setAttribute('hidden', ''); }
        if (bt) bt.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    });

    U.on(mount, 'click', '[data-pillar-tab]', function (e, t) {
      var tabKey = t.getAttribute('data-pillar-tab');
      if (!tabKey) return;
      try { sessionStorage.setItem('obol.pillar-tab', tabKey); } catch (x) {}
      var canvas = mount.querySelector('#ns-canvas');
      if (!canvas) return;
      Array.prototype.forEach.call(canvas.querySelectorAll('.anatomy-tab-btn'), function (btn) {
        var isThis = btn.getAttribute('data-pillar-tab') === tabKey;
        btn.classList.toggle('on', isThis);
        btn.setAttribute('aria-selected', isThis ? 'true' : 'false');
      });
      Array.prototype.forEach.call(canvas.querySelectorAll('[data-pillar-section]'), function (sec) {
        var secKey = sec.getAttribute('data-pillar-section');
        if (tabKey === 'all' || secKey === tabKey) {
          sec.removeAttribute('hidden');
        } else {
          sec.setAttribute('hidden', '');
        }
      });
      var body = canvas.querySelector('.ns-canvas-body');
      if (body) body.scrollTop = 0;
    });
    U.on(mount, 'keydown', '.anatomy-tab-btn', function (e, t) {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        var tabs = Array.prototype.slice.call(mount.querySelectorAll('.anatomy-tabs .anatomy-tab-btn'));
        var idx = tabs.indexOf(t);
        if (idx >= 0) {
          e.preventDefault();
          var nextIdx = e.key === 'ArrowRight' ? (idx + 1) % tabs.length : (idx - 1 + tabs.length) % tabs.length;
          tabs[nextIdx].focus();
          tabs[nextIdx].click();
        }
      }
    });
    // dismiss blocker fact via diagnostic fix card
    U.on(mount, 'click', '[data-dismiss-blocker]', function (e, t) {
      var k = t.getAttribute('data-dismiss-blocker');
      if (k && OBOL.store && OBOL.store.retractFactKind) {
        OBOL.store.retractFactKind(k);
        U.toast('Diagnostic resolved');
        OBOL.router.render();
      }
    });
    // mark done
    U.on(mount, 'click', '.btn-done', function (e, t) {
      var id = t.getAttribute('data-action');
      OBOL.store.update(function (eng) { eng.checklist = eng.checklist || {}; eng.checklist[id] = 'done'; }, 'done');
      U.toast('Marked done, recomputing');
      OBOL.router.render();
    });
    // dismiss the workspace scaffold banner
    U.on(mount, 'click', '.ws-done', function () {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.wsScaffoldDone = true; }, 'ui');
      OBOL.router.render();
    });
    // "Got It" on a Set Up First prep step: collapse it to one line (obol can't see your disk, so you tell
    // it the file is written). Keyed by content, so it re-appears if the file obol would write changes.
    U.on(mount, 'click', '.prep-done', function (e, t) {
      var key = t.getAttribute('data-prep'); if (!key) return;
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.prepDone = eng.ui.prepDone || {}; eng.ui.prepDone[key] = true; }, 'ui');
      OBOL.router.render();
    });
    // "Show" on a collapsed prep step: bring the full command back.
    U.on(mount, 'click', '.prep-undo', function (e, t) {
      var key = t.getAttribute('data-prep'); if (!key) return;
      OBOL.store.update(function (eng) { if (eng.ui && eng.ui.prepDone) delete eng.ui.prepDone[key]; }, 'ui');
      OBOL.router.render();
    });
    // paste-back: toggle this move's inline ingestion box (no route jump — ingest right here)
    U.on(mount, 'click', '.btn-pasteback', function (e, t) {
      var art = t.closest('.ns-card') || t.closest('.move'); if (!art) return;
      var box = art.querySelector('.move-ingest'); if (!box) return;
      var open = box.hasAttribute('hidden');
      if (open) { box.removeAttribute('hidden'); } else { box.setAttribute('hidden', ''); }
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { var ta = box.querySelector('.mi-text'); if (ta) ta.focus(); }
    });
    // inline ingest: parse this move's output, mint facts, advance the coach
    U.on(mount, 'click', '.mi-go', function (e, t) {
      var box = t.closest('.move-ingest'); if (!box) return;
      var ta = box.querySelector('.mi-text'), out = box.querySelector('.mi-result');
      var text = (ta && ta.value) || '';
      if (!text.trim()) { if (out) out.textContent = 'Paste the output first.'; return; }
      if (out) out.textContent = 'Reading…';
      t.disabled = true;
      OBOL.ingest.ensureParsers().then(function (okp) {
        if (!okp) { if (out) out.textContent = 'Parsers still loading, try again.'; t.disabled = false; return; }
        var r = OBOL.ingest.run({ text: text, command: box.getAttribute('data-cmd') || '',
          actionId: box.getAttribute('data-action') || '', source: 'paste' });
        if (!r.ok) { if (out) out.textContent = r.reason === 'parsers' ? 'Parsers still loading, try again.' : 'Nothing to parse.'; t.disabled = false; return; }
        if (r.added) {
          // Positive, value-aware feedback: say what obol learned + the next move, so the paste never
          // reads as silent. The flash survives the re-render below (the toast element gets wiped).
          _pasteFlash = pasteSummary(r.facts);
          var lead = _pasteFlash && _pasteFlash.phrases[0] ? _pasteFlash.phrases[0] : ('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's'));
          U.toast(lead + ' · coach updated');
          OBOL.router.render(); // coach advances: the move may now be satisfied and new moves appear
        } else {
          var aid = box.getAttribute('data-action') || '';
          var toolNm = ((box.getAttribute('data-cmd') || '').trim().split(/\s+/)[0] || '').split('/').pop().replace(/\.(py|exe)$/, '') || 'the tool';
          var bodyLines = text.trim().split(/\r?\n/).filter(function (l) { return l.trim(); }).length;
          // The move's tool ran to completion and proved nothing HERE (a useless path right now — e.g. no
          // SCCM in the environment): acknowledge it and retire the move from the coach instead of
          // re-suggesting a command already run. Guarded so a junk paste or a broken/denied run does NOT
          // retire — and so RE-PASTING evidence that already paid off (this MOVE produced facts on an
          // earlier run) never buries a move you still need. Judged per move (its own activities), not by a
          // fact-kind that some unrelated move may have produced.
          var eng2 = OBOL.store.active() || {};
          var moveEverPaid = (eng2.activities || []).some(function (a) { return a && a.action_id === aid && (a.produced || []).length > 0; });
          if (aid && !moveEverPaid && !r.parseError && r.recognizedTool && !r.looksError && bodyLines >= 2) {
            OBOL.store.update(function (engg) { engg.checklist = engg.checklist || {}; engg.checklist[aid] = 'empty'; }, 'done');
            U.toast(toolNm + ' ran, nothing found here. Retired from the coach.');
            OBOL.router.render();
            return;
          }
          t.disabled = false;
          if (out) {
            // The output is always saved as evidence; only fact extraction may come up empty.
            out.innerHTML = r.parseError
              ? ('Output saved, the parser skipped part of it, no new facts. <a href="#/evidence/' + esc(aid) + '">Open in Evidence ↗</a>')
              : r.facts.length
                ? ('Recognized ' + r.facts.length + ', nothing new (already known).')
                : 'No facts recognized (output saved). <a href="#/evidence/' + esc(aid) + '">Set the command in Evidence ↗</a>';
          }
        }
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.path = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
