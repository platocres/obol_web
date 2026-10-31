/*!
 * obol ui - routes/path.js - THE COCKPIT (formerly "Coach" / "Next Steps").
 * NOTE FOR DEVELOPERS & AGENTS: In the user-facing UI and documentation, this workspace is
 * called "Cockpit" (and its top card is the "Cockpit HUD"). In the codebase, its route hash is
 * `#/path`, its JS namespace is `OBOL.coach` / `OBOL.routes.path`, and its CSS selectors use
 * `.coach-*` and `.ns-*`. Keep these internal identifiers intact to preserve test and link stability.
 *
 * A proof-gated operator cockpit: ranked next moves from the engine, each with its *why*, its
 * copy-ready command variant(s), its *does-not-prove* honesty line, and what it *produces*.
 * NO toggles/switches here - command *building* lives in the Tools route. Blocked moves are
 * listed with their unmet-prereq reason; adding the unlocking fact promotes them live.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  function esc(s) { return U.esc(s); }

  // Scope lens (teaching filter, orthogonal to fact-gating): narrow the visible moves to a syllabus level
  // so a newcomer isn't handed the whole arsenal at once. Default 'oscp+' (displayed as OSCP) includes the
  // full modern OSCP/PEN-200 syllabus and hides only the handful of genuinely out-of-scope edge CVEs
  // (zerologon/noPac/PrintNightmare/MS14-068/SCCM/WSUS); the operator flips to All any time.
  var LENS_KEY = 'obol.scope-lens', LENS_ORDER = { oscp: 1, 'oscp+': 1, beyond: 2, all: 2 };
  function lensGet() {
    try {
      var v = localStorage.getItem(LENS_KEY) || localStorage.getItem('obol.scope.lens.v1');
      if (v === 'all') return 'all';
      if (v === 'oscp' || v === 'oscp+') return 'oscp+';
    } catch (e) {}
    try {
      var eng = (OBOL.store && OBOL.store.active) ? OBOL.store.active() : null;
      if (eng && eng.profile && OBOL.profile && OBOL.profile.defaultLens) {
        var dl = OBOL.profile.defaultLens(eng.profile);
        return dl === 'all' ? 'all' : 'oscp+';
      }
    } catch (e) {}
    return 'oscp+';
  }
  function lensSet(v) {
    var norm = v === 'all' ? 'all' : 'oscp+';
    try { localStorage.setItem(LENS_KEY, norm); localStorage.setItem('obol.scope.lens.v1', norm); } catch (e) {}
  }
  function scopeAllowed(scope, lens) { if (lens === 'all') return true; return LENS_ORDER[scope || 'oscp'] <= LENS_ORDER[lens]; }

  var CAMPAIGN_KEY = 'obol.campaign';
  function campaignGet() { try { var v = sessionStorage.getItem(CAMPAIGN_KEY) || 'all'; return v; } catch (e) { return 'all'; } }
  function campaignSet(v) { try { sessionStorage.setItem(CAMPAIGN_KEY, v); } catch (e) {} }

  // A slim one-line status strip linking to the global Loadout: not-set-up CTA, or a synced summary that
  // nudges a re-sync once the box snapshot is stale. Reads the per-browser profile straight from
  // localStorage (no dependency on the lazy arsenal.js), so it renders on the coach without loading it.
  var ARSENAL_STALE_DAYS = 21;
  function arsenalProfile() { try { return JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null'); } catch (e) { return null; } }
  // Commands ALWAYS render as authored - we never gate a move on what we think the box has. But once the box
  // is synced, if a command's tool isn't present, add a quiet "install it" nudge beneath it (never hiding it).
  // Only nudge for tools obol actually PROVISIONS (apt/pipx/git/release/material/staged) - never for base Kali
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
    return '<div class="cmd-missing">' + OBOL.ic('bolt') + ' Not On Your Box: ' + miss.map(function (e) {
      var how = e.install ? '<code class="cmd-miss-cmd" data-copy="' + U.attr(e.install) + '" title="Click to copy">' + esc(e.install) + '</code>'
        : (e.manual_url ? '<a href="' + U.attr(e.manual_url) + '" target="_blank" rel="noopener">get it ↗</a>' : 'see Loadout');
      return '<b>' + esc(e.label || e.key) + '</b> ' + how;
    }).join(' · ') + ' · <a href="#/loadout">Loadout →</a></div>';
  }
  function arsenalStrip() {
    var p = arsenalProfile();
    if (!p) {
      return '<a class="lo-strip lo-strip-cta" href="#/loadout"><span class="lo-strip-ico">' + OBOL.ic('gear') + '</span>'
        + '<span class="lo-strip-txt">Set up your attack box, OBOL tailors every command to the tools you have</span>'
        + '<span class="lo-strip-go">Loadout →</span></a>';
    }
    var present = 0; try { Object.keys(p.tools || {}).forEach(function (k) { if (p.tools[k] && p.tools[k].present) present++; }); } catch (e) {}
    var ageDays = p.savedAt ? (Date.now() - p.savedAt) / 86400000 : 0;
    var stale = ageDays > ARSENAL_STALE_DAYS;
    var txt = stale
      ? ('Loadout synced ' + Math.round(ageDays) + 'd ago, re-sync your box?')
      : ('Loadout: ' + present + ' tools · ' + (p.staged || []).length + ' staged ready');
    return '<a class="lo-strip ' + (stale ? 'lo-strip-stale' : 'lo-strip-ok') + '" href="#/loadout">'
      + '<span class="lo-strip-ico">' + (stale ? OBOL.ic('bolt') : OBOL.ic('check')) + '</span>'
      + '<span class="lo-strip-txt">' + esc(txt) + '</span><span class="lo-strip-go">Loadout →</span></a>';
  }

  function arsenalHeroBadge() {
    var p = arsenalProfile();
    if (!p) {
      return '<a class="hero-loadout-badge lo-cta" href="#/loadout" title="Set up your attack box, OBOL tailors every command">'
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
      + '<span class="lo-badge-ico">' + (stale ? OBOL.ic('bolt') : OBOL.ic('check')) + '</span>'
      + '<span class="lo-badge-txt">' + esc(txt) + '</span>'
      + '<span class="lo-badge-go">→</span></a>';
  }

  // When defense-enum has proven endpoint controls, warn the operator (remote-first) rather than nudging
  // them onto a monitored host. Detection only - obol surfaces the posture, it does not evade anything.
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

  // Tokens that come from proven facts, the engagement params, or the workspace - the operator fills
  // these on the sidebar or by pasting evidence, so they stay a "needs:" hint, not a text box.
  var DERIVED_TOKENS = {
    target: 1, domain: 1, basedn: 1, dc: 1, user: 1, password: 1, nthash: 1, lhost: 1, lport: 1,
    userlist: 1, hashfile: 1, wordlist: 1, dc_netbios: 1, dc_account: 1, domain_sid: 1,
    target_sam: 1, group: 1, ca_name: 1, template: 1, pfx: 1, nmap_ports: 1, krbtgt_hash: 1,
  };
  // Ad-hoc, operator-supplied free-text tokens get an inline fill box right on the card (the coach
  // stays a builder-free surface - this only completes a placeholder, no toggles). Nice labels/hints:
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

  // "Set up the file this move reads" - obol proved the user list / hashes, so it hands back a
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
    // {{userlist}} - the move reads it and obol has proven users to write into it.
    if (OBOL.loot.actionUsesToken(action, 'userlist')) {
      var users = OBOL.loot.usernames(facts);
      var ulCmd = OBOL.loot.userlistCommand(facts, dirs);
      if (users.length && ulCmd) {
        var ulKey = 'ul:' + prepHash(ulCmd);
        steps += prepStep('Write', 'creates ' + OBOL.loot.userlistPath(dirs),
          ulCmd, 'Run once, the ' + users.length + ' users OBOL proved, written where every command below reads them.', ulKey, !!doneMap[ulKey]);
      }
    }
    // {{hashfile}} as an INPUT (a crack move) - obol holds the roasted hashes as facts but no file
    // was written (a stdout roast), so give the operator the line that lays them down for cracking.
    var reqs = [].concat(action.requires_all || []);
    var cracksHashes = reqs.some(function (r) { return /^hash\./.test(r); });
    if (cracksHashes && OBOL.loot.actionUsesToken(action, 'hashfile')) {
      var hfCmd = OBOL.loot.hashfileCommand(facts, action, dirs);
      if (hfCmd) {
        var hfKey = 'hf:' + prepHash(hfCmd);
        steps += prepStep('Write', 'creates ' + OBOL.loot.hashfilePath(dirs, action),
          hfCmd, 'Lay the roasted hashes OBOL captured into the file the crack reads.', hfKey, !!doneMap[hfKey]);
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
  // Next Steps redesign - a ranked card grid (left) + a field-notes canvas (right). Cards are compact and
  // scannable; selecting one morphs it wider, reveals its commands with a Remote/On-Host toggle, and loads
  // the field notes for the selected command into the canvas. Glow follows selection; #1 keeps a persistent
  // "Suggested Start" tag. See docs/mockups/next-steps-redesign.html for the agreed design.
  // ===================================================================================================

  // Which card is open, which command inside it, which locus tab. Module-level so it survives the route's
  // full re-renders (a fact change re-renders the whole coach); validated against the live set each render.
  var nsSel = { id: null, idx: 0, locus: null, userLocus: false, userCmd: false };
  var _manualPillarMoveId = null;
  // Multi-open (owner-requested, default OFF): when on, clicking a card toggles it and leaves the others
  // open, so you can read several side by side; nsSel stays the FOCUSED card that drives the field-notes
  // canvas. nsOpen is the set of expanded card ids (it always contains nsSel.id). The default single-focus
  // behaviour is unchanged. The preference persists per engagement in eng.ui.nsMultiOpen.
  var nsOpen = {};
  function nsMultiOpen() { try { return !!(((OBOL.store.active() || {}).ui || {}).nsMultiOpen); } catch (e) { return false; } }
  function nsFocusMode() { try { return !!(((OBOL.store.active() || {}).ui || {}).nsFocusMode); } catch (e) { return false; } }
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
    nthash: 1, userlist: 1, hashfile: 1, domain_sid: 1, target_sam: 1, group: 1, abuse_groups_quoted: 1, ca_name: 1, template: 1,
    pfx: 1, nmap_ports: 1, krbtgt_hash: 1, dahash: 1, dauser: 1, flag_path_local: 1, flag_smb_path_local: 1, flag_path_root: 1, share: 1, cpassword: 1 };
  // Human phrasing for the "unlocks once you have ..." affordance (deduped). user/password both read as
  // "a credential" so a command needing both reads once.
  var GATE_LABEL = { domain: 'the domain', basedn: 'the base DN', dc: 'the DC', dc_netbios: 'the DC name',
    dc_account: 'the DC account', user: 'a credential', password: 'a credential', nthash: 'an NT hash',
    userlist: 'a user list', hashfile: 'a captured hash', domain_sid: 'the domain SID', group: 'a group',
    abuse_groups_quoted: 'a writable group',
    ca_name: 'the CA name', template: 'a cert template', pfx: 'a certificate', nmap_ports: 'a port scan',
    krbtgt_hash: 'the krbtgt hash', target_sam: 'the SAM', flag_path_local: 'the located user flag',
    flag_smb_path_local: 'the located user flag',
    flag_path_root: 'the located root flag', share: 'a readable share', cpassword: 'a GPP cpassword' };
  // A command is GATED when, after filling from the engagement's facts/params, it still carries an unfilled
  // EARNED token: a value meant to come from a proven fact the operator has not earned yet. Its time has not
  // come, so the coach hides it rather than showing a dead "Needs: basedn" line, and it reappears, filled,
  // the moment the fact that feeds it is proven.
  function cmdUnmetGates(v) {
    return OBOL.command.unfilledTokens((v && v.filled) || '').filter(function (t) { return GATE_TOKENS[t]; });
  }
  function cmdGated(v) { return !!(v && v.blocked) || cmdUnmetGates(v).length > 0; }

  function cmdWasTriedInEpoch(move, cmdObj, filledObj, eng, curEpoch, target, context) {
    if (!move || !cmdObj || !eng) return false;
    var filledStr = filledObj && filledObj.filled ? filledObj.filled : '';
    if (OBOL.command && OBOL.command.commandTriedInEpoch) {
      return OBOL.command.commandTriedInEpoch(move, cmdObj, filledStr, eng.activities || [], curEpoch, target || move.contextTarget || (eng.params && eng.params.target), context);
    }
    return false;
  }

  function fillOptsForTarget(eng, params, targetIp) {
    var e = eng || (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var ui = e.ui || {};
    var p = params || e.params || {};
    var tIp = String(targetIp || p.target || (e.params && e.params.target) || '').trim();
    var formMap = ui.selectedFormByTarget || {};
    var socksMap = ui.unwrapSocksByTarget || {};
    return {
      params: p,
      profile: e.profile,
      workspace: OBOL.workspace ? OBOL.workspace.tokens(e) : {},
      unwrapSocks: !!(tIp && socksMap[tIp]),
      selectedFormIdx: (tIp && typeof formMap[tIp] === 'number') ? formMap[tIp] : undefined
    };
  }

  function pasteHintForCommand(v, cmdObj) {
    var s = String((v && v.filled) || (cmdObj && cmdObj.run) || '').trim();
    if (!s) return '';
    if (/\bligolo-proxy\b|\bproxy\s+-selfcert\b/i.test(s)) {
      return 'Paste the ligolo-ng startup banner or "Agent joined" session line once the target connects.';
    }
    if (/\bchisel\s+server\b/i.test(s)) {
      return 'Paste the chisel server "Listening on ..." or "session#1: tun: proxy#..." line once connected.';
    }
    if (/\bsshuttle\b|\bssh\s+-(?:[fNT]+\s+)*[DLR]\s/i.test(s)) {
      return 'Paste the "Connected to server" line (or a quick curl / proxychains check through the tunnel).';
    }
    if (/\b(?:rlwrap\s+)?nc(?:\.traditional)?\s+-[a-z]*l[a-z]*p?\b|\bsocat\s+TCP-LISTEN\b|\bpwncat(?:-cs)?\b/i.test(s)) {
      return 'Leave this listener running in Terminal 1; once your shell catches, run id or whoami and paste that back.';
    }
    if (/\bpython3?\s+-m\s+http\.server\b|\bupdog\b|\bimpacket-smbserver\b/i.test(s)) {
      return 'Leave this file server running in Terminal 1 while the target fetches the staged file, then paste the transfer log or target output.';
    }
    return '';
  }

  function _scopedFactValues(facts, kind, targetIp) {
    if (!facts) return [];
    var scope = targetIp ? ('host:' + targetIp) : '';
    if (Array.isArray(facts.facts)) {
      var out = [];
      for (var i = 0; i < facts.facts.length; i++) {
        var f = facts.facts[i];
        if (!f || f.state !== 'supported' || f.kind !== kind) continue;
        if (scope && f.scope && f.scope !== scope && f.scope !== 'host:target') continue;
        if (f.value && typeof f.value === 'object') out.push(f.value);
      }
      return out;
    }
    if (typeof facts.values === 'function') return facts.values(kind) || [];
    return [];
  }

  function renderWebSurfaceStrip(action, facts, eng, targetIp) {
    if (!action) return '';
    var BC = OBOL.burpCopilot || null;
    var eligibleBurp = !!(BC && BC.isEligibleMove(action));
    var phase = (OBOL.phases && OBOL.phases.phaseOfAction) ? OBOL.phases.phaseOfAction(action) : '';
    if (!eligibleBurp && phase !== 'web' && action.id !== 'recon-web-triage') return '';

    var formFacts = _scopedFactValues(facts, 'web.forms_discovered', targetIp);
    var forms = [];
    var seenForms = {};
    var links = [];
    var seenLinks = {};
    formFacts.forEach(function (fv) {
      (fv.forms || []).forEach(function (fm) {
        var k = (fm.method || 'GET') + ' ' + (fm.action || '/');
        if (!seenForms[k]) { seenForms[k] = 1; forms.push(fm); }
      });
      (fv.links || []).forEach(function (lk) {
        var lkKey = lk.pathname || lk.href || '';
        if (lkKey && !seenLinks[lkKey]) { seenLinks[lkKey] = 1; links.push(lk); }
      });
    });

    if (!forms.length && !links.length && !eligibleBurp) return '';

    var ui = (eng && eng.ui) || {};
    var tKey = String(targetIp || (eng && eng.params && eng.params.target) || '').trim();
    var selFormIdx = (tKey && ui.selectedFormByTarget && typeof ui.selectedFormByTarget[tKey] === 'number') ? ui.selectedFormByTarget[tKey] : 0;
    if (selFormIdx < 0 || selFormIdx >= forms.length) selFormIdx = 0;

    var html = '<div class="ns-web-strip">';
    if (forms.length || links.length) {
      html += '<div class="ns-web-strip-main">'
        + '<span class="ns-web-strip-k">Discovered Forms &amp; Parameters:</span>';
      if (forms.length > 1) {
        html += '<div class="ns-form-picker" role="group" aria-label="Select discovered HTML form">'
          + forms.map(function (fm, idx) {
            var on = idx === selFormIdx;
            return '<button type="button" class="ns-form-pill' + (on ? ' on' : '') + '" data-select-form="' + idx + '" data-target-ip="' + U.attr(tKey) + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
              + esc((fm.method || 'GET') + ' ' + (fm.action || '/')) + '</button>';
          }).join('')
          + '</div>';
      }
      if (forms.length) {
        var activeFm = forms[selFormIdx];
        var fChips = (activeFm.fields || []).slice(0, 6).map(function (fl) {
          return '<code class="ns-web-field-chip">' + esc(fl.name + (fl.type && fl.type !== 'text' ? (':' + fl.type) : '')) + '</code>';
        }).join(' ');
        html += '<span class="ns-web-form-summary"><code>' + esc((activeFm.method || 'GET') + ' ' + (activeFm.action || '/')) + '</code>'
          + (fChips ? (' ' + fChips) : '')
          + (activeFm.hasCsrf ? ' <span class="ns-csrf-badge">CSRF token auto-wired</span>' : '')
          + ((activeFm.isMultipart || activeFm.hasFile) ? ' <span class="ns-csrf-badge">Multipart upload</span>' : '')
          + '</span>';
      } else if (links.length) {
        var lChips = links.slice(0, 4).map(function (lk) {
          var pNames = (lk.params || []).map(function (p) { return p.name; }).join(',');
          return '<code class="ns-web-field-chip">' + esc('GET ' + (lk.pathname || '/') + (pNames ? ('?' + pNames) : '')) + '</code>';
        }).join(' ');
        html += '<span class="ns-web-form-summary">' + lChips + '</span>';
      }
      html += '</div>';
    }

    if (eligibleBurp) {
      var curMode = BC.shouldAutoOpen(action, facts, eng, tKey) ? 'burp' : 'cli';
      html += '<div class="ns-web-mode-toggle" role="group" aria-label="Web execution mode">'
        + '<button type="button" class="ns-web-mode-btn' + (curMode === 'cli' ? ' on' : '') + '" data-web-mode="cli" data-action="' + esc(action.id) + '" aria-pressed="' + (curMode === 'cli' ? 'true' : 'false') + '">1-Click CLI (curl)</button>'
        + '<button type="button" class="ns-web-mode-btn' + (curMode === 'burp' ? ' on' : '') + '" data-web-mode="burp" data-action="' + esc(action.id) + '" aria-pressed="' + (curMode === 'burp' ? 'true' : 'false') + '">Burp Guide</button>'
        + '</div>';
    }

    html += '</div>';
    return html;
  }

  // The default command for a move at a locus: the house-toolkit (nxc) pick, a switchless probe first, never
  // a command already settled by a held fact, never one still gated on an unearned fact, and preferring
  // untried commands over those already run in the current access epoch.
  function isGuidedStepperMove(move) {
    if (!move) return false;
    if (OBOL.pack && typeof OBOL.pack.isGuidedSequenceMove === 'function') {
      return OBOL.pack.isGuidedSequenceMove(move);
    }
    return !!(move.stepper || (move.sequence && (move.id === 'pivot-ligolo' || move.id === 'pivot-chisel-socks' || move.id === 'dns-tunnel' || move.id === 'jdwp-local-privesc')));
  }

  function firstCmdIndexForLocus(move, locus, facts, variants) {
    if (!move) return 0;
    var isStepper = isGuidedStepperMove(move);
    var eng = OBOL.store.active() || {};
    var commandParams = move.resolvedContext ? move.resolvedContext.params : Object.assign({}, eng.params || {}, facts && facts.context ? {target:facts.context.target} : {});
    var targetIp = move.contextTarget || (commandParams && commandParams.target) || '';
    var filled = variants || OBOL.command.fillAll(move, facts, fillOptsForTarget(eng, commandParams, targetIp));
    var curEpoch = (OBOL.pack && OBOL.pack.accessEpoch && facts) ? OBOL.pack.accessEpoch(facts) : '';
    function isGatedCmd(cmd, i) {
      var commandFacts = facts && facts.forAction ? facts.forAction(move, cmd) : facts;
      return (move.eligible && commandFacts && !move.eligible(commandFacts))
        || OBOL.pack.commandSettled(cmd, commandFacts)
        || (OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmd, commandFacts, move))
        || cmdGated(filled[i]);
    }
    function isTriedCmd(cmd, i) {
      var commandFacts = facts && facts.forAction ? facts.forAction(move, cmd) : facts;
      var ctx = (commandFacts && commandFacts._resolvedContext) || move.resolvedContext || (facts && facts._resolvedContext);
      var tgt = move.contextTarget || (ctx && ctx.target) || (commandParams && commandParams.target) || '';
      var v = filled[i] || {};
      var checkFn = (isStepper && OBOL.command && OBOL.command.commandRanExactOrSig)
        ? OBOL.command.commandRanExactOrSig
        : (OBOL.command && OBOL.command.commandWasRun);
      var wasRun = checkFn
        ? checkFn(v.filled || v.run || '', eng.activities || [], commandParams, tgt)
        : false;
      return wasRun || cmdWasTriedInEpoch(move, cmd, v, eng, curEpoch, tgt, ctx);
    }
    if (isStepper && Array.isArray(move.commands) && move.commands.length) {
      var seqMap = (eng.ui && eng.ui.seqStepByAction) || {};
      var validSeq = [];
      for (var si = 0; si < move.commands.length; si++) {
        var sc = move.commands[si];
        if (sc && !sc.alt && !isGatedCmd(sc, si)) validSeq.push(si);
      }
      if (!validSeq.length) {
        for (var sj = 0; sj < move.commands.length; sj++) {
          if (!isGatedCmd(move.commands[sj], sj)) validSeq.push(sj);
        }
      }
      if (typeof seqMap[move.id] === 'number' && validSeq.indexOf(seqMap[move.id]) >= 0) {
        return seqMap[move.id];
      }
      for (var sk = 0; sk < validSeq.length; sk++) {
        var idxCand = validSeq[sk];
        if (!isTriedCmd(move.commands[idxCand], idxCand)) return idxCand;
      }
      return validSeq.length ? validSeq[0] : 0;
    }
    return OBOL.pack.preferredCommandIndex(
      move,
      locus,
      facts || null,
      isGatedCmd,
      isTriedCmd
    );
  }
  // "Because <held gate> → expect <first payoff>" - the attack-graph cause/effect in one plain line.
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
  function nsCommandRows(action, filled, selLocus, selIdx, spansBoth, facts, focusMode, cardTargetIp) {
    var eng = OBOL.store.active() || {}, acts = eng.activities || [], params = eng.params || {};
    var gatedNeeds = {};   // earned-token -> 1, union across all hidden (gated) commands, for the affordance
    var unavailableVariants = {};
    var items = [];
    var bhHopBanner = '';
    if (facts && facts.has('ad.attack_paths') && (action.id === 'bloodyad-acl' || action.id === 'ad-acl-abuse')) {
      var apList = facts.values('ad.attack_paths') || [];
      var pHops = (apList[0] && Array.isArray(apList[0].path)) ? apList[0].path : [];
      var joinedGroups = {};
      (facts.values('ad.group_joined') || []).forEach(function (jv) {
        if (jv && jv.group) joinedGroups[String(jv.group).split('@')[0].trim().toLowerCase()] = 1;
      });
      var hasDcsync = facts.has('ad.control_paths') || facts.has('ad.domain_control') || facts.has('loot.ntds');
      var hopPills = [], stepN = 0, currentMarked = false;
      pHops.forEach(function (h) {
        if (!h || /^memberof$/i.test(String(h.edge || ''))) return;
        stepN++;
        var hTo = String(h.to || '').split('@')[0].trim();
        var isGrp = /group/i.test(String(h.to_kind || '')) || /^add(?:member|self)$/i.test(String(h.edge || ''));
        if (!isGrp && !h.to_kind && !/^getchanges/i.test(String(h.edge || ''))) {
          var domPart = String(h.to || '').indexOf('@') >= 0 ? String(h.to || '').split('@')[1].trim() : '';
          if ((!domPart || hTo.toLowerCase() !== domPart.toLowerCase()) && hTo.indexOf('.') < 0) isGrp = true;
        }
        var done = isGrp ? !!joinedGroups[hTo.toLowerCase()] : hasDcsync;
        var statusTag = done ? 'Done' : (!currentMarked ? (currentMarked = true, '→ Run Now') : 'Next');
        var badgeStyle = done
          ? 'background:rgba(46,160,67,0.16);color:#3fb950;border:1px solid rgba(46,160,67,0.4);'
          : (statusTag === '→ Run Now'
            ? 'background:rgba(56,139,253,0.16);color:#58a6ff;border:1px solid rgba(56,139,253,0.45);'
            : 'background:rgba(139,148,158,0.12);color:#8b949e;border:1px solid rgba(139,148,158,0.3);');
        hopPills.push('<span class="bh-hop-pill" style="display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:4px;font-size:12px;' + badgeStyle + '">'
          + '<b>Step ' + stepN + ':</b> ' + esc(h.edge) + ' → <code>' + esc(hTo) + '</code> <span>(' + (done ? OBOL.ic('check') + ' ' : '') + statusTag + ')</span></span>');
      });
      if (hopPills.length) {
        bhHopBanner = '<div class="bh-path-banner" style="margin:0 0 8px 0;padding:8px 10px;border-radius:6px;background:rgba(56,139,253,0.06);border:1px solid rgba(56,139,253,0.22);display:flex;flex-wrap:wrap;align-items:center;gap:8px">'
          + '<span style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;opacity:0.8">BloodHound ACL Chain:</span>'
          + hopPills.join('<span class="ns-arrow" style="opacity:0.6">→</span>')
          + '</div>';
      }
    }
    var isStepper = isGuidedStepperMove(action);
    var seenCmdKeys = {};
    var locusStep = {};
    var seqGlobalStep = 0;
    (action.commands || []).forEach(function (cmdObj, i) {
      var commandFacts = facts && facts.forAction ? facts.forAction(action, cmdObj) : facts;
      if (action.eligible && commandFacts && !action.eligible(commandFacts)) {
        var unavailableLocus = OBOL.pack.commandLocus(cmdObj);
        unavailableVariants[(unavailableLocus === 'onhost' ? 'On-Host' : 'Remote') + ': ' + action.unmet(commandFacts)] = true;
        return;
      }
      // A command that has done its job drops out: a run-once probe (the switchless null-session check)
      // disappears once the fact it was there to prove is held, so you never re-run a question you answered.
      if (OBOL.pack.commandSettled(cmdObj, commandFacts)) return;
      if (OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmdObj, commandFacts, action)) {
        if (action.id === 'flag-hunt-windows' && cmdObj.requires_admin && !spansBoth) {
          gatedNeeds['administrative access (to spawn an on-host WMI/PsExec shell when WinRM 5985 & RDP 3389 are closed)'] = 1;
        }
        return;
      }
      var v = filled[i] || {};
      if (v.blocked) {
        items.push({ index: i, locus: OBOL.pack.commandLocus(cmdObj), hidden: false, isLead: i === selIdx, ran: false, alt: !!cmdObj.alt, html: '<div class="cmd-note" role="status">' + esc((v.errors || []).join(' ')) + '</div>' });
        return;
      }
      // A command whose time has not come drops out too: it still needs an EARNED fact (base DN, domain, a
      // credential) the operator has not proven yet. Collect what it waits on, then hide it; it returns,
      // filled, once that fact is minted. (Config tokens like lhost are not gates, see GATE_TOKENS.)
      var gates = cmdUnmetGates(v);
      if (gates.length) { gates.forEach(function (t) { gatedNeeds[GATE_LABEL[t] || t] = 1; }); return; }
      var locus = OBOL.pack.commandLocus(cmdObj);
      var hidden = spansBoth && locus !== selLocus;
      if (v.filled) {
        var dedupKey = locus + '|' + String(v.filled).trim()
          .replace(/'([A-Za-z0-9_@%+=:,./-]+)'/g, '$1')
          .replace(/"([A-Za-z0-9_@%+=:,./-]+)"/g, '$1')
          .replace(/\s+(?:-d|--domain)\s+\S+/g, '')
          .replace(/\s+/g, ' ');
        if (seenCmdKeys[dedupKey]) {
          if (i === selIdx) {
            var prev = seenCmdKeys[dedupKey];
            prev.isLead = true;
            prev.html = prev.html.replace('class="ns-cmd"', 'class="ns-cmd active"');
          }
          return;
        }
      }
      var stepNum = isStepper
        ? (!cmdObj.alt ? (++seqGlobalStep) : '+')
        : (locusStep[locus] = (locusStep[locus] || 0) + 1);
      var curEpoch = (OBOL.pack && OBOL.pack.accessEpoch && facts) ? OBOL.pack.accessEpoch(facts) : '';
      var rowCheckFn = (isStepper && OBOL.command && OBOL.command.commandRanExactOrSig)
        ? OBOL.command.commandRanExactOrSig
        : OBOL.command.commandWasRun;
      var ran = rowCheckFn(v.filled || v.run, acts, params, cardTargetIp) || cmdWasTriedInEpoch(action, cmdObj, v, eng, curEpoch, cardTargetIp);
      var unfilled = OBOL.command.unfilledTokens(v.filled || '');
      var fillable = unfilled.filter(function (t) { return !DERIVED_TOKENS[t]; });
      var fillRow = fillable.length
        ? '<div class="cmd-fill-row">' + fillable.map(function (t) {
            return '<label class="cmd-fill-lbl"><span>' + esc(FILL_LABEL[t] || t) + '</span>'
              + '<input class="cmd-fill" data-tok="' + esc(t) + '" placeholder="' + esc(FILL_PH[t] || ('value for ' + t)) + '" autocomplete="off" spellcheck="false"></label>';
          }).join('') + '</div>' : '';
      var step = action.sequence ? ('<span class="ns-cmd-step">' + stepNum + '</span>') : '';
      var ranTag = ran ? '<span class="ns-cmd-ran" title="OBOL saw this in your run ledger">Ran</span>' : '';
      var isLead = (i === selIdx);
      var fn = OBOL.fieldNote ? OBOL.fieldNote(action, i) : null;
      var webNoteText = (v && v.webNote) || (cmdObj && cmdObj.web_note) || '';
      var noteText = webNoteText || (cmdObj && cmdObj.note) || (fn && fn.what) || (fn && fn.land && fn.land[0]) || '';
      var noteHtml = (webNoteText || (focusMode && isLead && noteText)) ? ('<div class="ns-cmd-note">' + fmtNote(noteText) + '</div>') : '';
      var socksHtml = v.socksAvailable
        ? ('<div class="ns-socks-bar">'
          + '<span class="ns-socks-badge' + (v.socksWrapped ? ' is-on' : ' is-off') + '">'
          + (v.socksWrapped ? 'Via SOCKS (proxychains4 auto-applied)' : 'SOCKS tunnel active (showing unwrapped command)')
          + '</span>'
          + '<button type="button" class="ns-socks-toggle" data-toggle-socks="' + U.attr(cardTargetIp || params.target || '') + '" aria-pressed="' + (v.socksWrapped ? 'false' : 'true') + '">'
          + (v.socksWrapped ? 'Show Unwrapped' : 'Apply proxychains4')
          + '</button></div>')
        : '';
      var edbHtml = v.edbPatchSummary ? ('<div class="ns-edb-patch-badge">' + esc(v.edbPatchSummary) + '</div>') : '';
      var webTgtHtml = v.webTargetSummary ? ('<div class="ns-web-target-badge">Auto-wired target: <code>' + esc(v.webTargetSummary) + '</code></div>') : '';
      var pHintText = isLead ? pasteHintForCommand(v, cmdObj) : '';
      var pasteHintHtml = pHintText ? ('<div class="ns-paste-hint"><strong>What to paste back:</strong> ' + esc(pHintText) + '</div>') : '';

      var rowHtml = '<div class="ns-cmd' + (isLead ? ' active' : '') + (fillable.length ? ' cmd-fillable' : '') + '"'
        + ' tabindex="0" role="group" aria-label="' + U.attr('Command ' + (i + 1) + ', ' + locus) + '"'
        + ' data-cmd-index="' + i + '" data-locus="' + locus + '"' + (hidden ? ' hidden' : '')
        + ' data-cmd="' + U.attr(v.filled || '') + '"'
        + (fillable.length ? ' data-tmpl="' + U.attr(v.filled || '') + '"' : '') + '>'
        + socksHtml + edbHtml + webTgtHtml
        + '<div class="ns-cmd-line">' + step
        + '<code class="cmd-run-code">' + esc(v.filled || '') + '</code>' + ranTag
        + '<button type="button" class="btn-copy ns-cmd-copy" data-copy="' + U.attr(v.filled || '') + '" title="Copy command" aria-label="Copy command">' + OBOL.ic('clip') + '</button></div>'
        + noteHtml + pasteHintHtml
        + fillRow + missingToolHint(action, v) + '</div>';

      var itemObj = { index: i, locus: locus, hidden: hidden, isLead: isLead, ran: ran, alt: !!cmdObj.alt, html: rowHtml };
      items.push(itemObj);
      if (v.filled && dedupKey) seenCmdKeys[dedupKey] = itemObj;
    });

    var rows = '';
    if (isStepper && items.length) {
      var seqItems = items.filter(function (it) { return !it.alt; });
      if (!seqItems.length) seqItems = items.slice();
      var seqAlts = items.filter(function (it) { return it.alt; });
      var activeStep = seqItems.filter(function (it) { return it.index === selIdx; })[0]
        || items.filter(function (it) { return it.index === selIdx; })[0]
        || seqItems.filter(function (it) { return !it.ran; })[0]
        || seqItems[0];
      var activePos = seqItems.indexOf(activeStep);
      if (activePos < 0) activePos = 0;
      var totalSteps = seqItems.length;
      var stepK = activePos + 1;
      var locusText = activeStep.locus === 'onhost' ? 'ON TARGET SHELL' : 'ON KALI TERMINAL 1';
      var stepPillsHtml = totalSteps > 1
        ? ('<div class="ns-seq-pills" role="group" aria-label="Sequence steps">'
          + seqItems.map(function (it, pos) {
              var on = it === activeStep;
              return '<button type="button" class="ns-seq-pill' + (on ? ' on' : '') + (it.ran ? ' is-done' : '') + '" data-seq-goto="' + it.index + '" data-action="' + esc(action.id) + '" aria-pressed="' + (on ? 'true' : 'false') + '">Step ' + (pos + 1) + '</button>';
            }).join('')
          + '</div>')
        : '';
      var nextStepBtn = (stepK < totalSteps)
        ? ('<button type="button" class="btn-ghost ns-seq-next-btn" data-seq-next="' + seqItems[activePos + 1].index + '" data-action="' + esc(action.id) + '">Step ' + stepK + ' Running -&gt; Show Step ' + (stepK + 1) + '</button>')
        : '';
      rows += '<div class="ns-seq-stepper">'
        + '<div class="ns-seq-bar">'
        + '<span class="ns-seq-badge is-' + esc(activeStep.locus) + '">STEP ' + stepK + ' OF ' + totalSteps + ' · ' + locusText + '</span>'
        + stepPillsHtml
        + nextStepBtn
        + '</div>'
        + activeStep.html;
      var restSeq = items.filter(function (it) { return it !== activeStep; });
      if (restSeq.length) {
        var peekLbl = 'Show all ' + totalSteps + ' steps' + (seqAlts.length ? (' (+ ' + seqAlts.length + ' optional)') : '');
        rows += '<div class="ns-focus-alts">'
          + '<details class="ns-more-ways ns-seq-peek">'
          + '<summary class="ns-chip-more-ways">' + esc(peekLbl) + '</summary>'
          + '<div class="ns-alt-cmds">' + restSeq.map(function (it) { return it.html; }).join('') + '</div>'
          + '</details>'
          + '</div>';
      }
      rows += '</div>';
    } else if (focusMode) {
      var lead = null, alts = [];
      items.forEach(function (it) {
        if (it.isLead && !it.ran) {
          lead = it;
        }
      });
      if (!lead) {
        lead = items.filter(function (it) { return !it.hidden && !it.ran; })[0]
          || items.filter(function (it) { return !it.hidden; })[0]
          || items[0] || null;
      }
      items.forEach(function (it) {
        if (it !== lead) alts.push(it);
      });

      rows = lead ? lead.html : '';
      if (alts.length) {
        var altRowsHtml = alts.map(function (it) { return it.html; }).join('');
        var count = alts.length;
        var waysLabel = 'Show ' + count + (count === 1 ? ' More Way' : ' More Ways');
        rows += '<div class="ns-focus-alts">'
          + '<details class="ns-more-ways">'
          + '<summary class="ns-chip-more-ways">' + esc(waysLabel) + '</summary>'
          + '<div class="ns-alt-cmds">' + altRowsHtml + '</div>'
          + '</details>'
          + '<a class="ns-chip-lib" href="#/library/moves?q=' + esc(action.id) + '">Open In Library -&gt;</a>'
          + '</div>';
      }
    } else {
      var untriedItems = items.filter(function (it) { return !it.ran; });
      var primaryUntried = untriedItems.filter(function (it) { return !it.alt; });
      var altUntried = untriedItems.filter(function (it) { return it.alt; });
      var ranItems = items.filter(function (it) { return it.ran; });
      if (untriedItems.length) {
        var mainList = primaryUntried.length ? primaryUntried : untriedItems;
        rows = mainList.map(function (it) { return it.html; }).join('');
        if (primaryUntried.length && altUntried.length) {
          var visibleAltCount = altUntried.filter(function (it) { return !it.hidden; }).length;
          if (visibleAltCount > 0) {
            var altLabel = 'Show ' + visibleAltCount + (visibleAltCount === 1 ? ' More Way' : ' More Ways');
            rows += '<div class="ns-focus-alts">'
              + '<details class="ns-more-ways">'
              + '<summary class="ns-chip-more-ways">' + esc(altLabel) + '</summary>'
              + '<div class="ns-alt-cmds">' + altUntried.map(function (it) { return it.html; }).join('') + '</div>'
              + '</details>'
              + '</div>';
          } else {
            rows += altUntried.map(function (it) { return it.html; }).join('');
          }
        }
        if (ranItems.length) {
          var ranHtml = ranItems.map(function (it) { return it.html; }).join('');
          rows += '<div class="ns-focus-alts">'
            + '<details class="ns-more-ways">'
            + '<summary class="ns-chip-more-ways">' + esc('Already tried (' + ranItems.length + ')') + '</summary>'
            + '<div class="ns-alt-cmds">' + ranHtml + '</div>'
            + '</details>'
            + '</div>';
        }
      } else {
        rows = items.map(function (it) { return it.html; }).join('');
      }
    }

    // Progressive disclosure: one quiet line for the commands still waiting on a fact, so the user knows
    // more unlocks here without seeing commands they cannot run yet.
    var needs = Object.keys(gatedNeeds);
    if (needs.length) {
      rows += '<div class="ns-cmd-locked" role="note">' + OBOL.ic('lock')
        + '<span>More unlocks once you have ' + esc(humanList(needs)) + '.</span></div>';
    }
    Object.keys(unavailableVariants).forEach(function (reason) {
      rows += '<div class="ns-cmd-locked" role="note">' + OBOL.ic('lock') + '<span>' + esc(reason) + '</span></div>';
    });
    return bhHopBanner + rows;
  }
  // "a, b and c" from a short list, for the unlocks affordance.
  function humanList(a) {
    if (a.length <= 1) return a[0] || '';
    if (a.length === 2) return a[0] + ' and ' + a[1];
    return a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1];
  }

  function actionTargetLabel(action, facts, eng, focusedTarget) {
    if (action.contextTarget) return action.contextTarget;
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

  function effectiveLocus(action, facts, filled, selLocus) {
    var loci = OBOL.pack.moveCommandLoci(action, facts);
    if (!loci.both) {
      return loci.onhost ? 'onhost' : (loci.remote ? 'remote' : selLocus);
    }
    var cmds = action.commands || [];
    function hasUngated(loc) {
      for (var i = 0; i < cmds.length; i++) {
        if (OBOL.pack.commandSettled(cmds[i], facts)) continue;
        var commandFacts = facts && facts.forAction ? facts.forAction(action, cmds[i]) : facts;
        if (action.eligible && commandFacts && !action.eligible(commandFacts)) continue;
        if (OBOL.pack.commandIsEligible && !OBOL.pack.commandIsEligible(cmds[i], commandFacts, action)) continue;
        if (OBOL.pack.commandLocus(cmds[i]) === loc && !cmdGated(filled[i])) return true;
      }
      return false;
    }
    var other = selLocus === 'remote' ? 'onhost' : 'remote';
    if (!hasUngated(selLocus) && hasUngated(other)) return other;
    return selLocus;
  }

  function renderPathChooserRegion(action, pc, pcOpen, selIdx) {
    if (!action) return '';
    var hasMap = !!(OBOL.pathChooser && OBOL.pathChooser.ACTION_TO_DECK && OBOL.pathChooser.ACTION_TO_DECK[action.id]);
    var hasGroups = !!(pc && pc.groups && pc.groups.length);
    if (!hasGroups && !hasMap) return '';
    var readyLanes = 0, totalLanes = 0;
    if (hasGroups) {
      pc.groups.forEach(function (g) {
        (g.lanes || []).forEach(function (l) {
          totalLanes++;
          if (l.status !== 'locked') readyLanes++;
        });
      });
    }
    var countN = readyLanes || totalLanes || 3;
    var hasAlert = !!(pc && pc.needsBothFlagsOnHost);
    return '<div class="ns-pc-wrap ns-pc-card-bridge" data-action="' + esc(action.id) + '">'
      + '<button type="button" class="ns-open-deck-btn' + (hasAlert ? ' has-alert' : '') + '" data-open-deck-action="' + esc(action.id) + '">'
      + '<span class="ns-open-deck-left"><span class="ns-pc-spark">' + OBOL.ic('branch') + '</span><span class="ns-open-deck-title">Choose Your Path in Operator Deck</span></span>'
      + '<span class="ns-open-deck-meta">' + countN + ' Ready Lane' + (countN === 1 ? '' : 's') + ' · Swap Tools &amp; Options →</span>'
      + '</button>'
      + '</div>';
  }

  // Closed cards need only their summary. Build commands when a card is opened.
  function nsCard(action, facts, params, opts) {
    opts = opts || {};
    if (action.resolvedContext) { facts = action.resolvedContext.facts; params = action.resolvedContext.params; }
    var famClass = ' ns-ph-' + OBOL.phases.phaseOfAction(action);
    var nCmd = (action.commands || []).length, body = '';
    if (opts.selected) {
    var activeEng = OBOL.store.active() || {};
    var dirs = OBOL.workspace.tokens(activeEng);
    var cardTargetIp = (opts.targetBadge && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(opts.targetBadge))
      ? opts.targetBadge
      : (action.contextTarget || (OBOL.store.activeTarget && OBOL.store.activeTarget()) || (params && params.target) || '');
    var filled = opts.filled || OBOL.command.fillAll(action, facts, fillOptsForTarget(activeEng, params, cardTargetIp));
    var isStepper = isGuidedStepperMove(action);
    var loci = OBOL.pack.moveCommandLoci(action, facts);
    var spansBoth = loci.both && !isStepper;
    var isFocused = (action.id === nsSel.id);
    var rawLocus = (isFocused && nsSel.userLocus && nsSel.locus) ? nsSel.locus : OBOL.pack.defaultCommandLocus(action, facts);
    var selLocus = (isFocused && nsSel.userLocus && spansBoth) ? rawLocus : effectiveLocus(action, facts, filled, rawLocus);
    var curSelCmd = isFocused && action.commands ? action.commands[nsSel.idx] : null;
    var curSelFacts = curSelCmd && facts && facts.forAction ? facts.forAction(action, curSelCmd) : facts;
    var curEpoch = (OBOL.pack && OBOL.pack.accessEpoch && facts) ? OBOL.pack.accessEpoch(facts) : '';
    var curSelCtx = (curSelFacts && curSelFacts._resolvedContext) || action.resolvedContext || (facts && facts._resolvedContext);
    var curCheckFn = (isStepper && OBOL.command && OBOL.command.commandRanExactOrSig)
      ? OBOL.command.commandRanExactOrSig
      : OBOL.command.commandWasRun;
    var curSelTried = curSelCmd ? (
      curCheckFn(((filled[nsSel.idx] && (filled[nsSel.idx].filled || filled[nsSel.idx].run)) || ''), activeEng.activities || [], params, cardTargetIp)
      || cmdWasTriedInEpoch(action, curSelCmd, filled[nsSel.idx], activeEng, curEpoch, cardTargetIp, curSelCtx)
    ) : false;
    var pinnedSeqIdx = (isStepper && activeEng.ui && activeEng.ui.seqStepByAction && typeof activeEng.ui.seqStepByAction[action.id] === 'number')
      ? activeEng.ui.seqStepByAction[action.id] : -1;
    var hasPinnedSeqStep = pinnedSeqIdx >= 0;
    var curSelInvalid = !curSelCmd
      || (spansBoth && OBOL.pack.commandLocus(curSelCmd) !== selLocus)
      || OBOL.pack.commandSettled(curSelCmd, curSelFacts)
      || cmdGated(filled[nsSel.idx])
      || (hasPinnedSeqStep && nsSel.idx !== pinnedSeqIdx)
      || (!nsSel.userCmd && !hasPinnedSeqStep && curSelTried);
    var selIdx = (isFocused && !curSelInvalid) ? nsSel.idx : firstCmdIndexForLocus(action, selLocus, facts, filled);
    if (isFocused && curSelInvalid) {
      nsSel.idx = selIdx;
    }
    if (isFocused && isStepper && action.commands && action.commands[selIdx]) {
      selLocus = OBOL.pack.commandLocus(action.commands[selIdx]);
      nsSel.locus = selLocus;
    }
    var pc = (OBOL.pathChooser && OBOL.pathChooser.build) ? OBOL.pathChooser.build(action, facts, params, filled, activeEng) : null;
    var hasDeckMap = !!(OBOL.pathChooser && OBOL.pathChooser.ACTION_TO_DECK && OBOL.pathChooser.ACTION_TO_DECK[action.id]);
    var pcHtml = (pc || hasDeckMap) ? renderPathChooserRegion(action, pc, false, selIdx) : '';
    var toggle = spansBoth
      ? '<div class="ns-toggle" role="group" aria-label="Where to run this">'
        + '<span class="ns-toggle-k">Run from:</span>'
        + '<button type="button" data-locus="remote" class="' + (selLocus === 'remote' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'remote') + '" title="Run remotely from your Kali terminal">Remote (Kali)</button>'
        + '<button type="button" data-locus="onhost" class="' + (selLocus === 'onhost' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'onhost') + '" title="Run inside an interactive shell on the target host">On-Host Shell</button>'
        + '</div>' : '';
    var webStripHtml = renderWebSurfaceStrip(action, facts, activeEng, cardTargetIp);
    var leadTip = opts.suggested
      ? '<div class="ns-card-tip">After running a command, click <strong>Paste Output</strong> so OBOL reads the result (or click <strong>Ran - Nothing Found</strong> inside Paste Output if it came back empty).</div>'
      : '';
    body = '<div class="ns-body">'
      + pcHtml
      + toggle
      + prepBlock(action, facts, dirs)
      + webStripHtml
      + '<div class="ns-cmds">' + nsCommandRows(action, filled, selLocus, selIdx, spansBoth, facts, opts.focusMode, cardTargetIp) + '</div>'
      + '<div class="ns-card-actions">'
      + '<button type="button" class="btn-ghost btn-pasteback" data-action="' + esc(action.id) + '" aria-expanded="false">Paste Output</button>'
      + '<button type="button" class="btn-ghost btn-done" data-action="' + esc(action.id) + '">Mark Done</button>'
      + nsBuildInTools(action)
      + '</div>'
      + leadTip
      + '<div class="move-ingest" data-action="' + esc(action.id) + '" data-cmd="' + U.attr((filled[selIdx] && filled[selIdx].filled) || (filled[0] && filled[0].filled) || '') + '" data-locus="' + esc(selLocus || 'remote') + '" hidden>'
      + '<textarea class="mi-text" placeholder="Paste the terminal output from running this command (or paste multiple commands run in sequence). If it ran cleanly with no output, click Ran - Nothing Found below." spellcheck="false"></textarea>'
      + '<div class="mi-row"><button type="button" class="btn-primary mi-go" data-action="' + esc(action.id) + '" data-target-ip="' + esc(cardTargetIp) + '">Ingest to Facts</button>'
      + '<button type="button" class="btn-ghost mi-empty" data-action="' + esc(action.id) + '" data-target-ip="' + esc(cardTargetIp) + '" title="Click if this command completed cleanly with empty output or found nothing">Ran - Nothing Found</button>'
      + '<a class="mi-evlink" href="#/evidence/' + esc(action.id) + '">Big output or a screenshot? Full Evidence</a>'
      + '<span class="mi-result" role="status"></span></div></div>'
      + '</div>';
    }
    // Not role="button" - the expanded body holds real buttons/inputs, which must not nest inside a
    // button for screen readers. It is a focusable region with an aria-label and Enter/Space handling.
    return '<article class="ns-card' + famClass + (opts.selected ? ' selected is-glow' : '') + '" tabindex="0"'
      + (opts.selected ? '' : ' data-body-deferred="1"')
      + ' aria-expanded="' + (opts.selected ? 'true' : 'false') + '"'
      + ' aria-label="' + U.attr(action.title + ' - press Enter to open its commands and field notes') + '" data-action="' + esc(action.id) + '" data-context-target="' + esc(params.target || '') + '">'
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
    var eng = (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var params = eng.params || {};
    Object.keys(docs).forEach(function (k) {
      if (facts.has(k)) {
        var hasAuthContext = facts.has('credential.available') || facts.has('credential.validated') || facts.has('smb.authenticated') || facts.has('smb.session') || facts.has('ldap.authenticated');
        // Guard: access_denied diagnostic is only relevant if credentials/accounts or authenticated operations exist
        if (k === 'blocker.access_denied') {
          // On a Domain Controller, --local-auth is impossible and invalid
          var isDC = facts.has('ad.dc_candidate') || facts.has('ad.domain_controller');
          if (isDC) return;
          // Must have valid credentials or an authenticated session, not an uncracked hash candidate
          if (!hasAuthContext) return;
        }
        if ((k === 'blocker.smb_null_denied' || k === 'blocker.ldap_anonymous_disabled') && hasAuthContext) {
          return;
        }
        if ((k === 'blocker.dcsync_denied' || k === 'blocker.acl_reauth') && (facts.has('ad.control_paths') || facts.has('ad.domain_control') || facts.has('loot.ntds'))) {
          return;
        }
        if (k === 'blocker.nxc_bh_config' && (facts.has('ad.graph.collected') || facts.has('ad.attack_paths'))) {
          return;
        }
        // Pre-flight Stage 2 hazard cards yield once the corresponding Stage 3 runtime blocker card is active
        if (k === 'exploit.hazard_py2' && facts.has('blocker.py2_syntax_or_module')) return;
        if (k === 'exploit.hazard_py3_syntax' && (facts.has('blocker.py2_syntax_or_module') || facts.has('blocker.python_dep_or_pep668'))) return;
        if (k === 'exploit.hazard_burp_proxy' && facts.has('blocker.hardcoded_proxy')) return;
        if (k === 'exploit.hazard_c_compile' && facts.has('blocker.glibc_or_arch_mismatch')) return;
        var scopes = {};
        (facts.facts || []).forEach(function (f) { if (f.kind === k && f.state === 'supported') scopes[f.scope] = true; });
        Object.keys(scopes).forEach(function (scope) {
        var d = Object.assign({ factKind: k, factScope: scope }, docs[k]);
        if (d.code) {
          var scopeTarget = /^host:/.test(scope) ? scope.slice(5) : '';
          var scopeFacts = (scopeTarget && OBOL.store && OBOL.store.factSetForTarget)
            ? OBOL.store.factSetForTarget(scopeTarget)
            : facts;
          var fillParams = Object.assign({}, params, scopeTarget ? { target: scopeTarget } : {});
          var fillOpts = Object.assign({
            params: fillParams,
            profile: eng.profile,
            workspace: (OBOL.workspace && OBOL.workspace.tokens) ? OBOL.workspace.tokens(eng) : {}
          }, fillParams);
          var resolvedEdbFile = (OBOL.command && OBOL.command.fillTemplate)
            ? OBOL.command.fillTemplate('{{edb_file}}', scopeFacts, fillOpts)
            : nsFill('{{edb_file}}', scopeFacts, fillParams);
          if (resolvedEdbFile === '{{edb_file}}' || /^<edb_file>$/i.test(resolvedEdbFile)) resolvedEdbFile = '';
          var rawCodeTmpl = String(d.code);
          if (k === 'exploit.hazard_java_target' && resolvedEdbFile && /\.(?:py|sh|rb|pl)$/i.test(resolvedEdbFile)) {
            rawCodeTmpl = "sed -i -E 's/-(source|target)[[:space:]]+(1\\.[567]|[567])/-\\1 8/g' {{edb_file}}";
          }
          var javaPlaceholder = (resolvedEdbFile && /\.java$/i.test(resolvedEdbFile)) ? '{{edb_file|Exploit.java}}' : 'Exploit.java';
          var tmpl = rawCodeTmpl
            .replace(/<(?:dc-ip|target-ip|target)>/g, '{{target}}')
            .replace(/<(?:user|username|svc|target-user)>/g, '{{user}}')
            .replace(/<pass>/g, "'{{password}}'")
            .replace(/<domain>/g, '{{domain}}')
            .replace(/<group>/g, '{{joined_group}}')
            .replace(/<host\.domain>/g, '{{dc_fqdn|{{domain}}}}')
            .replace(/<share>/g, '{{share}}')
            .replace(/<hashfile>/g, '{{hashfile}}')
            .replace(/<lhost>/g, '{{lhost}}')
            .replace(/<exploit\.py>/g, '{{edb_file|exploit.py}}')
            .replace(/<exploit\.c>/g, '{{edb_file|exploit.c}}')
            .replace(/<exploit\.java>/g, javaPlaceholder)
            .replace(/<script>/g, '{{edb_file|script.sh}}');
          if (OBOL.command && OBOL.command.fillTemplate) {
            d.code = OBOL.command.fillTemplate(tmpl, scopeFacts, fillOpts);
          } else {
            d.code = nsFill(tmpl, scopeFacts, fillParams);
          }
        }
        out.push(d);
        });
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
            + (d.factKind ? ('<button type="button" class="fix-card-dismiss" data-dismiss-blocker="' + esc(d.factKind) + '" data-fact-scope="' + esc(d.factScope || '') + '" title="Dismiss this diagnostic">' + OBOL.ic('check') + ' Resolved</button>') : '')
            + '</div>'
            + '<div class="fix-card-body">'
            + (d.why ? ('<div class="fix-card-why"><strong>Root Cause:</strong> ' + esc(d.why) + '</div>') : '')
            + (d.body ? ('<p class="fix-card-desc">' + esc(d.body) + '</p>') : '')
            + (d.code ? ('<div class="fix-card-cmd-wrap">'
                + '<pre class="fix-card-code"><code>' + esc(d.code) + '</code></pre>'
                + '<button type="button" class="btn-copy fix-card-copy" data-copy="' + U.attr(d.code) + '" title="Copy fix command">Copy Fix</button>'
                + '</div>') : '')
            + (d.gotcha ? ('<div class="fix-card-gotcha"><strong>Gotcha / Trap:</strong> ' + esc(d.gotcha) + '</div>') : '')
            + '<div class="fix-card-gotcha"><strong>Next Step:</strong> No need to paste this fix output back. Click <strong>Resolved</strong> above (or proceed directly to <strong>#1 Suggested Start</strong> below; this banner clears automatically when your next move succeeds).</div>'
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
    var actEng = (OBOL.store && OBOL.store.active) ? OBOL.store.active() : null;
    var flagsOn = (OBOL.profile && OBOL.profile.hasFlags && actEng && actEng.profile) ? OBOL.profile.hasFlags(actEng.profile) : true;

    if (newShell) {
      var isWin = p.indexOf('foothold.windows') >= 0;
      var isLin = p.indexOf('foothold.linux') >= 0 || p.indexOf('access.shell') >= 0;
      if (!isWin && !isLin) isLin = true;
      var orient = '';
      if (isLin && O.linux) orient += nsSetupStep(O.linux.label, O.linux.cmd);
      if (isWin && O.windows) orient += nsSetupStep(O.windows.label, O.windows.cmd);
      var leadTxt = flagsOn
        ? 'You have a shell. Get your bearings first, then the Cockpit ranks your next moves. Do not forget to grab the flag.'
        : 'You have a shell. Get your bearings and record your host identity first, then the Cockpit ranks privilege escalation, credential harvesting, and lateral movement.';
      var html = '<p class="ns-cn-h">Once You Are In</p>'
        + '<p class="ns-oyi-lead">' + leadTxt + '</p>';
      if (orient) html += '<div class="ns-setup">' + orient + '</div>';
      // The PTY stabilization is a real multi-step, two-machine sequence, so it is NOT crammed into one copy
      // box: it renders as ordered, machine-labelled steps (Linux shells only; Windows needs no PTY fix).
      if (isLin && OBOL.renderPtySteps) html += OBOL.renderPtySteps();
      return html;
    }
    // Elevation: you already have a working shell and just became root/SYSTEM. No PTY to fix.
    var win = p.indexOf('access.system') >= 0;
    if (!flagsOn) {
      var pocCmd = win ? 'whoami /all & hostname & ipconfig' : 'id; hostname; ip -4 addr | grep inet';
      return '<p class="ns-cn-h">You Have ' + (win ? 'SYSTEM' : 'Root') + ' Now</p>'
        + '<p class="ns-oyi-lead">Confirm administrative access with your host identity in one terminal frame for the report, then proceed to credential harvesting (NTDS / SAM / LSASS / SSH keys) and lateral movement.</p>'
        + '<div class="ns-setup">' + nsSetupStep('Record PoC Administrative Identity', pocCmd, 'proof') + '</div>';
    }
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
      ? '<p class="ns-oyi-lead">OBOL found ' + r.items.length + ' that GTFOBins can turn into a root shell. Here ' + (r.items.length === 1 ? 'is' : 'are') + ' the exact escape' + (r.items.length === 1 ? '' : 's') + ':</p>'
      : '<p class="ns-oyi-lead">Paste your ' + (r.context === 'suid' ? 'SUID list' : '<code>sudo -l</code>') + ' output on Evidence and OBOL fills the exact escape here. Or look one up now:</p>';
    var lookup = '<div class="ns-gtfo-lookup"><label class="cmd-fill-lbl"><span>Look Up A Binary</span>'
      + '<input class="ns-gtfo-input" data-ctx="' + r.context + '" placeholder="e.g. find, awk, vim, less" autocomplete="off" spellcheck="false"></label>'
      + '<div class="ns-gtfo-result" aria-live="polite"></div></div>';
    return '<p class="ns-cn-h">GTFOBins: Exact ' + ctxLabel + ' Escape</p>' + intro
      + (rows ? '<div class="ns-setup">' + rows + '</div>' : '') + lookup;
  }
  // "Build In Tools": deep link a move to the exact Tool Builder, pre-selecting the protocol / recipe /
  // mode most relevant to the move, so the card lands ready to tune instead of on a blank tool. The link
  // is #/tools/<builderId>/<selector>; the Tools route applies the selector (a recipe id, a protocol
  // value, or a hashcat/john mode). Classify by the move's tool + id/title + produces, all authored data.
  var TOOL_TO_BUILDER = {
    nxc: 'tb-nxc', netexec: 'tb-nxc', crackmapexec: 'tb-nxc', cme: 'tb-nxc',
    hashcat: 'tb-hashcat', john: 'tb-john',
    'evil-winrm': 'tb-evilwinrm', evilwinrm: 'tb-evilwinrm',
    hydra: 'tb-hydra', kerbrute: 'tb-kerbrute',
    ffuf: 'tb-ffuf', gobuster: 'tb-gobuster-ferox', feroxbuster: 'tb-gobuster-ferox',
    sqlmap: 'tb-sqlmap', curl: 'tb-curl', nmap: 'tb-nmap', rustscan: 'tb-rustscan',
    secretsdump: 'tb-secretsdump', 'impacket-secretsdump': 'tb-secretsdump',
    getuserspns: 'tb-getuserspns', 'impacket-getuserspns': 'tb-getuserspns',
    getnpusers: 'tb-getnpusers', 'impacket-getnpusers': 'tb-getnpusers',
    certipy: 'tb-certipy', 'certipy-ad': 'tb-certipy',
    mssqlclient: 'tb-mssqlclient', 'impacket-mssqlclient': 'tb-mssqlclient',
    bloodyad: 'tb-bloodyad', coercer: 'tb-coercer', ntlmrelayx: 'tb-ntlmrelayx',
    responder: 'tb-responder', wpscan: 'tb-wpscan', smbmap: 'tb-smbmap', smbclient: 'tb-smbclient',
    wmiexec: 'tb-impacket-exec', 'impacket-wmiexec': 'tb-impacket-exec', psexec: 'tb-impacket-exec',
    'impacket-psexec': 'tb-impacket-exec', atexec: 'tb-impacket-exec', smbexec: 'tb-impacket-exec',
    ldapsearch: 'tb-ldapsearch', psql: 'tb-psql', mysql: 'tb-mysql',
    'bloodhound-python': 'tb-bloodhound-python', bloodhound: 'tb-bloodhound-python', masscan: 'tb-masscan',
  };
  // True if the Tools surface actually has a builder for this id/name (so we do not deep-link a move to a
  // tool that has no builder, which would land on the wrong tool). Needs OBOL.TOOLSET, loaded once the
  // Tools tab has been opened; a mapped TOOL_TO_BUILDER id is always a real builder, so it never needs this.
  function builderExists(name) {
    try { return (OBOL.TOOLSET || []).some(function (b) { return b.id === name || String(b.tool || '').toLowerCase() === name || (b.equips || []).some(function (t) { return String(t).toLowerCase() === name; }); }); }
    catch (e) { return false; }
  }
  function nsToolTarget(move) {
    if (!move) return null;
    var tool = String(move.tool || (move.tools && move.tools[0]) || '').toLowerCase();
    if (!tool) return null;
    var builder = TOOL_TO_BUILDER[tool];
    if (!builder) { if (!builderExists(tool)) return null; builder = tool; } // suppress the link for a tool OBOL has no builder for
    var idt = ((move.id || '') + ' ' + (move.title || '')).toLowerCase();
    var pt = (move.produces || []).join(' ').toLowerCase() + ' ' + idt;
    var sel = '';
    if (builder === 'tb-nxc') {
      if (/kerberoast/.test(idt)) sel = 'kerberoast';
      else if (/as.?rep/.test(idt)) sel = 'asrep';
      else if (/bloodhound/.test(idt)) sel = 'bloodhound';
      else if (/ntds|dcsync/.test(idt)) sel = 'ntds';
      else if (/\bspider\b/.test(idt)) sel = 'spider';
      else if (/\blaps\b/.test(idt)) sel = 'laps-smb';
      else if (/\bsam\b/.test(idt)) sel = 'sam';
      else if (/\blsa\b/.test(idt)) sel = 'lsa';
      else if (/share/.test(idt)) sel = 'shares';
      else if (/password policy|pass.?pol/.test(idt)) sel = 'pass-pol';
      else if (/rid.?(brute|cycl)/.test(idt)) sel = 'rid-brute';
      else if (/winrm|remote (exec|command|shell)/.test(idt)) sel = 'winrm-check';
      else if (/mssql|sql server/.test(idt)) sel = 'mssql-check';
      else if (/\bftp\b/.test(idt)) sel = 'ftp-check';
      else if (/user list|\busers?\b|enumerate user|userlist/.test(idt)) sel = 'users';
      else if (/validate|confirm (a )?cred|check cred/.test(idt)) sel = 'validate';
    } else if (builder === 'tb-hashcat') {
      if (/kerberoast|krb5tgs|\btgs\b/.test(pt)) sel = '13100';
      else if (/as.?rep|krb5asrep/.test(pt)) sel = '18200';
      else if (/netntlmv2/.test(pt)) sel = '5600';
      else if (/\bntlm\b|ntds|nt hash|dcc|mscache|secretsdump/.test(pt)) sel = '1000';
    } else if (builder === 'tb-john') {
      if (/kerberoast|krb5tgs|\btgs\b/.test(pt)) sel = 'krb5tgs';
      else if (/as.?rep|krb5asrep/.test(pt)) sel = 'krb5asrep';
      else if (/netntlmv2/.test(pt)) sel = 'netntlmv2';
      else if (/\bntlm\b|ntds|nt hash/.test(pt)) sel = 'NT';
    }
    return { builder: builder, sel: sel };
  }
  function nsBuildInTools(move) {
    var tt = nsToolTarget(move);
    if (!tt) return '';
    return '<a class="btn-ghost" href="#/tools/' + esc(tt.builder) + (tt.sel ? '/' + esc(tt.sel) : '') + '">Build In Tools</a>';
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
    // password spraying
    if (/password.?spray|\bspray\b/i.test(idt)) {
      add('spray', 'Plan Spray In Workbench');
    }
    // a sudo / SUID / LOLBAS escape
    if (move.id === 'sudo-abuse' || move.id === 'suid-gtfobins' || /gtfobins|lolbas/i.test(idt)) {
      add('gtfobins', 'Open GTFOBins & LOLBAS');
    }
    // pivoting / port forwarding / tunneling
    if (/pivot|port.?forward|tunnel|chisel|ligolo|socat|proxychains|internal.?port/i.test(idt) || /\bpivot\./.test(produces)) {
      add('pivot', 'Build Pivot / Tunnel');
    }
    // file transfer / staging tools (linpeas, winpeas, pspy, sharphound, potato)
    if (/linpeas|winpeas|pspy|sharphound|potato|file.?transfer|stage.?tool|upload.?payload/i.test(idt)) {
      add('transfer', 'Build File Transfer');
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
    if (/\bjwt\b|json web token/i.test(idt)) add('jwt', 'Forge / Sign JWT');
    // manual SQL injection: the Workbench builds the payloads step by step
    if (/sql injection|sqli|sql-inj/i.test(idt)) add('sqli', 'Build The SQLi');
    // payloads that often need encoding or evasion (LFI/traversal, command injection, XSS)
    if (/command inj|cmdi|local file inclusion|\blfi\b|traversal|\bxss\b|cross-site script/i.test(idt)) add('codec', 'Encode / Evasion Payload');
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
    var actEng = (OBOL.store && OBOL.store.active) ? OBOL.store.active() : null;
    var flagsOn = (OBOL.profile && OBOL.profile.hasFlags && actEng && actEng.profile) ? OBOL.profile.hasFlags(actEng.profile) : true;
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
      out.push({
        trigger: 'Initial Shell Landed',
        action: flagsOn
          ? 'Stabilize PTY session, run situational awareness (whoami /priv), and locate user.txt flag.'
          : 'Stabilize PTY session, run situational awareness (whoami /priv), and enumerate local credentials and privilege escalation vectors.'
      });
    }
    if (!out.length && prod.length) {
      out.push({ trigger: 'Move Completed', action: 'Minted facts advance the Cockpit frontier; check Ready Now for the next unlocked commands.' });
    }
    return out;
  }

  function nsDoctorBlock(d, facts) {
    var code = d.code || '';
    if (code) {
      var act = OBOL.store ? OBOL.store.active() : null;
      var f = facts || (act && act.facts) || [];
      var p = (act && act.params) || {};
      var tmpl = String(code)
        .replace(/<(?:dc-ip|target-ip|target)>/g, '{{target}}')
        .replace(/<(?:user|username|svc|target-user)>/g, '{{user}}')
        .replace(/<pass>/g, "'{{password}}'")
        .replace(/<domain>/g, '{{domain}}')
        .replace(/<group>/g, '{{joined_group}}')
        .replace(/<host\.domain>/g, '{{dc_fqdn|{{domain}}}}')
        .replace(/<share>/g, '{{share}}')
        .replace(/<hashfile>/g, '{{hashfile}}')
        .replace(/<lhost>/g, '{{lhost}}')
        .replace(/<exploit\.py>/g, '{{edb_file|exploit.py}}')
        .replace(/<exploit\.c>/g, '{{edb_file|exploit.c}}')
        .replace(/<exploit\.java>/g, '{{edb_file|Exploit.java}}')
        .replace(/<script>/g, '{{edb_file|script.sh}}');
      code = nsFill(tmpl, f, p);
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
  function nsExampleBlock(move, idx, cmdText) {
    if (!move || !OBOL.study || !OBOL.study.replayFor) return '';
    var rp = null; try { rp = OBOL.study.replayFor(move.id, idx, cmdText); } catch (e) { rp = null; }
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
    if (move.resolvedContext) { facts = move.resolvedContext.facts; params = move.resolvedContext.params; }
    var activeEng = OBOL.store.active() || {};
    var canvasTargetIp = move.contextTarget || (params && params.target) || (OBOL.store.activeTarget && OBOL.store.activeTarget()) || '';
    var filled = OBOL.command.fillAll(move, facts, fillOptsForTarget(activeEng, params, canvasTargetIp));
    var cmdText = (filled[idx] && filled[idx].filled) || '';
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, idx) : null;
    var live = nsLiveDoctors(facts);
    var movePh = (OBOL.phases && OBOL.phases.phaseOfAction) ? OBOL.phases.phaseOfAction(move) : 'recon';
    var phCls = ' ns-ph-' + esc(movePh);
    var html = '<div class="ns-canvas-head' + phCls + '"><span class="ns-canvas-kick">Field Notes</span>'
      + '<span class="ns-canvas-sep">·</span>'
      + '<span class="ns-canvas-move" title="' + U.attr(move.title) + '">' + esc(move.title) + '</span></div>'
      + '<div class="ns-canvas-body' + phCls + '">';

    live.forEach(function (d) { html += nsDoctorBlock(d, facts); });

    // Staged command display
    if (cmdText) html += '<div class="ns-canvas-cmd' + phCls + '"><code>' + esc(cmdText) + '</code></div>';
    if (filled[idx] && filled[idx].webNote) {
      html += '<div class="ns-cmd-note" style="margin:6px 0 10px 0">' + fmtNote(filled[idx].webNote) + '</div>';
    }

    // "See It Run": toggleable Learn-style example run + expected output for this move.
    html += nsExampleBlock(move, idx, cmdText);

    var flagsExpl = (OBOL.command && OBOL.command.explainFlags) ? OBOL.command.explainFlags(cmdText) : [];
    var mistakes = (note && note.mistakes) || [];
    var lookSignals = (note && note.look) || [];
    var hasDoctor = (note && note.doctor) || (live && live.length > 0);

    var BC = OBOL.burpCopilot || null;
    var hasBurpTab = !!(BC && BC.isEligibleMove(move));
    var allowedTabs = hasBurpTab ? ['p1', 'p2', 'p3', 'p4', 'burp', 'all'] : ['p1', 'p2', 'p3', 'p4', 'all'];

    // Active tab preference (default: p1 for zero-scroll focused view, or burp via Smart Auto-Open)
    var activeTab = 'p1';
    try {
      var savedTab = sessionStorage.getItem('obol.pillar-tab');
      if (savedTab && allowedTabs.indexOf(savedTab) >= 0) {
        activeTab = savedTab;
      }
    } catch (e) {}
    if (hasBurpTab && _manualPillarMoveId !== move.id) {
      if (BC.shouldAutoOpen(move, facts, activeEng, canvasTargetIp)) {
        activeTab = 'burp';
      } else if (activeTab === 'burp') {
        activeTab = 'p1';
      }
    }

    // Segmented Pillar Tab Bar (keyboard navigable, zero-scroll)
    html += '<div class="anatomy-tabs" role="tablist" aria-label="Anatomy Pillars">'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p1' ? ' on' : '') + '" data-pillar-tab="p1" aria-selected="' + (activeTab === 'p1' ? 'true' : 'false') + '"><span class="tab-badge badge-p1">1</span> Goal</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p2' ? ' on' : '') + '" data-pillar-tab="p2" aria-selected="' + (activeTab === 'p2' ? 'true' : 'false') + '"><span class="tab-badge badge-p2">2</span> Syntax' + (flagsExpl.length ? ' <span class="tab-count">' + flagsExpl.length + '</span>' : '') + '</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p3' ? ' on' : '') + '" data-pillar-tab="p3" aria-selected="' + (activeTab === 'p3' ? 'true' : 'false') + '"><span class="tab-badge badge-p3">3</span> Gotchas' + (mistakes.length || hasDoctor ? ' <span class="tab-warn-dot" title="Gotchas or diagnostic tips available">!</span>' : '') + '</button>'
      + '<button type="button" role="tab" class="anatomy-tab-btn' + (activeTab === 'p4' ? ' on' : '') + '" data-pillar-tab="p4" aria-selected="' + (activeTab === 'p4' ? 'true' : 'false') + '"><span class="tab-badge badge-p4">4</span> Pivot</button>'
      + (hasBurpTab ? ('<button type="button" role="tab" class="anatomy-tab-btn anatomy-tab-burp' + (activeTab === 'burp' ? ' on' : '') + '" data-pillar-tab="burp" aria-selected="' + (activeTab === 'burp' ? 'true' : 'false') + '"><span class="tab-badge badge-burp">B</span> Burp Co-Pilot</button>') : '')
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
      + (winText ? ('<div class="ns-cn-win"><span class="ns-tick" aria-hidden="true">' + OBOL.ic('check') + '</span><span><strong>Expected Proof:</strong> ' + fmtNote(winText) + '</span></div>') : '')
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

    if (hasBurpTab) {
      html += '<section class="anatomy-pillar pillar-burp" data-pillar-section="burp"' + (activeTab !== 'all' && activeTab !== 'burp' ? ' hidden' : '') + '>'
        + '<div class="pillar-header">'
        + '<span class="pillar-badge badge-burp">Burp Co-Pilot</span>'
        + '<h4 class="pillar-title">Interactive Repeater Instrument</h4>'
        + '</div>'
        + '<div class="pillar-content">'
        + BC.renderPanel({ targetIp: canvasTargetIp, move: move, facts: facts })
        + '</div></section>';
    }

    html += '</div>';
    return html;
  }

  // The aspirational "Opens Up Next" strip: capability-unlocks only, nearest first, each with its fact
  // chips. Capped to a peek with a "+N more" expander so it invites rather than overwhelms.
  var _deferredOpensMoreHtml = '';
  function nsOpensStrip(opens) {
    _deferredOpensMoreHtml = '';
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
    if (more.length) {
      _deferredOpensMoreHtml = more.map(card).join('');
    }
    return '<section class="ns-opens"><div class="ns-opens-head">'
      + '<span class="ns-opens-kick">Opens Up Next</span>'
      + '<span class="ns-opens-sub">What a little more progress unlocks, closest first.</span>'
      + '<span class="ns-opens-n">' + opens.length + '</span></div>'
      + '<div class="ns-opens-peek">' + peek.map(card).join('') + '</div>'
      + (more.length ? '<details class="ns-opens-more"><summary>' + more.length + ' more, further out</summary>'
          + '<div class="ns-opens-peek" data-opens-deferred="1"></div></details>' : '')
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
    var flagsOn = (!OBOL.profile || !OBOL.profile.hasFlags || !eng) ? true : OBOL.profile.hasFlags(eng.profile);
    var flagsCardHtml = '';
    if (flagsOn || flags.length || located.length) {
      flagsCardHtml = railCard('Flags (' + flags.length + ')', (flags.length || located.length)
        ? '<ul class="rail-list rail-flags">' + flags.map(function (f) {
            var v = f.value || {}; var SL = { root: 'Root Flag', local: 'Local Flag', user: 'Local Flag' };
            var label = SL[v.slot] || U.titleCase(f.kind.split('.').pop().replace('_', ' '));
            var val = v.flag || '';
            // Show the WHOLE flag (wrapped, selectable, click-to-copy) - a captured flag is the deliverable.
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
        : '<div class="rail-empty">None captured yet.</div>');
    } else {
      var hasFoothold = facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('access.shell') || facts.has('foothold.webshell');
      var hasAdmin = facts.has('access.admin') || facts.has('access.system') || facts.has('access.root');
      var hasDomain = facts.has('loot.ntds') || facts.has('ad.domain_admin') || facts.has('ad.domain_control');
      flagsCardHtml = railCard('Objectives', '<ul class="rail-list">'
        + '<li><span>' + (hasFoothold ? OBOL.ic('check') : OBOL.ic('crosshair')) + ' Initial Foothold</span><span class="rail-produced">' + (hasFoothold ? 'Done' : 'Pending') + '</span></li>'
        + '<li><span>' + (hasAdmin ? OBOL.ic('check') : OBOL.ic('crosshair')) + ' Admin / Root</span><span class="rail-produced">' + (hasAdmin ? 'Done' : 'Pending') + '</span></li>'
        + (facts.has('ad.dc_candidate') || hasDomain ? ('<li><span>' + (hasDomain ? OBOL.ic('check') : OBOL.ic('crosshair')) + ' Domain Compromise</span><span class="rail-produced">' + (hasDomain ? 'Done' : 'Pending') + '</span></li>') : '')
        + '</ul>');
    }
    return '<aside class="context-rail" aria-label="Live context">'
      + railCard('Access', '<div class="rail-access ra-' + access[1] + '">' + esc(access[0]) + '</div>')
      + railCard('Next Move', topMove ? ('<div class="rail-move">' + esc(topMove.title) + '</div>') : '<div class="rail-empty">Log evidence to unlock moves.</div>')
      + flagsCardHtml
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

  // Shared coach computation - the SINGLE source of truth for "what's next". Used by this coach AND by
  // the engagement Hub's "Your Next Move" anchor, the Hub's per-target cards, and the Evidence summary,
  // so every screen shows the same move instead of disagreeing (the Hub used to call the old v1 ranker
  // while the coach called v2). Report-only writeup checks (OBOL.pack.isReportOnly) are pulled out of the
  // live ready/coming-up lists into their own group, so an info-severity finding (SPF/DMARC, headers, …)
  // can never headline a box you're actively working.
  function computeCoach(overrideTarget) {
    var eng = OBOL.store.active();
    var targetIp = (overrideTarget !== undefined) ? overrideTarget : (OBOL.store.activeTarget ? OBOL.store.activeTarget() : null);
    if (!targetIp && OBOL.context && (eng.targets || []).length > 1) {
      var computations = eng.targets.filter(function (t) { return t.ip || t.id; }).map(function (t) {
        return rankFor(OBOL.store.factSetForTarget(t.ip || t.id), {target:t.ip || t.id});
      });
      if (computations.length) {
        var result = Object.assign({}, computations[0], {target:null,targetContexts:computations});
        ['onFlow','comingUp','reportChecks'].forEach(function (section) {
          var picks = {}, entries = [];
          computations.forEach(function (c, hostIndex) { c[section].forEach(function (a, rank) {
            if (a.id === nsSel.id && nsSel.target && picks[a.id] && picks[a.id].action.contextTarget === nsSel.target) return;
            if (a.id === nsSel.id && a.contextTarget === nsSel.target) { picks[a.id] = {action:a,rank:rank,hostIndex:hostIndex}; return; }
            if (picks[a.id] && picks[a.id].rank <= rank) return;
            picks[a.id] = {action:a,rank:rank,hostIndex:hostIndex};
          }); });
          Object.keys(picks).forEach(function (id) { entries.push(picks[id]); });
          result[section] = entries.sort(function (a,b) { return a.rank-b.rank || a.hostIndex-b.hostIndex; }).map(function (e) { return e.action; });
        });
        return result;
      }
    }
    var facts = (targetIp && OBOL.store.factSetForTarget)
      ? OBOL.store.factSetForTarget(targetIp)
      : OBOL.store.factSet();
    return rankFor(facts, { target: targetIp });
  }
  // rankFor(facts, opts) is computeCoach generalized to ANY factset - the engagement-wide one for this coach and
  // the Hub anchor, or a single host's (factSetForTarget) for the per-target "Next Steps for this box"
  // panel - so every surface ranks moves the same way and shows the same prep steps. Report-only writeup
  // checks are split out; the frontier/phase are computed from the passed facts (correct per scope).
  function rankFor(facts, opts) {
    opts = opts || {};
    var eng = OBOL.store.active();
    var params = Object.assign({}, (eng && eng.params) || {});
    if (opts.target) params.target = opts.target;
    var context = null;
    if (OBOL.context) {
      var hosts = {};
      ((facts && facts.facts) || []).forEach(function (f) { if (/^host:/.test(f.scope || '') && f.scope !== 'host:target') hosts[f.scope.slice(5)] = true; });
      var contextTarget = opts.target || (Object.keys(hosts).length === 1 ? Object.keys(hosts)[0] : params.target);
      context = OBOL.context.resolve({engagement:eng,target:contextTarget,facts:facts,params:params,locus:'overview'});
      facts = context.facts; params = context.params;
    }
    var pack = OBOL.packs.actions();
    var curEpoch = (OBOL.pack && OBOL.pack.accessEpoch) ? OBOL.pack.accessEpoch(facts) : 'anon';
    var doneIds = OBOL.store.doneIdsForTarget ? OBOL.store.doneIdsForTarget(params.target, facts, eng) : {};

    var focus = (OBOL.profile && eng && eng.profile) ? OBOL.profile.profileFocus(eng.profile) : [];
    var flagsOn = (!OBOL.profile || !OBOL.profile.hasFlags || !eng) ? true : OBOL.profile.hasFlags(eng.profile);
    var ranked = (OBOL.pack.rankActions || OBOL.pack.nextActions)(facts, pack, { doneIds: doneIds, focusPrefixes: focus, noFlags: !flagsOn });
    var frontier = OBOL.phases.frontierIndex(facts);
    var onFlow = [], comingUp = [], reportChecks = [];
    function reportOnly(a) { return !!(OBOL.pack.isReportOnly && OBOL.pack.isReportOnly(a, pack)); }
    // Trap-doctor moves (gated on a pasted-error blocker.* fact, or producing only advice.*) are NOT cards
    // in the rail - their fix surfaces reactively in the field-notes canvas the moment the blocker mints.
    // Keeping them out of the grid is the de-clutter the redesign calls for; real exploit moves that happen
    // to key on a vuln.* fingerprint stay, because running them IS the next attack step.
    function isCanvasDoctor(a) {
      var gates = (a.requires_all || []).concat(a.requires_any || []);
      if (gates.some(function (k) { return /^blocker\./.test(k); })) return true;
      var prod = a.produces || [];
      return prod.length > 0 && prod.every(function (k) { return /^advice\./.test(k); });
    }
    var hasFoot = !!(facts && (facts.has('foothold.windows') || facts.has('foothold.linux') || facts.has('access.shell') || facts.has('foothold.webshell')));
    // A move is actionable NOW only if it has a command you can actually run now: one that is neither
    // settled (already done), gated on a fact you have not earned, nor already tried in the current epoch.
    // A move whose every command still waits on an unearned fact or was already tried in this epoch drops
    // out of Ready Now rather than holding #1 with nothing left to run.
    var activeEng = OBOL.store.active() || {};
    var activeWsTokens = OBOL.workspace ? OBOL.workspace.tokens(activeEng) : {};
    function hasRunnableCommand(a) {
      var cmds = a.commands || []; if (!cmds.length) return true;
      var eng = activeEng;
      var loci = (OBOL.pack && OBOL.pack.moveCommandLoci) ? OBOL.pack.moveCommandLoci(a, facts) : null;
      for (var i = 0; i < cmds.length; i++) {
        var commandFacts = facts.forAction ? facts.forAction(a, cmds[i]) : facts;
        if (!a.eligible(commandFacts)) continue;
        if (!OBOL.pack.commandIsEligible(cmds[i], commandFacts, a)) continue;
        if (OBOL.pack.commandSettled(cmds[i], commandFacts)) continue;
        if (!hasFoot && loci && loci.both && OBOL.pack.commandLocus && OBOL.pack.commandLocus(cmds[i]) === 'onhost') continue;
        var filled = OBOL.command.fillCommand(a, facts, { params: params, profile: eng.profile, workspace: activeWsTokens }, i);
        if (cmdGated(filled)) continue;
        if (cmdWasTriedInEpoch(a, cmds[i], filled, eng, curEpoch, params.target, commandFacts._resolvedContext)) continue;
        return true;
      }
      return false;
    }
    var hasAdSignal = facts.has('ad.dc_candidate') || facts.has('ad.domain_known') || facts.has('ad.base_dn') ||
      facts.has('kerberos.reachable') || facts.has('ldap.reachable') ||
      facts.has('port:88') || facts.has('port:389') || facts.has('port:636') || facts.has('port:3268') ||
      // Downstream AD progress is itself conclusive AD signal: once you hold an attack path, ACL lead, domain
      // control, or DCSync loot, the engagement is unambiguously AD even if the discovery-phase port/domain
      // facts were never logged, so AD-only follow-ons (dcsync, etc.) belong in Ready Now, not Coming Up.
      facts.has('ad.control_paths') || facts.has('ad.acl_lead') || facts.has('ad.attack_paths') ||
      facts.has('ad.domain_control') || facts.has('loot.ntds');
    function isAdOnlyMove(a) {
      if (!a || a.pack_id !== 'ad_2026_09') return false;
      if (a.id === 'rpc-endpoint-abuse') return false;
      if (/^(ad-|kerberoast|asrep-roast|bloodhound-|bloodyad-|dcsync|golden-ticket|silver-ticket|trust-enum|sccm-|wsus-abuse|certifried|adcs-|shadow-credentials|delegation-abuse|gmsa-read|laps-read|adidns-abuse|timeroasting|zerologon-|nopac|ms14-068|kerberos-|azuread-)/.test(a.id)) return true;
      var prod = a.produces || [];
      return prod.length > 0 && prod.every(function (k) { return /^(ad\.|kerberos\.|hash\.asrep|hash\.tgs|hash\.krbtgt|loot\.ntds|persistence\.domain|sccm\.)/.test(k); });
    }
    ranked.forEach(function (a) {
      if (isCanvasDoctor(a)) return;                                       // doctor -> canvas only, never a card
      if (reportOnly(a)) { reportChecks.push(a); return; }                 // writeup check -> own group, never headlines
      if (!hasAdSignal && isAdOnlyMove(a)) { comingUp.push(a); return; }
      if (OBOL.phases.prematurity(a, facts) === 0 && hasRunnableCommand(a)) onFlow.push(a); else comingUp.push(a);
    });
    if (onFlow.length > 1 && OBOL.command && typeof OBOL.command.moveDryTriesInEpoch === 'function') {
      var dryMap = {}, origIdx = {};
      onFlow.forEach(function (a, idx) {
        origIdx[a.id] = idx;
        dryMap[a.id] = OBOL.command.moveDryTriesInEpoch(a, facts, eng, curEpoch, params.target);
      });
      onFlow = onFlow.slice().sort(function (a, b) {
        var da = dryMap[a.id] || 0, db = dryMap[b.id] || 0;
        if (da !== db) return da - db;
        return (origIdx[a.id] || 0) - (origIdx[b.id] || 0);
      });
    }
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
    if (context) {
      function bind(a) { var instance = Object.create(a); instance.contextTarget = context.target; instance.resolvedContext = context; return instance; }
      onFlow = onFlow.map(bind); comingUp = comingUp.map(bind); reportChecks = reportChecks.map(bind);
    }
    return { eng: eng, facts: facts, params: params, context:context, target: opts.target || null, pack: pack, frontier: frontier,
      onFlow: onFlow, comingUp: comingUp, reportChecks: reportChecks, locked: locked,
      lens: lens, hiddenBy: hiddenBy, factCount: factCount, phaseName: phaseName,
      campId: campId, campTrack: campTrack, hiddenByCamp: hiddenByCamp };
  }
  // The authoritative ranking every screen shares, plus the renderers (prep step + full move card) so the
  // per-target panel can show the exact same "Set Up First" steps and cards the coach does.
  OBOL.coach = {
    selectValidation: function () { nsSel = {id:null,idx:0,locus:null}; },
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
  var _dismissedOutcomes = {};
  var _seenOutcomeToast = {};
  var _expandedOutcomes = {};
  var _outcomeToastTimer = 0;

  function outcomeTone(kind) {
    if (kind === 'success') return 'ok';
    if (kind === 'rejected' || kind === 'authorization-denied' || kind === 'environment-error' || kind === 'parser-error') return 'err';
    return 'warn';
  }

  function renderCompactOutcomeWidget(latestOutcome, outcomeId, fallbackTarget) {
    var o = (latestOutcome && latestOutcome.outcome) || {};
    var oKind = o.kind || 'unknown';
    var oStatus = o.status || 'unresolved';
    var tone = outcomeTone(oKind);
    var c = o.context || {};
    var ctxLine = [c.target || fallbackTarget, c.principal, c.service, c.locus].filter(Boolean).join(' / ');
    var obs = o.observed || [];
    var obsCount = obs.length;
    var isExpanded = !!_expandedOutcomes[outcomeId];
    var isFreshToast = !isExpanded && !_seenOutcomeToast[outcomeId] && !!(latestOutcome.at && (Date.now() - latestOutcome.at < 8000));
    var pillTitle = o.title || 'Latest recorded outcome';

    var routing = o.routing || {};
    var forced = routing.mode === 'forced'
      ? ('<div class="ev-hint outcome-routing">Filed to: ' + esc(routing.target)
        + (routing.sourceTargets && routing.sourceTargets.length ? ' (output named: ' + routing.sourceTargets.map(esc).join(', ') + ')' : '') + '</div>')
      : '';
    var diagHtml = '';
    if (o.errorFixes && o.errorFixes.length) {
      diagHtml += '<div class="outcome-triage-list">' + o.errorFixes.map(function (ef) {
        return '<div class="outcome-triage-card outcome-triage-err">'
          + '<div class="ot-head"><span class="ot-badge ot-badge-err">Error Diagnosis</span> <strong>' + esc(ef.title) + '</strong></div>'
          + '<p class="ot-why">' + esc(ef.why) + '</p>'
          + (ef.fixCmd ? '<div class="ot-cmd"><code>' + esc(ef.fixCmd) + '</code><button type="button" class="btn-copy" data-copy="' + U.attr(ef.fixCmd) + '">Copy Fix</button></div>' : '')
          + '</div>';
      }).join('') + '</div>';
    }
    if (o.baselines && o.baselines.length) {
      diagHtml += '<div class="outcome-triage-list">' + o.baselines.map(function (bl) {
        return '<div class="outcome-triage-card outcome-triage-base">'
          + '<div class="ot-head"><span class="ot-badge ot-badge-base">' + esc(bl.verdict || 'Benign Baseline') + '</span> <strong>' + esc(bl.title) + '</strong></div>'
          + '<p class="ot-why">' + esc(bl.detail) + '</p>'
          + '<p class="ot-next"><strong>Next Step:</strong> ' + esc(bl.next) + '</p>'
          + '</div>';
      }).join('') + '</div>';
    }
    var summaryHtml = (!obsCount && o.summary)
      ? ('<p class="coach-outcome-summary">' + esc(o.summary) + '</p>')
      : '';
    var obsHtml = obsCount
      ? ('<ul class="outcome-observed coach-outcome-list">' + obs.map(function (m) {
          return '<li>' + esc(String(m).replace(/^Observed:\s*/i, '')) + '</li>';
        }).join('') + '</ul>')
      : '';
    var credPromptHtml = (OBOL.credbar && OBOL.credbar.prompt)
      ? OBOL.credbar.prompt((o.context && o.context.target) || fallbackTarget)
      : '';

    return '<div class="coach-flash coach-outcome-widget' + (isFreshToast ? ' is-toast' : '') + (isExpanded ? ' is-expanded' : '') + ' outcome-tone-' + esc(tone) + '" data-receipt-id="' + esc(outcomeId) + '">'
      + '<div class="coach-outcome-drawer" id="coach-outcome-drawer">'
      + '<div class="coach-outcome-drawer-head">'
      + '<span class="coach-outcome-kicker">' + esc(ctxLine || 'Latest Paste') + '</span>'
      + '<a href="#/history" class="coach-outcome-loglink">Run Log →</a>'
      + '</div>'
      + '<div class="coach-outcome-body">' + forced + summaryHtml + obsHtml + diagHtml + '</div>'
      + '</div>'
      + (credPromptHtml ? ('<div class="coach-outcome-credbar">' + credPromptHtml + '</div>') : '')
      + '<div class="coach-outcome-pillbar">'
      + '<button type="button" class="coach-outcome-pill" data-outcome="' + esc(oKind) + '" data-outcome-status="' + esc(oStatus) + '" aria-expanded="' + (isExpanded ? 'true' : 'false') + '" aria-controls="coach-outcome-drawer" title="Click to expand or collapse latest outcome details">'
      + '<span class="coach-outcome-dot" aria-hidden="true"></span>'
      + '<span class="coach-outcome-pill-t">' + esc(pillTitle) + '</span>'
      + (obsCount > 0 ? ('<span class="coach-outcome-count">+' + obsCount + '</span>') : '')
      + '<span class="coach-outcome-chev" aria-hidden="true">' + (isExpanded ? '▾' : '▴') + '</span>'
      + '</button>'
      + '<button type="button" class="coach-flash-x" title="Dismiss outcome" aria-label="Dismiss">×</button>'
      + '</div>'
      + '</div>';
  }
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
    if (k === 'credential.available') return 'Recovered credential material' + (who ? (' for ' + who) : '') + ' (authentication untested)';
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
        return { id: ph.id, label: (idx + 1) + '. ' + String(ph.name || '').replace(/^\d+\.\s*/, '') };
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
      var displayLabel = String(step.label || '');
      if (i < activeIdx) {
        cls += ' done';
        stateIcon = '<span class="step-check">' + OBOL.ic('check') + '</span> ';
      } else if (i === activeIdx) {
        cls += ' active';
        stateIcon = '<span class="step-dot">●</span> ';
      } else {
        cls += ' pending';
        stateIcon = '<span class="step-num">' + (i + 1) + '</span> ';
        displayLabel = displayLabel.replace(/^\d+\.\s*/, '');
      }
      html += '<div class="' + cls + '">'
        + '<span class="step-label">' + stateIcon + esc(displayLabel) + '</span>'
        + '</div>';
      if (i < steps.length - 1) {
        html += '<span class="campaign-step-arrow" aria-hidden="true">→</span>';
      }
    });
    html += '</div></div>';
    return html;
  }

  function renderHeroScopeLens(lens, hiddenBy) {
    var isAll = lens === 'all';
    return '<div class="coach-hero-lens" role="group" aria-label="Syllabus scope filter">'
      + '<span class="hero-lens-label">Scope</span>'
      + '<button type="button" class="hero-lens-opt lens-opt' + (!isAll ? ' on' : '') + '" data-lens="oscp+" aria-pressed="' + (!isAll ? 'true' : 'false') + '" title="OSCP / PEN-200 scope (hides only legacy infrastructure CVEs)">OSCP</button>'
      + '<button type="button" class="hero-lens-opt lens-opt' + (isAll ? ' on' : '') + '" data-lens="all" aria-pressed="' + (isAll ? 'true' : 'false') + '" title="Full arsenal including legacy CVEs, SCCM, and WSUS">All</button>'
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
      + '<label class="ctx-pill ctx-target" title="Focus Cockpit on a specific target or view engagement-wide">'
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

  function evaluateCompletionState(eng, activeTarget, facts, flagsOn) {
    if (!flagsOn || !facts || !facts.has) return { complete: false };
    var hasRoot = facts.has('objective.root_flag');
    var hasLocal = facts.has('objective.local_flag') || facts.has('objective.flag');
    if (!hasRoot || !hasLocal) return { complete: false };

    var rootVals = (facts.values && facts.values('objective.root_flag')) || [];
    var localVals = (facts.values && facts.values('objective.local_flag')) || [];
    var genericVals = (facts.values && facts.values('objective.flag')) || [];
    var rootFlag = (rootVals[0] && (rootVals[0].value || rootVals[0].hash || rootVals[0].flag)) || '';
    var localFlag = (localVals[0] && (localVals[0].value || localVals[0].hash || localVals[0].flag))
      || (genericVals[0] && (genericVals[0].value || genericVals[0].hash || genericVals[0].flag)) || '';

    var tgts = (eng && eng.targets) || [];
    var unresolved = [];
    if (tgts.length > 1 && OBOL.store && OBOL.store.factSetForTarget) {
      tgts.forEach(function (t) {
        var ip = t.ip || t.id;
        if (!ip || ip === activeTarget) return;
        var tf = OBOL.store.factSetForTarget(ip);
        var tDone = tf && tf.has && tf.has('objective.root_flag') && (tf.has('objective.local_flag') || tf.has('objective.flag'));
        if (!tDone) unresolved.push(t);
      });
    }
    return {
      complete: true,
      allTargetsComplete: unresolved.length === 0,
      unresolvedTargets: unresolved,
      rootFlag: rootFlag,
      localFlag: localFlag,
      targetLabel: activeTarget || (eng && eng.params && eng.params.target) || (tgts[0] && (tgts[0].ip || tgts[0].id)) || 'this target'
    };
  }

  function renderCompletionBanner(comp, onFlowCount) {
    if (!comp || !comp.complete) return '';
    var flagsHtml = '<div class="ns-complete-flags">';
    if (comp.localFlag) {
      flagsHtml += '<div class="ns-complete-flag-pill">'
        + '<span class="ns-flag-k">user.txt</span>'
        + '<code class="ns-flag-v">' + esc(comp.localFlag) + '</code>'
        + '<button type="button" class="btn-copy ns-flag-copy" data-copy="' + U.attr(comp.localFlag) + '">copy</button>'
        + '</div>';
    }
    if (comp.rootFlag) {
      flagsHtml += '<div class="ns-complete-flag-pill ns-complete-flag-root">'
        + '<span class="ns-flag-k">root.txt</span>'
        + '<code class="ns-flag-v">' + esc(comp.rootFlag) + '</code>'
        + '<button type="button" class="btn-copy ns-flag-copy" data-copy="' + U.attr(comp.rootFlag) + '">copy</button>'
        + '</div>';
    }
    flagsHtml += '</div>';

    if (comp.allTargetsComplete) {
      return '<div class="ns-complete-banner" role="region" aria-label="Objective Complete">'
        + '<div class="ns-complete-head">'
        + '<span class="ns-complete-icon" aria-hidden="true">' + (OBOL.ic ? OBOL.ic('flag') : '') + '</span>'
        + '<div class="ns-complete-titles">'
        + '<div class="ns-complete-kicker">Objective Complete · All Targets Resolved</div>'
        + '<h2 class="ns-complete-h2">Congratulations! All flags have been captured on ' + esc(comp.targetLabel) + '.</h2>'
        + '<p class="ns-complete-p">Your attack chain, credentials, findings, and proof flags are recorded. You can export your exam/lab report now, or expand the optional drawer below if you want to practice post-exploitation and persistence techniques.</p>'
        + '</div>'
        + '</div>'
        + flagsHtml
        + '<div class="ns-complete-actions">'
        + '<a href="#/report" class="btn-primary ns-complete-btn">View &amp; Export Report →</a>'
        + '<a href="#/findings" class="btn-ghost ns-complete-btn">Review Findings</a>'
        + '<a href="#/scoreboard" class="btn-ghost ns-complete-btn">Scoreboard &amp; Flags</a>'
        + '<a href="#/targets" class="btn-ghost ns-complete-btn">Manage Targets</a>'
        + '</div>'
        + '</div>';
    }

    var nextBtns = comp.unresolvedTargets.map(function (t) {
      var ip = t.ip || t.id;
      var label = t.hostname ? (ip + ' (' + t.hostname + ')') : ip;
      return '<button type="button" class="btn-primary btn-target-pill ns-complete-btn" data-tid="' + U.attr(ip) + '">Switch to ' + esc(label) + ' →</button>';
    }).join('');

    return '<div class="ns-complete-banner ns-host-complete-banner" role="region" aria-label="Host Complete">'
      + '<div class="ns-complete-head">'
      + '<span class="ns-complete-icon" aria-hidden="true">' + (OBOL.ic ? OBOL.ic('flag') : '') + '</span>'
      + '<div class="ns-complete-titles">'
      + '<div class="ns-complete-kicker">Host Complete · ' + comp.unresolvedTargets.length + ' Unresolved Target' + (comp.unresolvedTargets.length === 1 ? '' : 's') + ' Remaining</div>'
      + '<h2 class="ns-complete-h2">All flags captured on ' + esc(comp.targetLabel) + '!</h2>'
      + '<p class="ns-complete-p">This host is fully compromised. Switch focus to one of your remaining targets below, or harvest additional credentials and pivot material if needed.</p>'
      + '</div>'
      + '</div>'
      + flagsHtml
      + '<div class="ns-complete-actions">'
      + nextBtns
      + '<a href="#/targets" class="btn-ghost ns-complete-btn">View All Targets</a>'
      + '<a href="#/report" class="btn-ghost ns-complete-btn">Preview Report</a>'
      + '</div>'
      + '</div>';
  }

  var _deckActiveStepId = null;

  function renderHeroOperatorDeck(facts, params, eng) {
    eng = eng || (OBOL.store && OBOL.store.active && OBOL.store.active()) || {};
    var deck = (OBOL.pathChooser && typeof OBOL.pathChooser.buildDeck === 'function')
      ? OBOL.pathChooser.buildDeck(facts, params, eng)
      : null;
    if (!deck) return '';
    var deckOpen = !!(eng && eng.ui && eng.ui.operatorDeckOpen);
    var tabs = deck.tabs || [];
    var savedTabId = (eng && eng.ui && (eng.ui.operatorDeckTab || eng.ui.deckTab)) || '';
    var selTab = (savedTabId && tabs.filter(function (t) { return t.id === savedTabId; })[0])
      || deck.selectedTab
      || tabs[0]
      || null;
    var activeTabId = selTab ? selTab.id : 'flags';
    var lanes = (selTab && selTab.lanes) || [];
    var savedLaneMap = (eng && eng.ui && eng.ui.operatorDeckLane) || {};
    var savedLaneId = selTab ? savedLaneMap[selTab.id] : '';
    var selLane = (savedLaneId && lanes.filter(function (l) { return l.id === savedLaneId; })[0])
      || ((deck.selectedLane && lanes.indexOf(deck.selectedLane) >= 0) ? deck.selectedLane : null)
      || lanes.filter(function (l) { return l.status === 'ready'; })[0]
      || lanes[0]
      || null;

    var credList = (OBOL.credbar && typeof OBOL.credbar.list === 'function')
      ? OBOL.credbar.list(eng)
      : ((OBOL.creds && typeof OBOL.creds.gather === 'function')
          ? OBOL.creds.gather(eng, facts)
          : ((OBOL.context && typeof OBOL.context.credentials === 'function')
              ? OBOL.context.credentials(eng)
              : []));
    var activeCredKey = (OBOL.creds && typeof OBOL.creds.activeKey === 'function')
      ? OBOL.creds.activeKey(eng)
      : ((OBOL.context && typeof OBOL.context.selectedId === 'function')
          ? (OBOL.context.selectedId(eng, (params && params.target) || '') || '')
          : '');
    var hasActiveCred = !!(activeCredKey || (params && (params.username || params.user)));
    var actId = deck.activeIdentity || {};

    // Single inline Identity selector in the top bar (zero extra rows)
    var idSelectHtml = '<label class="hero-op-id-select-wrap' + (hasActiveCred ? (actId.isAdmin ? ' is-admin' : ' is-user') : ' is-anon') + '" title="Switch active identity for Operator Deck commands">'
      + '<span class="hero-op-id-ic">' + OBOL.ic(actId.isAdmin ? 'shield' : 'key') + '</span>'
      + '<select class="hero-op-cred-select" data-deck-cred-select aria-label="Active Identity">'
      + '<option value="none"' + (!hasActiveCred ? ' selected' : '') + '>Null / No Credential</option>'
      + credList.map(function (c) {
          var cid = c.id || (OBOL.creds && OBOL.creds.keyOf ? OBOL.creds.keyOf(c) : (c.user || c.username || ''));
          var cKey = (OBOL.creds && OBOL.creds.keyOf) ? OBOL.creds.keyOf(c) : cid;
          var isOn = (activeCredKey && (cid === activeCredKey || cKey === activeCredKey))
            || (!activeCredKey && hasActiveCred && String(c.user || c.username || '').toLowerCase() === String((params && (params.username || params.user)) || '').toLowerCase());
          var cDom = c.domain ? (c.domain + '\\') : '';
          var cUser = c.user || c.username || 'account';
          var sKind = (c.type === 'NT' || (c.nthash && !c.secret && !c.password)) ? 'NT Hash' : 'Password';
          return '<option value="' + U.attr(cid) + '"' + (isOn ? ' selected' : '') + '>' + esc(cDom + cUser + ' (' + sKind + ')') + '</option>';
        }).join('')
      + '</select>'
      + '</label>';

    // Single unified 5-Tab Strip right inside the 44px bar
    var barTabsHtml = '<div class="hero-op-bar-tabs" role="tablist" aria-label="Operator Deck Categories">'
      + tabs.map(function (tb) {
          var isOn = !!(deckOpen && selTab && selTab.id === tb.id);
          var rc = typeof tb.readyCount === 'number' ? tb.readyCount : 0;
          return '<button type="button" role="tab" class="hero-op-bar-tab tab-theme-' + esc(tb.id) + (isOn ? ' active' : '') + (rc > 0 ? ' has-ready' : '') + '"'
            + ' data-deck-tab="' + esc(tb.id) + '" aria-selected="' + (isOn ? 'true' : 'false') + '" title="' + U.attr(tb.title) + '">'
            + OBOL.ic(tb.icon || 'branch')
            + '<span class="hero-op-bar-tab-t">' + esc(tb.title) + '</span>'
            + '<span class="hero-op-bar-tab-cnt">' + rc + '</span>'
            + '</button>';
        }).join('')
      + '</div>';

    // Left column (.hero-op-lanes) + Right column (.hero-op-steps-pane)
    var lanesHtml = '<div class="hero-op-lanes" role="group" aria-label="Execution Lanes">'
      + lanes.map(function (ln) {
          var isLaneOn = !!(selLane && selLane.id === ln.id);
          var isDone = ln.status === 'done' || ln.done || /^done$/i.test(ln.badge || '');
          var isLocked = ln.status === 'locked';
          var stateCls = isLocked ? 'is-locked' : (isDone ? 'is-done is-ready' : 'is-ready');
          var bIcon = ln.badgeIcon ? OBOL.ic(ln.badgeIcon) : (isLocked ? OBOL.ic('lock') : OBOL.ic('check'));
          return '<button type="button" class="hero-op-lane-card ' + stateCls + (isLaneOn ? ' active' : '') + '"'
            + ' data-deck-lane="' + esc(ln.id) + '" data-deck-tab-id="' + esc(activeTabId) + '"'
            + ' aria-pressed="' + (isLaneOn ? 'true' : 'false') + '">'
            + '<div class="hero-op-lane-top">'
            + '<span class="hero-op-lane-title">' + esc(ln.title || ln.label || ln.id) + '</span>'
            + '<span class="hero-op-lane-badge ' + stateCls + '">' + bIcon + '<span>' + esc(ln.badge || (isLocked ? 'Locked' : 'Ready')) + '</span></span>'
            + '</div>'
            + (ln.sub ? '<div class="hero-op-lane-sub">' + esc(ln.sub) + '</div>' : '')
            + '</button>';
        }).join('')
      + '</div>';

    var deckTargetIp = (OBOL.store && OBOL.store.activeTarget && OBOL.store.activeTarget()) || (params && params.target) || '';
    var paneHtml = '<div class="hero-op-steps-pane">';
    if (selLane) {
      var laneSteps = selLane.steps || [];
      var activeStep = laneSteps.filter(function (s) { return (s.id || String(s.stepNum)) === _deckActiveStepId; })[0]
        || laneSteps.filter(function (s) { return !s.done; })[0]
        || laneSteps[0]
        || null;
      var selDone = selLane.status === 'done' || selLane.done || /^done$/i.test(selLane.badge || '');
      var selLocked = selLane.status === 'locked';
      var selStateCls = selLocked ? 'is-locked' : (selDone ? 'is-done is-ready' : 'is-ready');
      var selBadgeIc = selLane.badgeIcon ? OBOL.ic(selLane.badgeIcon) : (selLocked ? OBOL.ic('lock') : OBOL.ic('check'));

      paneHtml += '<div class="hero-op-pane-head">'
        + '<div class="hero-op-pane-titles">'
        + '<h3 class="hero-op-pane-title">' + esc(selLane.title || selLane.label || '') + '</h3>'
        + '<span class="hero-op-pane-inst">' + (selLocked ? ('Locked (' + esc(selLane.lockReason || 'Prerequisites not yet met') + ') · Previewing command templates') : 'Copy a step (or run steps in sequence) and click Paste Output') + '</span>'
        + '</div>'
        + '<span class="hero-op-lane-badge ' + selStateCls + '">' + selBadgeIc + '<span>' + esc(selLane.badge || (selLocked ? 'Locked' : 'Ready')) + '</span></span>'
        + '</div>';

      if (deck.needsBothFlagsOnHost && activeTabId === 'flags') {
        var flagAlertText = deck.localFlagCapturedRemotely
          ? 'user.txt was grabbed remotely — use "Capture Both User + Root Flags On-Host" for a combined exam proof screenshot'
          : 'Admin access achieved before user.txt was captured on-host — use "Capture Both User + Root Flags On-Host (One Shot)" to grab both flags in a single exam frame';
        paneHtml += '<div class="hero-op-callout is-flag-alert" role="note">'
          + '<span class="hero-op-callout-ic">' + OBOL.ic('flag') + '</span>'
          + '<span><strong>' + flagAlertText + '</strong></span>'
          + '</div>';
      }

      if (selLocked && selLane.lockReason) {
        paneHtml += '<div class="hero-op-callout is-locked-reason" role="note">'
          + '<span class="hero-op-callout-ic">' + OBOL.ic('lock') + '</span>'
          + '<span>' + esc(selLane.lockReason) + '</span>'
          + '</div>';
      }

      paneHtml += '<div class="hero-op-steps">';
      laneSteps.forEach(function (st, sIdx) {
        var stNum = st.stepNum || (sIdx + 1);
        var stId = st.id || ('step-' + stNum);
        var stLabel = st.label || st.title || ('Step ' + stNum);
        var stCmd = st.command || st.filled || '';
        var stNote = st.note || st.sub || '';
        var stLocus = st.locus === 'onhost' ? 'onhost' : 'remote';
        var isStActive = !!(activeStep && (activeStep.id || ('step-' + activeStep.stepNum)) === stId);

        var stStatusHtml = st.done
          ? '<span class="hero-op-step-status is-done">' + OBOL.ic('check') + '<span>Done</span></span>'
          : (selLocked
              ? '<span class="hero-op-step-status is-locked" title="' + U.attr(selLane.lockReason || 'Locked') + '">' + OBOL.ic('lock') + '<span>' + esc(selLane.badge || 'Locked') + '</span></span>'
              : (st.needsPrevStepPaste
                  ? '<span class="hero-op-step-status is-wait">' + OBOL.ic('clip') + '<span>Paste Prev Step First</span></span>'
                  : (st.isEducatedGuess
                      ? '<span class="hero-op-step-status is-guess" title="Educated Guess (Unverified Path) — run Locate step to confirm">' + (OBOL.ic('alert') || '⚠') + '<span>' + esc(st.guessBadge || 'Educated Guess') + '</span></span>'
                      : (st.verifiedPath
                          ? '<span class="hero-op-step-status is-ready is-verified" title="Flag path verified from evidence">' + OBOL.ic('zap') + '<span>Ready · Verified Path</span></span>'
                          : '<span class="hero-op-step-status is-ready">' + OBOL.ic('zap') + '<span>Ready</span></span>'))));

        var stLocusHtml = '<span class="hero-op-step-locus is-' + stLocus + '">'
          + OBOL.ic(stLocus === 'onhost' ? 'host' : 'box')
          + '<span>' + (stLocus === 'onhost' ? 'On Target' : 'From Kali') + '</span>'
          + '</span>';

        var variantsHtml = '';
        if (st.variants && st.variants.length > 1) {
          var vLbl = st.variantLabel || 'Tool:';
          variantsHtml = '<div class="hero-op-variants" role="group" aria-label="Swap variant">'
            + '<span class="hero-op-variants-k">' + esc(vLbl) + '</span>'
            + st.variants.map(function (v) {
                var isVarOn = st.selectedVariantId ? (v.id === st.selectedVariantId) : (v.command === stCmd);
                return '<button type="button" class="hero-op-variant-pill' + (isVarOn ? ' active' : '') + '"'
                  + ' data-deck-variant="' + esc(v.id) + '"'
                  + ' data-lane-id="' + esc(selLane.id) + '"'
                  + ' data-step-id="' + esc(stId) + '"'
                  + ' aria-pressed="' + (isVarOn ? 'true' : 'false') + '">'
                  + esc(v.label) + '</button>';
              }).join('')
            + '</div>';
        }

        var paramGroupsHtml = '';
        if (st.paramGroups && st.paramGroups.length) {
          paramGroupsHtml = st.paramGroups.map(function (pg) {
            return '<div class="hero-op-param-row" role="group" aria-label="' + U.attr(pg.label || pg.key) + '">'
              + '<span class="hero-op-param-k">' + esc(pg.label || pg.key) + '</span>'
              + (pg.options || []).map(function (opt) {
                  var isOptOn = (pg.active === opt.id);
                  var setAttr = opt.setParams ? (' data-deck-param-json="' + U.attr(JSON.stringify(opt.setParams)) + '"') : '';
                  return '<button type="button" class="hero-op-param-pill' + (isOptOn ? ' active' : '') + '"'
                    + ' data-deck-param="' + esc(pg.key) + '"'
                    + ' data-deck-param-val="' + esc(opt.id) + '"'
                    + setAttr
                    + ' aria-pressed="' + (isOptOn ? 'true' : 'false') + '">'
                    + '<span>' + esc(opt.label) + '</span>'
                    + (opt.sub ? '<span class="hero-op-param-pill-sub">· ' + esc(opt.sub) + '</span>' : '')
                    + '</button>';
                }).join('')
              + '</div>';
          }).join('');
        }

        var fillInputsHtml = '';
        if (st.fillInputs && st.fillInputs.length) {
          fillInputsHtml = '<div class="hero-op-fill-row">'
            + st.fillInputs.map(function (fi) {
                return '<label class="hero-op-fill-field">'
                  + '<span class="hero-op-fill-k">' + esc(fi.label || fi.key) + '</span>'
                  + '<input type="text" class="hero-op-fill-input" data-deck-param-input="' + esc(fi.key) + '"'
                  + ' value="' + U.attr(fi.value || '') + '"'
                  + ' placeholder="' + U.attr(fi.placeholder || '') + '"'
                  + ' autocomplete="off" spellcheck="false">'
                  + '</label>';
              }).join('')
            + '</div>';
        }

        var unfilled = (OBOL.command && typeof OBOL.command.unfilledTokens === 'function')
          ? OBOL.command.unfilledTokens(stCmd) : [];
        var fillable = unfilled.filter(function (t) { return !DERIVED_TOKENS[t]; });
        var fillRow = fillable.length
          ? '<div class="cmd-fill-row">' + fillable.map(function (t) {
              return '<label class="cmd-fill-lbl"><span>' + esc(FILL_LABEL[t] || t) + '</span>'
                + '<input class="cmd-fill" data-tok="' + esc(t) + '" placeholder="' + esc(FILL_PH[t] || ('value for ' + t)) + '" autocomplete="off" spellcheck="false"></label>';
            }).join('') + '</div>' : '';

        paneHtml += '<div class="hero-op-step step-n-' + ((stNum - 1) % 3 + 1) + (st.done ? ' is-done' : '') + (selLocked ? ' is-locked' : '') + (isStActive ? ' active' : '') + (st.needsPrevStepPaste ? ' is-wait' : '') + (st.isEducatedGuess ? ' is-guess' : '') + (fillable.length ? ' cmd-fillable' : '') + '"'
          + ' data-deck-step="' + esc(stId) + '"'
          + ' data-step-num="' + esc(String(stNum)) + '"'
          + ' data-step-label="' + U.attr(stLabel) + '"'
          + ' data-cmd="' + U.attr(stCmd) + '"'
          + ' data-locus="' + esc(stLocus) + '"'
          + (fillable.length ? ' data-tmpl="' + U.attr(stCmd) + '"' : '')
          + ' tabindex="0" role="group" aria-label="' + U.attr('Step ' + stNum + ': ' + stLabel) + '">'
          + '<div class="hero-op-step-head">'
          + '<span class="hero-op-step-num">' + stNum + '</span>'
          + '<span class="hero-op-step-label">' + esc(stLabel) + '</span>'
          + variantsHtml
          + stLocusHtml
          + stStatusHtml
          + '</div>'
          + paramGroupsHtml
          + fillInputsHtml
          + '<div class="ns-pc-cmd-row" data-copy="' + U.attr(stCmd) + '">'
          + '<pre class="cmd-run"><code class="cmd-run-code">' + esc(stCmd) + '</code></pre>'
          + '<div class="hero-op-step-actions">'
          + '<button type="button" class="btn-copy" data-copy="' + U.attr(stCmd) + '">' + OBOL.ic('copy') + ' Copy</button>'
          + '<button type="button" class="btn-deck-paste" data-deck-paste-step'
          + ' data-action="' + esc(selLane.actionId || '') + '"'
          + ' data-cmd="' + U.attr(stCmd) + '"'
          + ' data-locus="' + esc(stLocus) + '"'
          + ' data-step-label="' + U.attr('Step ' + stNum + ' · ' + stLabel) + '"'
          + ' data-target-ip="' + esc(deckTargetIp) + '"'
          + ' title="Open Quick-Paste modal for this step">' + OBOL.ic('clip') + ' Paste Output</button>'
          + '</div>'
          + '</div>'
          + fillRow
          + (stNote ? '<div class="hero-op-step-note">' + fmtNote(stNote) + '</div>' : '')
          + '</div>';
      });
      paneHtml += '</div>'; // .hero-op-steps
    }
    paneHtml += '</div>'; // .hero-op-steps-pane

    return '<div class="hero-op-deck-wrap deck-theme-' + esc(activeTabId) + (deckOpen ? ' is-open' : '') + (deck.unlocked ? ' is-unlocked' : ' is-locked-pre') + (deck.needsBothFlagsOnHost ? ' has-flag-alert' : '') + '" id="hero-op-deck" data-deck-active-tab="' + esc(activeTabId) + '">'
      + '<div class="hero-op-bar">'
      + '<div class="hero-op-bar-left">'
      + '<button type="button" class="hero-op-brand-btn" data-deck-toggle aria-expanded="' + (deckOpen ? 'true' : 'false') + '" aria-controls="hero-op-drawer">'
      + '<span class="hero-op-brand-ic">' + OBOL.ic('branch') + '</span>'
      + '<span class="hero-op-brand-title">OPERATOR DECK</span>'
      + '</button>'
      + idSelectHtml
      + '</div>'
      + barTabsHtml
      + '<div class="hero-op-bar-right">'
      + '<button type="button" class="hero-op-toggle-btn" data-deck-toggle aria-expanded="' + (deckOpen ? 'true' : 'false') + '" aria-controls="hero-op-drawer">'
      + (deckOpen ? 'Collapse ▴' : 'Expand ▾')
      + '</button>'
      + '</div>'
      + '</div>'
      + '<div class="hero-op-drawer" id="hero-op-drawer"' + (deckOpen ? '' : ' hidden') + '>'
      + '<div class="hero-op-workspace">'
      + lanesHtml
      + paneHtml
      + '</div>'
      + '</div>'
      + '</div>';
  }

  function render(ctx) {
    var c = computeCoach();
    var eng = c.eng, facts = c.facts, params = c.params, pack = c.pack;
    var onFlow = c.onFlow, comingUp = c.comingUp, reportChecks = c.reportChecks, locked = c.locked;
    var frontier = c.frontier, lens = c.lens, hiddenBy = c.hiddenBy, factCount = c.factCount, phaseName = c.phaseName;
    var flagsOn = (!OBOL.profile || !OBOL.profile.hasFlags || !eng) ? true : OBOL.profile.hasFlags(eng.profile);
    var compState = evaluateCompletionState(eng, c.target, facts, flagsOn);

    var opens = OBOL.pack.opensUpNext ? OBOL.pack.opensUpNext(facts, pack) : [];
    var opensCount = OBOL.pack.opensUpNext ? opens.length : locked.length;
    var html = '<section class="coach ns-coach-wrap">';
    // Retain the latest scoped result across renders and target switches. The recorded outcome,
    // rather than a new-fact count, explains success, negative results, failures, and uncertainty.
    var outcomeTarget = c.target || params.target || '';
    var latestOutcome = (eng.activities || []).find(function (a) { return a && a.outcome && (!outcomeTarget || a.target === outcomeTarget); });
    var outcomeId = latestOutcome ? String(latestOutcome.target || '') + ':' + String(latestOutcome.at || '') : '';
    if (latestOutcome && !_dismissedOutcomes[outcomeId]) {
      html += renderCompactOutcomeWidget(latestOutcome, outcomeId, outcomeTarget);
    }

    // hero
    var targetSelectorHtml = renderHeroTargetSelector(eng, c.target);
    var scopeLensHtml = renderHeroScopeLens(lens, hiddenBy);
    var heroKickerHtml = compState.complete
      ? ('<div class="coach-kicker">Status: <strong>' + (compState.allTargetsComplete ? 'Objective Complete' : 'Host Complete') + '</strong>'
        + '<span class="kicker-sep">·</span>'
        + '<span class="hero-ready-tag"><span class="ready-pulse">●</span> <strong>All Flags Secured</strong></span>'
        + (onFlow.length ? ('<span class="kicker-sep">·</span><span>' + onFlow.length + ' optional move' + (onFlow.length === 1 ? '' : 's') + ' available</span>') : '')
        + '</div>')
      : ('<div class="coach-kicker">Next Move · Frontier: <strong>' + esc(U.titleCase(phaseName)) + '</strong></div>');
    var heroH1 = compState.complete
      ? (compState.allTargetsComplete
          ? ('Objective Complete: ' + esc(compState.targetLabel))
          : ('Host Complete: ' + esc(compState.targetLabel) + ' (' + compState.unresolvedTargets.length + ' target' + (compState.unresolvedTargets.length === 1 ? '' : 's') + ' left)'))
      : (onFlow.length ? esc(onFlow[0].title) : 'Log evidence to unlock moves');
    var heroSub = compState.complete
      ? (compState.allTargetsComplete
          ? 'Both user.txt and root.txt are secured and verified. Export your report, review your findings, or explore optional post-exploitation moves below.'
          : 'All flags are secured on this host. Switch to an unresolved target below to continue the engagement.')
      : (onFlow.length ? esc(U.firstSentence(onFlow[0].hypothesis || '')) : 'Paste tool output on the Evidence route (or add a fact) and the Cockpit ranks your next commands.');

    var mOpen = nsMultiOpen();
    var focusMode = nsFocusMode();
    var wsConfigured = OBOL.workspace.isConfigured(eng);
    var wsPending = wsConfigured && !((eng.ui || {}).wsScaffoldDone) && factCount < 3;
    var pthCalloutHtml = (params && params.nthash && !params.password)
      ? ('<div class="coach-pth-callout"><strong>Pass-the-Hash Active:</strong> Commands for <code>' + esc(params.username || params.user || 'selected account') + '</code> are automatically filled with <code>-H</code> / <code>-hashes</code>.</div>')
      : '';

    var heroWsHtml = '';
    if (wsConfigured && !wsPending) {
      var scaffoldCompact = OBOL.workspace.scaffold(eng);
      var wsRootCompact = OBOL.workspace.tokens(eng).root || '~/ctf';
      heroWsHtml = '<div class="ws-compact">'
        + '<span class="ws-compact-l">' + OBOL.ic('folder') + ' Working directory: <code title="' + U.attr(wsRootCompact) + '">' + esc(wsRootCompact) + '</code></span>'
        + '<button type="button" class="btn-copy ws-compact-copy" data-copy="' + U.attr(scaffoldCompact) + '">' + OBOL.ic('copy') + ' Copy mkdir &amp;&amp; cd</button>'
        + '</div>';
    }
    var heroControlsHtml = '';
    if (onFlow.length && !compState.complete) {
      heroControlsHtml = '<div class="ns-controls" role="group" aria-label="Card display options">';
      if (onFlow.length > 1) {
        heroControlsHtml += '<button type="button" id="ns-multiopen" class="hero-pill-toggle ns-multi-toggle' + (mOpen ? ' on' : '') + '" aria-pressed="' + (mOpen ? 'true' : 'false') + '" title="Keep multiple move cards expanded at the same time">'
          + '<span class="hero-pill-dot" aria-hidden="true"></span><span>Keep Cards Open</span></button>'
          + (mOpen ? '<button type="button" class="ns-collapse-others hero-pill-collapse" data-ns-collapse title="Collapse all open cards back to the active one">Collapse To One</button>' : '');
      }
      heroControlsHtml += '<button type="button" id="ns-focusmode" class="hero-pill-toggle ns-focus-toggle' + (focusMode ? ' on' : '') + '" aria-pressed="' + (focusMode ? 'true' : 'false') + '" title="Show only the lead runnable command on each card">'
        + '<span class="hero-pill-dot" aria-hidden="true"></span><span>Focus Mode</span></button>'
        + '</div>';
    }
    var heroCenterHtml = heroControlsHtml
      ? ('<div class="coach-hero-center hero-utility-row">' + heroControlsHtml + '</div>')
      : '';

    html += '<div class="coach-hero' + (compState.complete ? ' coach-hero-complete' : '') + '">'
      + '<div class="coach-hero-top">'
      + '<div class="coach-hero-top-left">' + heroKickerHtml + targetSelectorHtml + scopeLensHtml + heroWsHtml + '</div>'
      + '</div>'
      + '<div class="coach-hero-body">'
      + '<div class="coach-hero-main">'
      + '<h1 class="coach-h1">' + heroH1 + '</h1>'
      + '<p class="coach-sub">' + heroSub + '</p>'
      + pthCalloutHtml
      + '</div>'
      + heroCenterHtml
      + '<div class="coach-hero-aside">'
      + '<div class="coach-metrics-deck">'
      + '<div class="metric-group metric-group-moves">'
      + '<div class="metric-group-h" title="How many moves your proven facts have unlocked or are 1 step from unlocking">Moves Unlocked &amp; Upcoming</div>'
      + '<div class="coach-metrics">'
      + '<div class="metric metric-ready" title="Unlocked moves ready to run right now"><span class="metric-n">' + onFlow.length + '</span><span class="metric-l">' + (compState.complete ? 'Optional Moves' : 'Moves Ready') + '</span></div>'
      + '<div class="metric metric-coming" title="Unlocked moves queued for a later phase"><span class="metric-n">' + comingUp.length + '</span><span class="metric-l">Coming Up</span></div>'
      + '<div class="metric metric-opens" title="Locked moves that are 1 fact away from unlocking"><span class="metric-n">' + opensCount + '</span><span class="metric-l">Opens Up Next</span></div>'
      + '</div></div>'
      + '<div class="metric-group metric-group-facts">'
      + '<div class="metric-group-h" title="Total facts derived from terminal output pasted into OBOL on this engagement">From Pastes</div>'
      + '<div class="coach-metrics">'
      + '<div class="metric metric-facts" title="Facts derived from terminal output you pasted into OBOL on this engagement"><span class="metric-n">' + factCount + '</span><span class="metric-l">Derived Facts</span></div>'
      + '</div></div>'
      + '</div></div></div>'
      + renderHeroOperatorDeck(facts, params, eng)
      + '</div>';

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

    // one-time workspace scaffold: create the output tree once, then every command below writes
    // into it and tells you which file to attach. Soft-gates the move cards until the operator
    // copies the setup command or explicitly opts out, preventing "No such file or directory" errors.
    if (wsPending) {
      var scaffold = OBOL.workspace.scaffold(eng);
      var wsTokens = OBOL.workspace.tokens(eng);
      var scandir = wsTokens.scandir;
      var wsRoot = wsTokens.root || '~/ctf';
      var stamp = OBOL.workspace.promptStamp ? OBOL.workspace.promptStamp((params || {}).lhost_iface || '') : (OBOL.workspace.PROMPT_STAMP_ZSH || '');
      html += '<div class="ws-banner is-glow">'
        + '<div class="ws-banner-top">'
        + '<span class="ns-suggested">STEP 0 · RUN THIS FIRST</span>'
        + '<span class="ns-chip">KALI WORKSPACE</span>'
        + '<span class="ns-chip ns-chip-tgt">' + esc(wsRoot) + '</span>'
        + '<span class="ws-banner-rank">#0</span>'
        + '</div>'
        + '<div class="ws-banner-h">' + OBOL.ic('folder') + ' Set up your working directory, run this once on your Kali box</div>'
        + '<div class="ws-banner-note ws-banner-sub">Every command below writes directly into relative folders (<code>' + esc(scandir) + '</code>, <code>loot/</code>, <code>exploit/</code>, <code>www/</code>, <code>proof/</code>). Run this once in your Kali terminal before starting so scans do not fail with "No such file or directory".</div>'
        + '<div class="ws-cmd-row ws-copy-unlock" data-copy="' + U.attr(scaffold) + '" title="Click to copy command and unlock moves">'
        + '<pre class="cmd-run"><code>' + esc(scaffold) + '</code></pre>'
        + '<span class="ws-cmd-copy">' + OBOL.ic('copy') + '</span>'
        + '</div>'
        + '<div class="ws-banner-actions">'
        + '<button type="button" class="btn-primary ws-copy-unlock" data-copy="' + U.attr(scaffold) + '">' + OBOL.ic('copy') + ' Copy Command &amp; Unlock Moves</button>'
        + '<button type="button" class="btn-ghost ws-done">I Already Ran This</button>'
        + '<button type="button" class="ws-skip ws-done">Opt Out / Skip Setup</button>'
        + '</div>'
        + (stamp
          ? ('<details class="ws-stamp"><summary>Optional: stamp your prompt with the time + VPN IP <span class="ev-import-tag">Recommended</span></summary>'
            + '<div class="ws-banner-note">Paste this into <code>~/.zshrc</code> once. It prints a dim <code>[UTC time] [tun0:IP]</code> line before each prompt (your prompt is untouched), so later you can paste your <strong>whole session</strong> into Evidence and OBOL orders it correctly and auto-fills your <code>{{lhost}}</code>.</div>'
            + '<pre class="cmd-run"><code>' + esc(stamp) + '</code></pre>'
            + '<div class="ws-banner-actions"><button type="button" class="btn-copy" data-copy="' + U.attr(stamp) + '">Copy Prompt Stamp</button></div>'
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
      nsSel.userLocus = false;
      nsSel.userCmd = false;
      var initTgt = (selMove && selMove.contextTarget) || (params && params.target) || '';
      var initFilled = selMove ? OBOL.command.fillAll(selMove, facts, fillOptsForTarget(eng, params, initTgt)) : [];
      nsSel.locus = selMove ? effectiveLocus(selMove, facts, initFilled, OBOL.pack.defaultCommandLocus(selMove, facts)) : null;
      nsSel.idx = selMove ? firstCmdIndexForLocus(selMove, nsSel.locus, facts, initFilled) : 0;
      if (selMove && isGuidedStepperMove(selMove) && selMove.commands && selMove.commands[nsSel.idx]) {
        nsSel.locus = OBOL.pack.commandLocus(selMove.commands[nsSel.idx]);
      }
    } else {
      var selIsStepper = isGuidedStepperMove(selMove);
      var selCmds = selMove.commands || [];
      var selTargetForFill = selMove.contextTarget || (params && params.target) || '';
      var selFilled = OBOL.command.fillAll(selMove, facts, fillOptsForTarget(eng, params, selTargetForFill));
      if (!nsSel.locus || !nsSel.userLocus) nsSel.locus = OBOL.pack.defaultCommandLocus(selMove, facts);
      if (!nsSel.userLocus) nsSel.locus = effectiveLocus(selMove, facts, selFilled, nsSel.locus);
      // Re-point a stale selection: out of range, OR a command that has since settled (a run-once probe now
      // hidden), OR one still gated on an unearned fact (now hidden), OR one that no longer matches the
      // active locus. Without this the canvas would keep showing a command the card no longer offers, and
      // the selected card would show no active row.
      var selCur = selCmds[nsSel.idx];
      var selEpoch = (OBOL.pack && OBOL.pack.accessEpoch && facts) ? OBOL.pack.accessEpoch(facts) : '';
      var selCmdFacts = (selCur && facts && facts.forAction) ? facts.forAction(selMove, selCur) : facts;
      var selCtx = (selCmdFacts && selCmdFacts._resolvedContext) || selMove.resolvedContext || (facts && facts._resolvedContext);
      var selTgt = selMove.contextTarget || (selCtx && selCtx.target) || (params && params.target) || '';
      var selPinnedIdx = (selIsStepper && eng.ui && eng.ui.seqStepByAction && typeof eng.ui.seqStepByAction[selMove.id] === 'number')
        ? eng.ui.seqStepByAction[selMove.id] : -1;
      var selPinnedSeq = selPinnedIdx >= 0;
      var selCheckFn = (selIsStepper && OBOL.command && OBOL.command.commandRanExactOrSig)
        ? OBOL.command.commandRanExactOrSig
        : OBOL.command.commandWasRun;
      var selWasTried = selCur ? (
        selCheckFn(((selFilled[nsSel.idx] && (selFilled[nsSel.idx].filled || selFilled[nsSel.idx].run)) || ''), eng.activities || [], params, selTgt)
        || cmdWasTriedInEpoch(selMove, selCur, selFilled[nsSel.idx], eng, selEpoch, selTgt, selCtx)
      ) : false;
      if (nsSel.idx >= selCmds.length
        || OBOL.pack.commandSettled(selCur, selCmdFacts)
        || cmdGated(selFilled[nsSel.idx])
        || (!selIsStepper && OBOL.pack.commandLocus(selCur) !== nsSel.locus)
        || (selPinnedSeq && nsSel.idx !== selPinnedIdx)
        || (!nsSel.userCmd && !selPinnedSeq && selWasTried)) {
        nsSel.idx = firstCmdIndexForLocus(selMove, nsSel.locus, facts, selFilled);
      }
      if (selIsStepper && selCmds[nsSel.idx]) {
        nsSel.locus = OBOL.pack.commandLocus(selCmds[nsSel.idx]);
      }
    }
    if (mOpen && nsSel.id) nsOpen[nsSel.id] = true;   // the focused card is always one of the open set
    function cardOpts(a, i, section) {
      var badge = actionTargetLabel(a, facts, eng, c.target);
      var open = mOpen ? (!!nsOpen[a.id] || a.id === nsSel.id) : (a.id === nsSel.id);
      return { rank: section === 'ready' ? (i + 1) : 0, selected: open, suggested: section === 'ready' && i === 0, targetBadge: badge, focusMode: focusMode };
    }

    // Narrow screens are best-effort: the two-column coach + canvas really wants width. Say so plainly
    // (shown only under the single-column breakpoint) and tell a phone user where the field notes land.
    html += '<p class="ns-mobile-note">The Cockpit is designed for a larger screen. On a phone it still works: tap a move to expand its commands, and its full field notes appear lower down.</p>';

    if (wsPending) {
      html += '<div class="ws-gate-notice">'
        + '<span><strong>Moves Locked Until Step 0 Is Acknowledged:</strong> Copy the working-directory command above (or click <em>Opt Out / Skip Setup</em>) to unlock the Cockpit.</span>'
        + '<button type="button" class="btn-ghost ws-done">Skip &amp; Unlock Moves</button>'
        + '</div>';
    }

    html += '<div class="ns-coach' + (wsPending ? ' ws-gated' : '') + '"><div class="ns-main">';

    // Diagnostic Fix Cards for active blocker.* errors
    var coachFixCards = renderCoachFixCards(facts);
    if (coachFixCards) {
      html += coachFixCards;
    }

    if (compState.complete) {
      html += renderCompletionBanner(compState, onFlow.length);
    }

    var READY_CAP = 8;
    if (compState.complete) {
      if (onFlow.length) {
        html += '<details class="ns-section ns-complete-drawer"><summary>Explore Optional Post-Exploitation &amp; Persistence Moves (' + onFlow.length + ')</summary>'
          + '<p class="ns-section-note">All required flags for this target are secured. These optional post-compromise, credential harvesting, and persistence moves remain available if you want to explore further.</p>'
          + '<div class="ns-grid">';
        onFlow.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'ready')); });
        html += '</div></details>';
      }
    } else if (onFlow.length) {
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
      html += '<div class="ns-empty">No ready moves yet. Paste a scan on the Evidence route, or add a target fact, and the Cockpit will rank your next commands here.</div>';
    }

    if (comingUp.length) {
      html += '<details class="ns-section ns-comingup"' + (!compState.complete && comingUp.some(function (a) { return a.id === nsSel.id; }) ? ' open' : '') + '><summary>Coming Up, eligible but ahead of your frontier (' + comingUp.length + ')</summary><div class="ns-grid">';
      comingUp.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'coming')); });
      html += '</div></details>';
    }

    if (reportChecks.length) {
      html += '<details class="ns-section ns-reportchecks"' + (!compState.complete && reportChecks.some(function (a) { return a.id === nsSel.id; }) ? ' open' : '') + '><summary>Report Checks, for the writeup (' + reportChecks.length + ')</summary>'
        + '<p class="ns-section-note">Info-only checks that do not move the box forward (SPF/DMARC, security headers, TLS, CORS). Run them when you are tidying up the report.</p><div class="ns-grid">';
      reportChecks.forEach(function (a, i) { html += nsCard(a, facts, params, cardOpts(a, i, 'report')); });
      html += '</div></details>';
    }

    // the aspirational roadmap of capability-unlocks (contingency doctors/vulns excluded by the engine)
    if (!compState.complete) {
      html += nsOpensStrip(opens);
    }

    html += '</div>'; // .ns-main
    html += '<aside class="ns-canvas" id="ns-canvas" aria-label="Field notes for the selected move" aria-live="polite">'
      + nsCanvasHtml(selMove, nsSel.idx, facts, params) + '</aside>';
    html += '</div>'; // .ns-coach

    html += '</section>';
    return html;
  }

  function mounted(ctx) {
    // The router replaces #view's innerHTML each render but REUSES the #view element, so delegated
    // listeners bound on it would stack on every re-render - the Paste-Output toggle would then fire
    // an even number of times (open->closed = no-op) and ingests would duplicate. Bind on the coach's
    // own container instead: it's recreated on each render, so its listeners die with the old DOM.
    var mount = ctx.mount.querySelector('.coach') || ctx.mount;

    var opensMore = mount.querySelector('.ns-opens-more');
    if (opensMore) {
      opensMore.addEventListener('toggle', function () {
        if (!opensMore.open) return;
        var slot = opensMore.querySelector('[data-opens-deferred="1"]');
        if (slot && _deferredOpensMoreHtml) {
          slot.removeAttribute('data-opens-deferred');
          slot.innerHTML = _deferredOpensMoreHtml;
        }
      });
    }

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
      var targetIp = (OBOL.store.activeTarget && OBOL.store.activeTarget()) || nsSel.target;
      var facts = (targetIp && OBOL.store.factSetForTarget) ? OBOL.store.factSetForTarget(targetIp) : OBOL.store.factSet();
      var params = Object.assign({}, (OBOL.store.active() || {}).params || {});
      if (targetIp) params.target = targetIp;
      var resolved = null;
      if (OBOL.store.resolvedContext) {
        resolved = OBOL.store.resolvedContext({target:targetIp || params.target,facts:facts});
        facts = resolved.facts; params = resolved.params;
      }
      return { facts: facts, pack: OBOL.packs.actions(), params: params, resolved: resolved, targetIp: targetIp || params.target || '' };
    }
    function moveById(pack, id, fx) {
      var found = pack.filter(function (a) { return a.id === id; })[0];
      if (!found || !fx || !fx.resolved) return found;
      var bound = Object.create(found);
      bound.resolvedContext = fx.resolved;
      bound.contextTarget = fx.targetIp || '';
      return bound;
    }
    function hydrateCard(card, move, fx, filled) {
      if (!card.hasAttribute('data-body-deferred')) return;
      var holder = document.createElement('div');
      holder.innerHTML = nsCard(move, fx.facts, fx.params, {selected:true,filled:filled,focusMode:nsFocusMode(),targetBadge:card.getAttribute('data-context-target') || fx.targetIp || ''});
      card.insertBefore(holder.querySelector('.ns-body'), card.querySelector('.ns-foot'));
      card.removeAttribute('data-body-deferred');
    }
    function repaintCanvas() {
      var el = mount.querySelector('#ns-canvas'); if (!el) return;
      var fx = freshCtx(); var m = moveById(fx.pack, nsSel.id, fx);
      el.innerHTML = nsCanvasHtml(m, nsSel.idx, fx.facts, fx.params);
    }
    function selectCard(card) {
      var id = card.getAttribute('data-action'); if (!id) return;
      nsSel.target = card.getAttribute('data-context-target') || null;
      var fx = freshCtx(); var m = moveById(fx.pack, id, fx); if (!m) return;
      if (nsSel.id !== id) _manualPillarMoveId = null;
      nsSel.id = id;
      nsSel.userLocus = false;
      nsSel.userCmd = false;
      var mFilled = OBOL.command.fillAll(m, fx.facts, fillOptsForTarget(OBOL.store.active(), fx.params, fx.targetIp));
      nsSel.locus = effectiveLocus(m, fx.facts, mFilled, OBOL.pack.defaultCommandLocus(m, fx.facts));
      nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus, fx.facts, mFilled);
      if (isGuidedStepperMove(m) && m.commands && m.commands[nsSel.idx]) {
        nsSel.locus = OBOL.pack.commandLocus(m.commands[nsSel.idx]);
      }
      hydrateCard(card, m, fx, mFilled);
      // glow + expand follow the selection
      Array.prototype.forEach.call(mount.querySelectorAll('.ns-card.selected'), function (o) {
        o.classList.remove('selected', 'is-glow', 'ns-bloom'); o.setAttribute('aria-expanded', 'false');
      });
      card.classList.add('selected', 'is-glow'); card.setAttribute('aria-expanded', 'true');
      // one-shot bloom shimmer ONLY on an explicit open - never on toggle/command clicks or re-render
      card.classList.remove('ns-bloom'); void card.offsetWidth; card.classList.add('ns-bloom');
      setTimeout(function () { card.classList.remove('ns-bloom'); }, 3600);
      // apply the move's default locus to its command rows + mark the preferred command active
      syncCardLocus(card, nsSel.locus);
      repaintCanvas();
    }
    function syncCardLocus(card, locus) {
      var pcOpenEl = card.querySelector('.ns-path-chooser:not([hidden])');
      if (pcOpenEl) {
        var activeStepEl = pcOpenEl.querySelector('.ns-pc-step.active') || pcOpenEl.querySelector('.ns-pc-step:not(.done)') || pcOpenEl.querySelector('.ns-pc-step');
        if (activeStepEl) {
          Array.prototype.forEach.call(pcOpenEl.querySelectorAll('.ns-pc-step'), function (s) { s.classList.remove('active'); });
          activeStepEl.classList.add('active');
          nsSel.idx = parseInt(activeStepEl.getAttribute('data-cmd-index'), 10) || 0;
          nsSel.locus = activeStepEl.getAttribute('data-locus') || locus || 'remote';
          var miPc = card.querySelector('.move-ingest');
          if (miPc) miPc.setAttribute('data-cmd', activeStepEl.getAttribute('data-cmd') || '');
          return;
        }
      }
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
        var keep = card.querySelector('.ns-cmd:not([hidden])[data-cmd-index="' + nsSel.idx + '"]');
        var chosenIdx = keep ? nsSel.idx : first;
        nsSel.idx = chosenIdx;
        var active = keep || card.querySelector('.ns-cmd[data-cmd-index="' + chosenIdx + '"]');
        if (active) active.classList.add('active');
        var lead = active;
        var mi = card.querySelector('.move-ingest');
        if (mi && lead) mi.setAttribute('data-cmd', lead.getAttribute('data-cmd') || (lead.querySelector('[data-copy]') && lead.querySelector('[data-copy]').getAttribute('data-copy')) || '');
      }
    }
    // Floating outcome toast -> minimized pill: auto-settle after 3.8s, click pill to expand/collapse, click × to dismiss
    var outcomeWidget = mount.querySelector('.coach-outcome-widget');
    if (outcomeWidget && outcomeWidget.classList.contains('is-toast')) {
      clearTimeout(_outcomeToastTimer);
      var toastRid = outcomeWidget.getAttribute('data-receipt-id') || '';
      _outcomeToastTimer = setTimeout(function () {
        _seenOutcomeToast[toastRid] = true;
        if (outcomeWidget && outcomeWidget.classList) outcomeWidget.classList.remove('is-toast');
      }, 3800);
    }
    U.on(mount, 'click', '.coach-outcome-pill', function (e, t) {
      var fl = t.closest('.coach-outcome-widget');
      if (!fl) return;
      clearTimeout(_outcomeToastTimer);
      var rid = fl.getAttribute('data-receipt-id') || '';
      _seenOutcomeToast[rid] = true;
      var willExpand = !(fl.classList.contains('is-expanded') || fl.classList.contains('is-toast'));
      fl.classList.remove('is-toast');
      fl.classList.toggle('is-expanded', willExpand);
      _expandedOutcomes[rid] = willExpand;
      t.setAttribute('aria-expanded', willExpand ? 'true' : 'false');
      var chev = t.querySelector('.coach-outcome-chev');
      if (chev) chev.textContent = willExpand ? '▾' : '▴';
    });
    U.on(mount, 'click', '.coach-flash-x', function (e, t) {
      clearTimeout(_outcomeToastTimer);
      var fl = t.closest('.coach-flash');
      if (fl) {
        var rid = fl.getAttribute('data-receipt-id') || '';
        _dismissedOutcomes[rid] = true;
        delete _expandedOutcomes[rid];
        if (OBOL.credbar && typeof OBOL.credbar.clearNotice === 'function') OBOL.credbar.clearNotice();
        fl.remove();
      }
    });
    U.on(mount, 'click', '[data-dismiss-cred-notice]', function (e, t) {
      if (OBOL.credbar && typeof OBOL.credbar.clearNotice === 'function') OBOL.credbar.clearNotice();
      var card = t.closest('.credential-next');
      var wrap = t.closest('.coach-outcome-credbar');
      if (card) card.remove();
      if (wrap && !wrap.children.length) wrap.remove();
    });
    // Open the clicked card and make it the focus, WITHOUT closing the other open cards (multi-open mode).
    function openCardKeepOthers(card) {
      var id = card.getAttribute('data-action'); if (!id) return;
      nsSel.target = card.getAttribute('data-context-target') || null;
      var fx = freshCtx(); var m = moveById(fx.pack, id, fx); if (!m) return;
      if (nsSel.id !== id) _manualPillarMoveId = null;
      nsOpen[id] = true; nsSel.id = id; nsSel.userLocus = false; nsSel.userCmd = false;
      var mFilled = OBOL.command.fillAll(m, fx.facts, fillOptsForTarget(OBOL.store.active(), fx.params, fx.targetIp));
      nsSel.locus = effectiveLocus(m, fx.facts, mFilled, OBOL.pack.defaultCommandLocus(m, fx.facts));
      nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus, fx.facts, mFilled);
      if (isGuidedStepperMove(m) && m.commands && m.commands[nsSel.idx]) {
        nsSel.locus = OBOL.pack.commandLocus(m.commands[nsSel.idx]);
      }
      hydrateCard(card, m, fx, mFilled);
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
      if (e.target.closest('.ns-cmd') || e.target.closest('.ns-pc-wrap') || e.target.closest('.ns-toggle') || e.target.closest('button') || e.target.closest('a') || e.target.closest('input') || e.target.closest('textarea') || e.target.closest('summary') || e.target.closest('.ns-chip-lib')) return;
      if (nsMultiOpen()) { if (t.classList.contains('selected')) collapseCard(t); else openCardKeepOthers(t); }
      else if (!t.classList.contains('selected')) selectCard(t);
    });
    U.on(mount, 'keydown', '.ns-card', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, a, input, textarea, summary, .ns-pc-wrap')) {
        e.preventDefault();
        if (nsMultiOpen()) { if (t.classList.contains('selected')) collapseCard(t); else openCardKeepOthers(t); }
        else if (!t.classList.contains('selected')) selectCard(t);
      }
    });
    // multi-open pill toggle + "collapse to one"
    U.on(mount, 'click', '#ns-multiopen', function () {
      var on = !nsMultiOpen();
      if (!on) nsOpen = nsSel.id ? (function () { var o = {}; o[nsSel.id] = true; return o; })() : {};
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.nsMultiOpen = on; }, 'ui');
      OBOL.router.render();
    });
    // focus mode pill toggle
    U.on(mount, 'click', '#ns-focusmode', function () {
      var on = !nsFocusMode();
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.nsFocusMode = on; }, 'ui');
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
      nsSel.userLocus = true;
      var fx = freshCtx(); var m = moveById(fx.pack, card.getAttribute('data-action'), fx);
      if (m) nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus, fx.facts);
      syncCardLocus(card, nsSel.locus);
      repaintCanvas();
    });
    // Hero Operator Deck & Path Chooser interactive handlers
    function refreshHeroOperatorDeck() {
      var curDeckEl = mount.querySelector('#hero-op-deck');
      if (!curDeckEl) {
        OBOL.router.render();
        return;
      }
      var fx = freshCtx();
      var activeEng = OBOL.store.active() || {};
      var html = renderHeroOperatorDeck(fx.facts, fx.params, activeEng);
      if (!html) return;
      var holder = document.createElement('div');
      holder.innerHTML = html;
      var nextDeckEl = holder.firstElementChild;
      if (nextDeckEl && curDeckEl.parentNode) {
        curDeckEl.parentNode.replaceChild(nextDeckEl, curDeckEl);
      }
    }
    function pickDeckStep(stepEl) {
      var deckEl = stepEl.closest('#hero-op-deck'); if (!deckEl) return;
      Array.prototype.forEach.call(deckEl.querySelectorAll('.hero-op-step'), function (x) { x.classList.remove('active'); });
      stepEl.classList.add('active');
      _deckActiveStepId = stepEl.getAttribute('data-deck-step') || null;
      var cmdStr = stepEl.getAttribute('data-cmd') || (stepEl.querySelector('[data-copy]') && stepEl.querySelector('[data-copy]').getAttribute('data-copy')) || '';
      var locStr = stepEl.getAttribute('data-locus') || 'remote';
      var stepLabel = stepEl.getAttribute('data-step-label') || '';
      var stepNum = stepEl.getAttribute('data-step-num') || '';
      var mi = deckEl.querySelector('.hero-op-paste .move-ingest');
      if (mi) {
        mi.setAttribute('data-cmd', cmdStr);
        mi.setAttribute('data-locus', locStr);
      }
      var pasteTargetLbl = deckEl.querySelector('.hero-op-paste-step-target');
      if (pasteTargetLbl && (stepNum || stepLabel)) {
        pasteTargetLbl.textContent = 'Step ' + stepNum + (stepLabel ? ' · ' + stepLabel : '');
      }
    }
    U.on(mount, 'click', '[data-deck-toggle]', function (e) {
      if (e.target && e.target.closest('[data-deck-tab]')) return;
      var curEng = OBOL.store.active() || {};
      var nextOpen = !((curEng.ui || {}).operatorDeckOpen);
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.operatorDeckOpen = nextOpen;
      }, 'ui');
      refreshHeroOperatorDeck();
    });
    U.on(mount, 'keydown', '[data-deck-toggle]', function (e, t) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        t.click();
      }
    });
    U.on(mount, 'click', '[data-deck-tab]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var tabId = t.getAttribute('data-deck-tab');
      if (!tabId) return;
      _deckActiveStepId = null;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        var curTab = eng.ui.operatorDeckTab || 'flags';
        if (eng.ui.operatorDeckOpen && curTab === tabId) {
          eng.ui.operatorDeckOpen = false;
        } else {
          eng.ui.operatorDeckOpen = true;
          eng.ui.operatorDeckTab = tabId;
        }
      }, 'ui');
      refreshHeroOperatorDeck();
    });
    U.on(mount, 'click', '[data-deck-lane]', function (e, t) {
      var laneId = t.getAttribute('data-deck-lane');
      var tabId = t.getAttribute('data-deck-tab-id') || (((OBOL.store.active() || {}).ui || {}).operatorDeckTab) || 'flags';
      if (!laneId) return;
      _deckActiveStepId = null;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.operatorDeckOpen = true;
        eng.ui.operatorDeckTab = tabId;
        eng.ui.operatorDeckLane = eng.ui.operatorDeckLane || {};
        eng.ui.operatorDeckLane[tabId] = laneId;
      }, 'ui');
      refreshHeroOperatorDeck();
    });
    U.on(mount, 'click', '[data-deck-variant]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var variantId = t.getAttribute('data-deck-variant');
      var laneId = t.getAttribute('data-lane-id') || '';
      var stepId = t.getAttribute('data-step-id') || '';
      if (!variantId || !laneId || !stepId) return;
      _deckActiveStepId = stepId;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.deckVariantSel = eng.ui.deckVariantSel || {};
        eng.ui.deckVariantSel[laneId + ':' + stepId] = variantId;
      }, 'ui');
      refreshHeroOperatorDeck();
    });
    function switchDeckCredential(credId) {
      var activeEng = OBOL.store.active() || {};
      if (credId === 'none' || !credId) {
        if (OBOL.credbar && typeof OBOL.credbar.clear === 'function') {
          OBOL.credbar.clear(activeEng);
        } else if (OBOL.credbar && typeof OBOL.credbar.apply === 'function') {
          OBOL.credbar.apply(activeEng, null);
        } else if (OBOL.store && typeof OBOL.store.selectCredential === 'function') {
          OBOL.store.selectCredential(null);
        } else {
          OBOL.store.update(function (eng) {
            eng.params = eng.params || {};
            eng.params.username = '';
            eng.params.user = '';
            eng.params.password = '';
            eng.params.nthash = '';
            eng.params.credentialId = '';
          }, 'params');
        }
        if (OBOL.credbar && OBOL.credbar.render) OBOL.credbar.render();
        if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
        if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
        OBOL.router.render();
        return;
      }
      if (OBOL.credbar && typeof OBOL.credbar.apply === 'function') {
        OBOL.credbar.apply(activeEng, credId);
        if (OBOL.credbar.render) OBOL.credbar.render();
        if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
        if (OBOL.router) OBOL.router.render();
        return;
      }
      var allCreds = (OBOL.credbar && typeof OBOL.credbar.list === 'function')
        ? OBOL.credbar.list(activeEng)
        : ((OBOL.creds && typeof OBOL.creds.gather === 'function') ? OBOL.creds.gather(activeEng) : []);
      var found = allCreds.filter(function (c) {
        var cid = c.id || (OBOL.creds && OBOL.creds.keyOf ? OBOL.creds.keyOf(c) : '');
        var cKey = (OBOL.creds && OBOL.creds.keyOf) ? OBOL.creds.keyOf(c) : '';
        return cid === credId || cKey === credId || String(c.user || c.username || '') === credId;
      })[0];
      if (found && OBOL.creds && typeof OBOL.creds.activate === 'function') {
        OBOL.creds.activate(found);
        return;
      }
      if (OBOL.store && typeof OBOL.store.selectCredential === 'function') {
        try { OBOL.store.selectCredential(credId); } catch (err) {}
        if (OBOL.credbar && OBOL.credbar.render) OBOL.credbar.render();
        if (OBOL.ctxbar && OBOL.ctxbar.render) OBOL.ctxbar.render();
        if (OBOL.router) OBOL.router.render();
      }
    }
    U.on(mount, 'click', '[data-deck-cred]', function (e, t) {
      switchDeckCredential(t.getAttribute('data-deck-cred'));
    });
    U.on(mount, 'change', '[data-deck-cred-select]', function (e, t) {
      switchDeckCredential(t.value);
    });
    U.on(mount, 'click', '[data-open-deck-action]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var actionId = t.getAttribute('data-open-deck-action') || '';
      var mapEntry = (OBOL.pathChooser && OBOL.pathChooser.ACTION_TO_DECK && OBOL.pathChooser.ACTION_TO_DECK[actionId]) || null;
      var tabId = null, laneId = null;
      if (typeof mapEntry === 'string') {
        var parts = mapEntry.split(':');
        tabId = parts[0] || null;
        laneId = parts[1] || null;
      } else if (mapEntry && typeof mapEntry === 'object') {
        tabId = mapEntry.tab || mapEntry.tabId || null;
        laneId = mapEntry.lane || mapEntry.laneId || null;
      }
      if (!tabId && OBOL.pathChooser && typeof OBOL.pathChooser.buildDeck === 'function') {
        var fx = freshCtx();
        var d = OBOL.pathChooser.buildDeck(fx.facts, fx.params, OBOL.store.active() || {});
        if (d && d.tabs) {
          for (var ti = 0; ti < d.tabs.length; ti++) {
            var tb = d.tabs[ti];
            var ln = (tb.lanes || []).filter(function (l) { return l.actionId === actionId || l.id === actionId; })[0];
            if (ln) { tabId = tb.id; laneId = ln.id; break; }
          }
        }
      }
      _deckActiveStepId = null;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.operatorDeckOpen = true;
        if (tabId) eng.ui.operatorDeckTab = tabId;
        if (tabId && laneId) {
          eng.ui.operatorDeckLane = eng.ui.operatorDeckLane || {};
          eng.ui.operatorDeckLane[tabId] = laneId;
        }
      }, 'ui');
      refreshHeroOperatorDeck();
      var deckEl = mount.querySelector('#hero-op-deck');
      if (deckEl && deckEl.scrollIntoView) {
        try { deckEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
        catch (err) { deckEl.scrollIntoView(); }
      }
    });
    U.on(mount, 'click', '[data-deck-param]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var key = t.getAttribute('data-deck-param');
      var val = t.getAttribute('data-deck-param-val');
      var jsonRaw = t.getAttribute('data-deck-param-json');
      if (!key) return;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.deckParams = eng.ui.deckParams || {};
        if (jsonRaw) {
          try {
            var patch = JSON.parse(jsonRaw);
            Object.keys(patch).forEach(function (k) { eng.ui.deckParams[k] = patch[k]; });
          } catch (err) {
            eng.ui.deckParams[key] = val;
          }
        } else {
          eng.ui.deckParams[key] = val;
          if (key === 'smb_share') eng.ui.deckParams.smb_preset = '';
        }
      }, 'ui');
      refreshHeroOperatorDeck();
    });
    U.on(mount, 'input', '[data-deck-param-input]', function (e, t) {
      var key = t.getAttribute('data-deck-param-input');
      if (!key) return;
      var val = t.value || '';
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.deckParams = eng.ui.deckParams || {};
        eng.ui.deckParams[key] = val;
        eng.ui.deckParams.smb_preset = '';
      }, 'ui');
      var stepEl = t.closest('[data-deck-step]');
      if (!stepEl || !OBOL.pathChooser || typeof OBOL.pathChooser.buildDeck !== 'function') return;
      var stepId = stepEl.getAttribute('data-deck-step');
      var fx = freshCtx();
      var engNow = OBOL.store.active() || {};
      var credKey = (engNow.ui && typeof engNow.ui.operatorDeckCredKey === 'string') ? engNow.ui.operatorDeckCredKey : null;
      var deckParams = Object.assign({}, fx.params);
      if (credKey) {
        var cParts = credKey.split('|');
        deckParams.user = cParts[0] || '';
        deckParams.username = cParts[0] || '';
        if (cParts[1]) deckParams.domain = cParts[1];
        if (cParts[2] === 'password' && cParts[3]) {
          deckParams.password = cParts[3];
          deckParams.nthash = '';
          deckParams.dahash = '';
        } else if (cParts[2] === 'nthash' && cParts[3]) {
          deckParams.nthash = cParts[3];
          deckParams.password = '';
        }
      }
      var liveDeck = OBOL.pathChooser.buildDeck(fx.facts, deckParams, engNow);
      var foundStep = null;
      (liveDeck.tabs || []).forEach(function (tb) {
        (tb.lanes || []).forEach(function (ln) {
          (ln.steps || []).forEach(function (st) {
            if (st.id === stepId) foundStep = st;
          });
        });
      });
      if (foundStep) {
        var newCmd = foundStep.command || '';
        stepEl.setAttribute('data-cmd', newCmd);
        var codeEl = stepEl.querySelector('.cmd-run-code');
        if (codeEl) codeEl.textContent = newCmd;
        Array.prototype.forEach.call(stepEl.querySelectorAll('[data-copy]'), function (cp) { cp.setAttribute('data-copy', newCmd); });
        var pasteBtn = stepEl.querySelector('[data-deck-paste-step]');
        if (pasteBtn) pasteBtn.setAttribute('data-cmd', newCmd);
        (foundStep.fillInputs || []).forEach(function (fi) {
          var inp = stepEl.querySelector('[data-deck-param-input="' + fi.key + '"]');
          if (inp && inp !== t) inp.setAttribute('placeholder', fi.placeholder || '');
        });
        Array.prototype.forEach.call(stepEl.querySelectorAll('[data-deck-param="smb_preset"]'), function (b) {
          b.classList.remove('active');
          b.setAttribute('aria-pressed', 'false');
        });
      }
    });
    U.on(mount, 'click', '[data-deck-step]', function (e, t) {
      if (e.target.closest('.cmd-fill') || e.target.closest('.hero-op-fill-input') || e.target.closest('[data-deck-param]') || e.target.closest('[data-deck-variant]') || e.target.closest('[data-deck-paste-step]')) return;
      pickDeckStep(t);
    });
    U.on(mount, 'keydown', '[data-deck-step]', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, input')) {
        e.preventDefault();
        pickDeckStep(t);
      }
    });
    U.on(mount, 'click', '[data-deck-paste-step]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var stepEl = t.closest('[data-deck-step]');
      if (stepEl) pickDeckStep(stepEl);
      var cmd = t.getAttribute('data-cmd') || (stepEl && stepEl.getAttribute('data-cmd')) || '';
      var actionId = t.getAttribute('data-action') || t.getAttribute('data-action-id') || '';
      var locus = t.getAttribute('data-locus') || (stepEl && stepEl.getAttribute('data-locus')) || 'remote';
      var label = t.getAttribute('data-step-label') || 'Operator Deck Step';
      var fx = freshCtx();
      var target = t.getAttribute('data-target-ip') || (fx.params && (fx.params.target || fx.params.dc_ip)) || '';
      if (OBOL.quickpaste && typeof OBOL.quickpaste.open === 'function') {
        OBOL.quickpaste.open({
          command: cmd,
          actionId: actionId,
          locus: locus,
          label: label,
          target: target
        });
      }
    });
    function pickPcStep(stepEl) {
      var card = stepEl.closest('.ns-card'); if (!card) return;
      Array.prototype.forEach.call(card.querySelectorAll('.ns-pc-step'), function (x) { x.classList.remove('active'); });
      stepEl.classList.add('active');
      nsSel.id = card.getAttribute('data-action') || nsSel.id;
      nsSel.idx = parseInt(stepEl.getAttribute('data-cmd-index'), 10) || 0;
      nsSel.locus = stepEl.getAttribute('data-locus') || 'remote';
      var mi = card.querySelector('.move-ingest');
      if (mi) mi.setAttribute('data-cmd', stepEl.getAttribute('data-cmd') || (stepEl.querySelector('[data-copy]') && stepEl.querySelector('[data-copy]').getAttribute('data-copy')) || '');
      repaintCanvas();
    }
    function refreshCardPathChooser(card) {
      if (!card) return;
      var actionId = card.getAttribute('data-action');
      var fx = freshCtx();
      var m = moveById(fx.pack, actionId, fx);
      if (!m || !(OBOL.pathChooser && OBOL.pathChooser.build)) return;
      var activeEng = OBOL.store.active() || {};
      var dirs = OBOL.workspace.tokens(activeEng);
      var filled = OBOL.command.fillAll(m, fx.facts, { params: fx.params, profile: activeEng.profile, workspace: dirs });
      var pc = OBOL.pathChooser.build(m, fx.facts, fx.params, filled, activeEng);
      if (!pc) return;
      var pcOpen = !!(activeEng.ui && activeEng.ui.pathChooserOpen);
      if (pcOpen && pc.selectedLane && pc.selectedLane.steps && pc.selectedLane.steps.length) {
        var nextStep = pc.selectedLane.steps.filter(function (s) { return !s.done; })[0] || pc.selectedLane.steps[0];
        if (nextStep) {
          nsSel.id = actionId;
          nsSel.idx = nextStep.cmdIndex;
          nsSel.locus = nextStep.locus || 'remote';
        }
      }
      var wrap = card.querySelector('.ns-pc-wrap');
      if (wrap) {
        var holder = document.createElement('div');
        holder.innerHTML = renderPathChooserRegion(m, pc, pcOpen, nsSel.idx);
        var nextWrap = holder.firstElementChild;
        if (nextWrap) wrap.parentNode.replaceChild(nextWrap, wrap);
      }
      var tgl = card.querySelector('.ns-toggle');
      var cmds = card.querySelector('.ns-cmds');
      if (pcOpen) {
        if (tgl) tgl.setAttribute('hidden', '');
        if (cmds) cmds.setAttribute('hidden', '');
        var activeStepEl = card.querySelector('.ns-pc-step.active') || card.querySelector('.ns-pc-step');
        var mi = card.querySelector('.move-ingest');
        if (mi && activeStepEl) mi.setAttribute('data-cmd', activeStepEl.getAttribute('data-cmd') || '');
      } else {
        if (tgl) tgl.removeAttribute('hidden');
        if (cmds) cmds.removeAttribute('hidden');
        syncCardLocus(card, nsSel.locus);
      }
      repaintCanvas();
    }
    U.on(mount, 'click', '[data-pc-toggle]', function (e, t) {
      var card = t.closest('.ns-card'); if (!card) return;
      var curEng = OBOL.store.active() || {};
      var nextOpen = !((curEng.ui || {}).pathChooserOpen);
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.pathChooserOpen = nextOpen;
      }, 'ui');
      refreshCardPathChooser(card);
    });
    U.on(mount, 'keydown', '[data-pc-toggle]', function (e, t) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        t.click();
      }
    });
    U.on(mount, 'click', '[data-pc-group]', function (e, t) {
      var card = t.closest('.ns-card'); if (!card) return;
      var actionId = t.getAttribute('data-action') || card.getAttribute('data-action');
      var groupId = t.getAttribute('data-pc-group');
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.pathChooserOpen = true;
        eng.ui.pathChooserSel = eng.ui.pathChooserSel || {};
        eng.ui.pathChooserSel[actionId] = { groupId: groupId, laneId: null };
      }, 'ui');
      refreshCardPathChooser(card);
    });
    U.on(mount, 'click', '[data-pc-lane]', function (e, t) {
      var card = t.closest('.ns-card'); if (!card) return;
      var actionId = t.getAttribute('data-action') || card.getAttribute('data-action');
      var groupId = t.getAttribute('data-pc-group');
      var laneId = t.getAttribute('data-pc-lane');
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.pathChooserOpen = true;
        eng.ui.pathChooserSel = eng.ui.pathChooserSel || {};
        eng.ui.pathChooserSel[actionId] = { groupId: groupId, laneId: laneId };
      }, 'ui');
      refreshCardPathChooser(card);
    });
    U.on(mount, 'click', '.ns-pc-step', function (e, t) {
      if (e.target.closest('.cmd-fill')) return;
      pickPcStep(t);
    });
    U.on(mount, 'keydown', '.ns-pc-step', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, input')) {
        e.preventDefault();
        pickPcStep(t);
      }
    });
    // pick a command row → it drives the canvas field notes (mouse or keyboard)
    function pickCmd(t) {
      var card = t.closest('.ns-card'); if (!card) return;
      Array.prototype.forEach.call(card.querySelectorAll('.ns-cmd'), function (x) { x.classList.remove('active'); });
      t.classList.add('active');
      nsSel.idx = parseInt(t.getAttribute('data-cmd-index'), 10) || 0;
      nsSel.userCmd = true;
      var rowLoc = t.getAttribute('data-locus');
      if (rowLoc) nsSel.locus = rowLoc;
      var lead = t;
      var mi = card.querySelector('.move-ingest');
      if (mi && lead) {
        mi.setAttribute('data-cmd', lead.getAttribute('data-cmd') || (lead.querySelector('[data-copy]') && lead.querySelector('[data-copy]').getAttribute('data-copy')) || '');
        if (rowLoc) mi.setAttribute('data-locus', rowLoc);
      }
      repaintCanvas();
    }
    U.on(mount, 'click', '.ns-cmd', function (e, t) {
      if (e.target.closest('.cmd-fill') || e.target.closest('[data-toggle-socks]')) return;
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
      var deckStep = t.closest('.hero-op-step');
      if (deckStep) pickDeckStep(deckStep);
      var pcStep = t.closest('.ns-pc-step');
      if (pcStep) pickPcStep(pcStep);
      var cmdRow = t.closest('.ns-cmd');
      if (cmdRow) pickCmd(cmdRow);
      var card = t.closest('.ns-card');
      var copiedCmd = t.getAttribute('data-copy') || (t.closest('[data-copy]') && t.closest('[data-copy]').getAttribute('data-copy')) || '';
      if (deckStep && copiedCmd && OBOL.ingest && typeof OBOL.ingest.setLastCopied === 'function') {
        var deckPasteBtn = deckStep.querySelector('[data-deck-paste-step]');
        var deckEl = deckStep.closest('#hero-op-deck');
        var deckIngest = deckEl && deckEl.querySelector('.hero-op-paste .move-ingest');
        var deckGo = deckIngest && deckIngest.querySelector('.mi-go');
        OBOL.ingest.setLastCopied({
          command: copiedCmd,
          actionId: (deckPasteBtn && (deckPasteBtn.getAttribute('data-action') || deckPasteBtn.getAttribute('data-action-id'))) || (deckIngest && deckIngest.getAttribute('data-action')) || '',
          target: (deckPasteBtn && deckPasteBtn.getAttribute('data-target-ip')) || (deckGo && deckGo.getAttribute('data-target-ip')) || '',
          locus: deckStep.getAttribute('data-locus') || 'remote'
        });
      } else if (card && copiedCmd && OBOL.ingest && typeof OBOL.ingest.setLastCopied === 'function') {
        var goBtn = card.querySelector('.mi-go');
        var copyMove = moveById(OBOL.packs.actions(), card.getAttribute('data-action') || '');
        var copyObj = copyMove && copyMove.commands && copyMove.commands[nsSel.idx];
        OBOL.ingest.setLastCopied({
          command: copiedCmd,
          actionId: card.getAttribute('data-action') || '',
          target: (goBtn && goBtn.getAttribute('data-target-ip')) || '',
          locus: nsSel.locus || 'remote', commandObj: copyObj
        });
      }
      U.copy(copiedCmd).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // pivot staging guide: tick a step done (in place, so the open guide and scroll are preserved)
    U.on(mount, 'click', '[data-stage]', function (e, t) {
      var id = t.getAttribute('data-stage'), i = t.getAttribute('data-stage-i'), key = 'obol.stage:' + id + ':' + i;
      var was; try { was = localStorage.getItem(key) === '1'; localStorage.setItem(key, was ? '0' : '1'); } catch (x) { was = false; }
      var on = !was;
      t.setAttribute('aria-checked', on ? 'true' : 'false');
      t.innerHTML = on ? OBOL.ic('check') : '';
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
      var cmd = t.closest('.ns-cmd') || t.closest('.ns-pc-step') || t.closest('.hero-op-step') || t.closest('.cmd'); if (!cmd) return;
      var out = cmd.getAttribute('data-tmpl') || '';
      Array.prototype.forEach.call(cmd.querySelectorAll('.cmd-fill'), function (inp) {
        var val = (inp.value || '').trim();
        if (!val) return;
        var tok = inp.getAttribute('data-tok') || '';
        var ph = '{{' + tok + '}}';
        var pos = out.indexOf(ph);
        if (pos >= 0 && pos > 0 && (out.charAt(pos - 1) === "'" || out.charAt(pos - 1) === '"')) {
          var q = out.charAt(pos - 1);
          var safe = q === "'" ? val.replace(/'/g, "'\\''") : val.replace(/(["\\$`])/g, '\\$1');
          out = out.split(ph).join(safe);
        } else {
          out = out.split(ph).join(val);
        }
      });
      var code = cmd.querySelector('.cmd-run-code') || cmd.querySelector('.cmd-run code'); if (code) code.textContent = out;
      var copy = cmd.querySelector('.btn-copy'); if (copy) copy.setAttribute('data-copy', out);
      var cmdRowWrap = cmd.querySelector('.ns-pc-cmd-row') || cmd.querySelector('.hero-op-cmd-row'); if (cmdRowWrap) cmdRowWrap.setAttribute('data-copy', out);
      var deckPaste = cmd.querySelector('[data-deck-paste-step]'); if (deckPaste) deckPaste.setAttribute('data-cmd', out);
      cmd.setAttribute('data-cmd', out);
      if (cmd.classList.contains('active')) {
        var card = cmd.closest('.ns-card');
        var mi = (card && card.querySelector('.move-ingest')) || (cmd.closest('#hero-op-deck') && cmd.closest('#hero-op-deck').querySelector('.hero-op-paste .move-ingest'));
        if (mi) mi.setAttribute('data-cmd', out);
      }
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
      _manualPillarMoveId = nsSel.id;
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

    // Pillar 6: Sequence micro-stepper, SOCKS unwrap toggle, HTML form picker, and CLI/Burp mode switcher
    function setSequenceStep(actionId, stepIdx) {
      if (!actionId || isNaN(stepIdx)) return;
      nsSel.id = actionId;
      nsSel.idx = stepIdx;
      nsSel.userCmd = true;
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.seqStepByAction = eng.ui.seqStepByAction || {};
        eng.ui.seqStepByAction[actionId] = stepIdx;
      }, 'ui');
      OBOL.router.render();
    }
    U.on(mount, 'click', '[data-seq-next]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      setSequenceStep(t.getAttribute('data-action') || nsSel.id, parseInt(t.getAttribute('data-seq-next'), 10));
    });
    U.on(mount, 'click', '[data-seq-goto]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      setSequenceStep(t.getAttribute('data-action') || nsSel.id, parseInt(t.getAttribute('data-seq-goto'), 10));
    });
    U.on(mount, 'click', '[data-toggle-socks]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var tIp = t.getAttribute('data-toggle-socks') || (((OBOL.store.active() || {}).params || {}).target) || 'default';
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.unwrapSocksByTarget = eng.ui.unwrapSocksByTarget || {};
        eng.ui.unwrapSocksByTarget[tIp] = !eng.ui.unwrapSocksByTarget[tIp];
      }, 'ui');
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-select-form]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var formIdx = parseInt(t.getAttribute('data-select-form'), 10) || 0;
      var tIp = t.getAttribute('data-target-ip') || (((OBOL.store.active() || {}).params || {}).target) || 'default';
      OBOL.store.update(function (eng) {
        eng.ui = eng.ui || {};
        eng.ui.selectedFormByTarget = eng.ui.selectedFormByTarget || {};
        eng.ui.selectedFormByTarget[tIp] = formIdx;
      }, 'ui');
      OBOL.router.render();
    });
    U.on(mount, 'click', '[data-web-mode]', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var mode = t.getAttribute('data-web-mode') || 'cli';
      var actId = t.getAttribute('data-action') || nsSel.id || '';
      if (actId) {
        nsSel.id = actId;
        _manualPillarMoveId = actId;
        OBOL.store.update(function (eng) {
          eng.ui = eng.ui || {};
          eng.ui.burpModeByAction = eng.ui.burpModeByAction || {};
          eng.ui.burpModeByAction[actId] = mode;
        }, 'ui');
      }
      try { sessionStorage.setItem('obol.pillar-tab', mode === 'burp' ? 'burp' : 'p1'); } catch (_e) {}
      OBOL.router.render();
    });
    if (OBOL.burpCopilot && typeof OBOL.burpCopilot.bindEvents === 'function') {
      OBOL.burpCopilot.bindEvents(mount, {
        onRepaint: function () { repaintCanvas(); },
        onIngested: function () { OBOL.router.render(); },
        onVerifiedWin: function () { OBOL.router.render(); }
      });
    }
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
        OBOL.store.retractFactKind(k, t.getAttribute('data-fact-scope'));
        U.toast('Diagnostic resolved');
        OBOL.router.render();
      }
    });
    // mark done
    U.on(mount, 'click', '.btn-done', function (e, t) {
      var id = t.getAttribute('data-action');
      OBOL.store.setChecklist(id, 'done');
      U.toast('Marked done, recomputing');
      OBOL.router.render();
    });
    // copy working-directory setup command + unlock moves in one click
    U.on(mount, 'click', '.ws-copy-unlock', function (e, t) {
      var cmd = t.getAttribute('data-copy') || '';
      U.copy(cmd).then(function (ok) {
        OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.wsScaffoldDone = true; }, 'ui');
        U.toast(ok ? 'Working directory command copied - moves unlocked!' : 'Moves unlocked', ok ? '' : 'err');
        OBOL.router.render();
      });
    });
    // dismiss / opt out of the workspace scaffold banner
    U.on(mount, 'click', '.ws-done', function () {
      OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.wsScaffoldDone = true; }, 'ui');
      U.toast('Moves unlocked');
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
    // paste-back: toggle this move's inline ingestion box (no route jump - ingest right here)
    U.on(mount, 'click', '.btn-pasteback', function (e, t) {
      var art = t.closest('.ns-card') || t.closest('.move'); if (!art) return;
      var box = art.querySelector('.move-ingest'); if (!box) return;
      var open = box.hasAttribute('hidden');
      if (open) { box.removeAttribute('hidden'); } else { box.setAttribute('hidden', ''); }
      t.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { var ta = box.querySelector('.mi-text'); if (ta) ta.focus(); }
    });
  function extractToolName(cmd) {
    if (OBOL.ingest && (OBOL.ingest.extractTool || OBOL.ingest.extractToolName)) {
      return (OBOL.ingest.extractTool || OBOL.ingest.extractToolName)(cmd);
    }
    if (!cmd) return '';
    var toks = String(cmd).trim().split(/\s+/);
    var i = 0;
    while (i < toks.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i])) i++;
    if (i >= toks.length) return '';
    var first = toks[i].split('/').pop().toLowerCase().replace(/\.(py|exe)$/, '');
    if (first === 'sudo') {
      i++;
      while (i < toks.length) {
        var t = toks[i];
        if (t === '-l' || t === '--list') return 'sudo';
        if (t === '-u' || t === '-g' || t === '-U' || t === '-h') { i += 2; continue; }
        if (/^-[a-zA-Z]/.test(t)) { i++; continue; }
        return t.split('/').pop().toLowerCase().replace(/\.(py|exe)$/, '');
      }
      return 'sudo';
    }
    return first;
  }

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
      var tIp = t.getAttribute('data-target-ip') || '';
      var inputMove = moveById(OBOL.packs.actions(), box.getAttribute('data-action') || '');
      var inputObj = inputMove && inputMove.id === nsSel.id && inputMove.commands && inputMove.commands[nsSel.idx];
      var r = OBOL.ingest.run({ text: text, command: box.getAttribute('data-cmd') || '',
        actionId: box.getAttribute('data-action') || '', source: 'paste',
        scope: tIp ? ('host:' + tIp) : undefined, locus: box.getAttribute('data-locus') || nsSel.locus || 'remote', commandObj: inputObj || undefined });
      if (!r.ok) { if (out) out.textContent = r.reason === 'parsers' ? 'Parsers still loading, try again.' : 'Nothing to parse.'; t.disabled = false; return; }
      if (r.arsenal && r.arsenal.ok && !r.added) {
        U.toast('Loadout stocked ' + r.arsenal.present + ' tools, ' + r.arsenal.staged + ' staged');
        OBOL.router.render();
        return;
      }
      if (r.workspaceSync && r.workspaceSync.ok && !r.added) {
        U.toast(r.workspaceSync.confirmed + ' confirmed · ' + r.workspaceSync.adopted + ' new file' + (r.workspaceSync.adopted === 1 ? '' : 's') + ' adopted');
        OBOL.router.render();
        return;
      }
      if (r.targetsImported && r.targetsImported.ok) {
        U.toast((r.targetsImported.added || 0) + ' target' + (r.targetsImported.added === 1 ? '' : 's') + ' imported');
        OBOL.router.render();
        return;
      }
      // Ingestion owns outcome semantics. Keep unknown, partial, and environment failures
      // available rather than retiring a move from a zero-fact or generic error heuristic.
      var pastedActId = box.getAttribute('data-action') || '';
      nsSel.userCmd = false;
      if (pastedActId) {
        OBOL.store.update(function (eng) {
          if (eng.ui && eng.ui.seqStepByAction) delete eng.ui.seqStepByAction[pastedActId];
        }, 'ui');
      }
      _pasteFlash = { outcome: r.outcome, target: tIp || ((OBOL.store.active() || {}).params || {}).target || '' };
      U.toast(OBOL.ingest.outcomeMessage(r));
      t.disabled = false;
      OBOL.router.render();
      });
    });
    U.on(mount, 'click', '.mi-empty', function (e, t) {
      var box = t.closest('.move-ingest'); if (!box) return;
      var out = box.querySelector('.mi-result');
      if (out) out.textContent = 'Recording…';
      t.disabled = true;
      OBOL.ingest.ensureParsers().then(function (okp) {
        if (!okp) { if (out) out.textContent = 'Parsers still loading, try again.'; t.disabled = false; return; }
        var tIp = t.getAttribute('data-target-ip') || '';
        var inputMove = moveById(OBOL.packs.actions(), box.getAttribute('data-action') || '');
        var inputObj = inputMove && inputMove.id === nsSel.id && inputMove.commands && inputMove.commands[nsSel.idx];
        var r = OBOL.ingest.run({ text: '[OBOL: completed with no output / nothing found]', command: box.getAttribute('data-cmd') || '',
          actionId: box.getAttribute('data-action') || '', source: 'paste',
          scope: tIp ? ('host:' + tIp) : undefined, locus: box.getAttribute('data-locus') || nsSel.locus || 'remote', commandObj: inputObj || undefined });
        var emptyActId = box.getAttribute('data-action') || '';
        nsSel.userCmd = false;
        if (emptyActId) {
          OBOL.store.update(function (eng) {
            if (eng.ui && eng.ui.seqStepByAction) delete eng.ui.seqStepByAction[emptyActId];
          }, 'ui');
        }
        _pasteFlash = { outcome: r.outcome, target: tIp || ((OBOL.store.active() || {}).params || {}).target || '' };
        U.toast(OBOL.ingest.outcomeMessage(r));
        t.disabled = false;
        OBOL.router.render();
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.path = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
