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
    target: 1, domain: 1, basedn: 1, dc: 1, user: 1, password: 1, nthash: 1, lhost: 1,
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
  // the browser stand-in for obol-local materializing loot/users.txt on disk: obol can't write the
  // operator's box, so it gives them the one command that does, with the names it already parsed.
  function prepStep(tag, variant, cmd, note) {
    return '<div class="cmd cmd-prep">'
      + '<div class="cmd-head"><span class="cmd-tag">' + esc(tag) + '</span>'
      + '<span class="cmd-variant">' + esc(variant) + '</span>'
      + '<button class="btn-copy" data-copy="' + U.attr(cmd) + '" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code>' + esc(cmd) + '</code></pre>'
      + (note ? '<div class="cmd-note">' + esc(note) + '</div>' : '') + '</div>';
  }

  function prepBlock(action, facts, dirs) {
    if (!OBOL.loot) return '';
    var steps = '';
    // {{userlist}} — the move reads it and obol has proven users to write into it.
    if (OBOL.loot.actionUsesToken(action, 'userlist')) {
      var users = OBOL.loot.usernames(facts);
      var ulCmd = OBOL.loot.userlistCommand(facts, dirs);
      if (users.length && ulCmd) {
        steps += prepStep('write', 'creates ' + OBOL.loot.userlistPath(dirs),
          ulCmd, 'Run once, the ' + users.length + ' users obol proved, written where every command below reads them.');
      }
    }
    // {{hashfile}} as an INPUT (a crack move) — obol holds the roasted hashes as facts but no file
    // was written (a stdout roast), so give the operator the line that lays them down for cracking.
    var reqs = [].concat(action.requires_all || []);
    var cracksHashes = reqs.some(function (r) { return /^hash\./.test(r); });
    if (cracksHashes && OBOL.loot.actionUsesToken(action, 'hashfile')) {
      var hfCmd = OBOL.loot.hashfileCommand(facts, action, dirs);
      if (hfCmd) {
        steps += prepStep('write', 'creates ' + OBOL.loot.hashfilePath(dirs, action),
          hfCmd, 'Lay the roasted hashes obol captured into the file the crack reads.');
      }
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
  var NS_INFRA = { 'target.configured': 1, 'host.up': 1, 'ports.open': 1, 'scan.nmap.quick': 1 };

  function firstCmdIndexForLocus(move, locus) {
    var cs = (move && move.commands) || [];
    for (var i = 0; i < cs.length; i++) if (OBOL.pack.commandLocus(cs[i]) === locus) return i;
    return 0;
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
  function nsCommandRows(action, filled, selLocus, selIdx, spansBoth) {
    var eng = OBOL.store.active() || {}, acts = eng.activities || [], params = eng.params || {};
    return (action.commands || []).map(function (cmdObj, i) {
      var v = filled[i] || {};
      var locus = OBOL.pack.commandLocus(cmdObj);
      var hidden = spansBoth && locus !== selLocus;
      var ran = OBOL.command.commandWasRun(v.run || v.filled, acts, params);
      var unfilled = OBOL.command.unfilledTokens(v.filled || '');
      var derived = unfilled.filter(function (t) { return DERIVED_TOKENS[t]; });
      var fillable = unfilled.filter(function (t) { return !DERIVED_TOKENS[t]; });
      var warn = derived.length
        ? '<div class="cmd-needs">Needs: ' + derived.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(', ') + '</div>' : '';
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
        + fillRow + warn + missingToolHint(action, v) + '</div>';
    }).join('');
  }

  // One ranked card. opts: { rank, selected, suggested }. The expanded body is always in the DOM (shown via
  // CSS when .selected) so the delegated fill / paste-back / copy listeners work without a re-render.
  function nsCard(action, facts, params, opts) {
    opts = opts || {};
    var famClass = ' ns-ph-' + OBOL.phases.phaseOfAction(action);
    var dirs = OBOL.workspace.tokens(OBOL.store.active());
    var filled = OBOL.command.fillAll(action, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: dirs });
    var loci = OBOL.pack.moveCommandLoci(action);
    var selLocus = opts.selected ? (nsSel.locus || OBOL.pack.defaultCommandLocus(action)) : OBOL.pack.defaultCommandLocus(action);
    var selIdx = opts.selected ? nsSel.idx : firstCmdIndexForLocus(action, selLocus);
    var nCmd = (action.commands || []).length;
    var toggle = loci.both
      ? '<div class="ns-toggle" role="group" aria-label="Where to run this">'
        + '<button type="button" data-locus="remote" class="' + (selLocus === 'remote' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'remote') + '">Remote</button>'
        + '<button type="button" data-locus="onhost" class="' + (selLocus === 'onhost' ? 'on' : '') + '" aria-pressed="' + (selLocus === 'onhost') + '">On-Host</button>'
        + '</div>' : '';
    var body = '<div class="ns-body">'
      + toggle
      + prepBlock(action, facts, dirs)
      + '<div class="ns-cmds">' + nsCommandRows(action, filled, selLocus, selIdx, loci.both) + '</div>'
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
    Object.keys(docs).forEach(function (k) { if (facts.has(k)) out.push(docs[k]); });
    return out;
  }
  function nsDoctorBlock(d) {
    return '<div class="ns-doctor"><div class="ns-doctor-h">' + OBOL.ic('shield') + ' ' + esc(d.title) + '</div>'
      + '<p>' + esc(d.body) + '</p>' + (d.code ? '<pre class="ns-doctor-code"><code>' + esc(d.code) + '</code></pre>'
        + '<div class="ns-doctor-actions"><button class="btn-copy" data-copy="' + U.attr(d.code) + '">Copy Fix</button></div>' : '') + '</div>';
  }
  function nsCanvasHtml(move, idx, facts, params) {
    if (!move) return '<div class="ns-canvas-head"><span class="ns-canvas-kick">Field Notes</span></div>'
      + '<div class="ns-canvas-empty">Pick a move on the left to see how to land it, step by step.</div>';
    var filled = OBOL.command.fillAll(move, facts, { params: params, profile: (OBOL.store.active() || {}).profile, workspace: OBOL.workspace.tokens(OBOL.store.active()) });
    var cmdText = (filled[idx] && filled[idx].filled) || '';
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, idx) : null;
    var live = nsLiveDoctors(facts);
    var html = '<div class="ns-canvas-head"><span class="ns-canvas-kick">Field Notes</span>'
      + '<span class="ns-canvas-move" title="' + U.attr(move.title) + '">' + esc(move.title) + '</span></div>'
      + '<div class="ns-canvas-body">';
    live.forEach(function (d) { html += nsDoctorBlock(d); });
    if (cmdText) html += '<div class="ns-canvas-cmd">' + esc(cmdText) + '</div>';
    if (note) {
      if (note.land && note.land.length) html += '<p class="ns-cn-h">How To Land It</p><ul class="ns-cn-list">'
        + note.land.map(function (l) { return '<li>' + l + '</li>'; }).join('') + '</ul>';
      if (note.win) html += '<div class="ns-cn-win"><span class="ns-tick" aria-hidden="true">✓</span><span>' + esc(note.win) + '</span></div>';
      if (note.mistakes && note.mistakes.length) html += '<p class="ns-cn-h">Common Mistakes</p><ul class="ns-cn-list warn">'
        + note.mistakes.map(function (l) { return '<li>' + esc(l) + '</li>'; }).join('') + '</ul>';
      if (note.doctor) html += nsDoctorBlock(note.doctor);
    }
    html += stagingGuide(move, params);
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
  function computeCoach() { return rankFor(OBOL.store.factSet()); }
  // rankFor(facts) is computeCoach generalized to ANY factset — the engagement-wide one for this coach and
  // the Hub anchor, or a single host's (factSetForTarget) for the per-target "Next Steps for this box"
  // panel — so every surface ranks moves the same way and shows the same prep steps. Report-only writeup
  // checks are split out; the frontier/phase are computed from the passed facts (correct per scope).
  function rankFor(facts) {
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
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
    ranked.forEach(function (a) {
      if (isCanvasDoctor(a)) return;                                       // doctor → canvas only, never a card
      if (reportOnly(a)) { reportChecks.push(a); return; }                 // writeup check → own group, never headlines
      if (OBOL.phases.prematurity(a, facts) === 0) onFlow.push(a); else comingUp.push(a);
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

    var factCount = Object.keys(facts.kinds()).length;
    var phaseName = OBOL.phases.PHASES[frontier] || 'recon';
    return { eng: eng, facts: facts, params: params, pack: pack, frontier: frontier,
      onFlow: onFlow, comingUp: comingUp, reportChecks: reportChecks, locked: locked,
      lens: lens, hiddenBy: hiddenBy, factCount: factCount, phaseName: phaseName };
  }
  // The authoritative ranking every screen shares, plus the renderers (prep step + full move card) so the
  // per-target panel can show the exact same "Set Up First" steps and cards the coach does.
  OBOL.coach = {
    compute: computeCoach,
    rankFor: rankFor,
    topMove: function () { return computeCoach().onFlow[0] || null; },
    topMoveFor: function (facts) { return rankFor(facts).onFlow[0] || null; },
    prepBlock: prepBlock,
  };

  function render(ctx) {
    var c = computeCoach();
    var eng = c.eng, facts = c.facts, params = c.params, pack = c.pack;
    var onFlow = c.onFlow, comingUp = c.comingUp, reportChecks = c.reportChecks, locked = c.locked;
    var frontier = c.frontier, lens = c.lens, hiddenBy = c.hiddenBy, factCount = c.factCount, phaseName = c.phaseName;

    var opensCount = OBOL.pack.opensUpNext ? OBOL.pack.opensUpNext(facts, pack).length : locked.length;
    var html = '<section class="coach ns-coach-wrap">';
    // hero
    html += '<div class="coach-hero">'
      + '<div class="coach-hero-main">'
      + '<div class="coach-kicker">Next Move · Frontier: <strong>' + esc(U.titleCase(phaseName)) + '</strong></div>'
      + '<h1 class="coach-h1">' + (onFlow.length ? esc(onFlow[0].title) : 'Log evidence to unlock moves') + '</h1>'
      + '<p class="coach-sub">' + (onFlow.length ? esc(U.firstSentence(onFlow[0].hypothesis || '')) : 'Paste tool output on the Evidence route (or add a fact) and the coach ranks your next commands.') + '</p>'
      + '</div>'
      + '<div class="coach-metrics">'
      + '<div class="metric"><span class="metric-n">' + onFlow.length + '</span><span class="metric-l">Ready</span></div>'
      + '<div class="metric"><span class="metric-n">' + comingUp.length + '</span><span class="metric-l">Coming Up</span></div>'
      + '<div class="metric"><span class="metric-n">' + opensCount + '</span><span class="metric-l">Opens Up Next</span></div>'
      + '<div class="metric"><span class="metric-n">' + factCount + '</span><span class="metric-l">Facts</span></div>'
      + '</div></div>';

    html += arsenalStrip();
    html += defenseAdvisory(facts);

    // Scope lens control: a newcomer-safe syllabus filter. OSCP (core only) · OSCP+ (adds modern AD) ·
    // All (the full arsenal, edge CVEs included). The hidden-count hint keeps it honest.
    html += '<div class="coach-lens" role="group" aria-label="Syllabus scope filter">'
      + '<span class="coach-lens-label">Scope</span>'
      + ['oscp', 'oscp+', 'all'].map(function (v) {
          var txt = v === 'oscp' ? 'OSCP' : (v === 'oscp+' ? 'OSCP+' : 'All');
          return '<button type="button" class="lens-opt' + (lens === v ? ' on' : '') + '" data-lens="' + v + '"'
            + ' aria-pressed="' + (lens === v ? 'true' : 'false') + '">' + txt + '</button>';
        }).join('')
      + (hiddenBy ? '<span class="coach-lens-hint">' + hiddenBy + ' move' + (hiddenBy === 1 ? '' : 's') + ' above this level, tap <strong>All</strong> to show</span>' : '')
      + '</div>';

    // Planned route to the objective: the planner's lowest-cost dependable path from what's proven to
    // the goal. Re-planned on every render as evidence accrues. A plausible route, not a promise — the
    // box decides which steps actually land; this sharpens as you capture more.
    var route = OBOL.pack.planPath ? OBOL.pack.planPath(facts, pack, {}) : null;
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
      nsSel.idx = selMove ? firstCmdIndexForLocus(selMove, nsSel.locus) : 0;
    } else {
      if (!nsSel.locus) nsSel.locus = OBOL.pack.defaultCommandLocus(selMove);
      if (nsSel.idx >= (selMove.commands || []).length) nsSel.idx = firstCmdIndexForLocus(selMove, nsSel.locus);
    }
    function cardOpts(a, i, section) {
      return { rank: section === 'ready' ? (i + 1) : 0, selected: a.id === nsSel.id, suggested: section === 'ready' && i === 0 };
    }

    html += '<div class="ns-coach"><div class="ns-main">';

    // If a pasted error minted a wall, say so at the top of the column (visible on every screen size,
    // including mobile where the canvas sits below) and point to the fix in Field Notes.
    var liveDocs = nsLiveDoctors(facts);
    if (liveDocs.length) {
      html += '<div class="ns-wall" role="alert">' + OBOL.ic('shield')
        + '<span>A wall was detected: <strong>' + esc(liveDocs.map(function (d) { return d.title; }).join(', '))
        + '</strong>. The fix is in <a href="#ns-canvas">Field Notes</a>.</span></div>';
    }

    var READY_CAP = 8;
    if (onFlow.length) {
      var top = onFlow.slice(0, READY_CAP), rest = onFlow.slice(READY_CAP);
      html += '<div class="ns-railhead"><h2>Ready Now</h2><span class="ns-count">' + onFlow.length + ' move' + (onFlow.length === 1 ? '' : 's') + '</span></div>';
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
      nsSel.idx = firstCmdIndexForLocus(m, nsSel.locus);
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
    // click a card (but not an interactive control inside it) to open it
    U.on(mount, 'click', '.ns-card', function (e, t) {
      if (e.target.closest('.ns-cmd') || e.target.closest('.ns-toggle') || e.target.closest('button') || e.target.closest('a') || e.target.closest('input') || e.target.closest('textarea')) return;
      if (!t.classList.contains('selected')) selectCard(t);
    });
    U.on(mount, 'keydown', '.ns-card', function (e, t) {
      if ((e.key === 'Enter' || e.key === ' ') && !e.target.closest('button, a, input, textarea')) { e.preventDefault(); if (!t.classList.contains('selected')) selectCard(t); }
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
    // scope lens: persist the choice and re-render the coach at the new syllabus level
    U.on(mount, 'click', '.lens-opt', function (e, t) {
      var v = t.getAttribute('data-lens'); if (!v) return;
      lensSet(v);
      OBOL.router.render();
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
          U.toast('Minted ' + r.added + ' fact' + (r.added === 1 ? '' : 's') + 'recomputing');
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
