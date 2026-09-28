/*!
 * obol ui — routes/home.js — THE ENGAGEMENT SCREEN (the front door / launch surface).
 * Replaces the old dashboard: create an engagement with a platform profile (HTB, OffSec/OSCP,
 * PWK, TryHackMe, HTB CPTS, CTF, OSWP, custom) + machine-type + scope/targets, then launch a
 * run (seeds facts -> lands on the coach). Also the engagement library + active-engagement
 * status. Emulates obol-local's `engagement new` + profile + scope flow.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  // Extract IPs and CIDRs from arbitrary pasted text (obol-local `scope paste` filter).
  var IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
  function extractScope(text) {
    var out = [], m, seen = {};
    while ((m = IP_RE.exec(text || '')) !== null) {
      var v = m[0];
      // validate octets 0-255
      var ok = v.split('/')[0].split('.').every(function (o) { return +o >= 0 && +o <= 255; });
      if (ok && !seen[v]) { seen[v] = 1; out.push(v); }
    }
    return out;
  }
  function isCidr(s) { return s.indexOf('/') >= 0; }

  function platformCards(selected) {
    return OBOL.profile.listPresets().map(function (p) {
      return '<label class="pf-card' + (p.id === selected ? ' sel' : '') + '">'
        + '<input type="radio" name="pf-platform" value="' + esc(p.id) + '"' + (p.id === selected ? ' checked' : '') + '>'
        + '<span class="pf-name">' + esc(p.name) + '</span>'
        + (p.exam ? '<span class="pf-badge exam">exam</span>' : '<span class="pf-badge lab">lab</span>')
        + '<span class="pf-flags">' + esc(p.flag_names.join(', ')) + '</span>'
        + '</label>';
    }).join('');
  }

  // Placeholder for the working-directory field: a GENERIC example, never the operator's own path. Left
  // blank, the real default is a neutral ~/engagements/<engagement-name> (see the launch handler).
  function workdirHint() {
    var sel = ((OBOL.store.active() || {}).profile || {}).platform || 'custom';
    return OBOL.workspace.join(OBOL.workspace.DEFAULT_BASE, OBOL.profile.isExamPlatform(sel) ? 'exam' : 'box');
  }

  function machineOptions(selected) {
    return '<option value="">— machine type (optional) —</option>' + OBOL.profile.listMachineTypes().map(function (m) {
      return '<option value="' + esc(m.id) + '"' + (m.id === selected ? ' selected' : '') + '>' + esc(m.name) + '</option>';
    }).join('');
  }

  // An engagement is "set up" once the operator has actually done something with it: chosen a real
  // platform, scoped a target, or collected a fact. A brand-new default run (custom platform, no
  // targets, no facts, still called "Untitled Run") is NOT set up — we greet it with guidance
  // instead of a confusing phase bar.
  function isConfigured(eng, factCount) {
    if (!eng) return false;
    var prof = eng.profile || {};
    var realPlatform = prof.platform && prof.platform !== 'custom';
    var targets = (eng.targets || []).length > 0;
    var scoped = !!(eng.params && (eng.params.scope_defined || eng.params.target));
    var named = !!eng.name && !/^(untitled run|new engagement)$/i.test(String(eng.name).trim());
    return realPlatform || targets || scoped || (factCount || 0) > 0 || named;
  }

  // First-run guidance shown in place of the active-run panel until the engagement is set up.
  function gettingStarted() {
    return '<div class="eng-welcome">'
      + '<div class="eng-welcome-h">Set up your first engagement</div>'
      + '<p class="eng-welcome-sub">obol coaches your next move from the evidence you collect — no run is configured yet. Set one up below and the coach takes over from there.</p>'
      + '<ol class="eng-steps">'
      + '<li><span class="eng-step-n">1</span><div><b>Pick a platform</b><span>Hack The Box, OffSec OSCP, CTF… it decides the flags, proof rules, and report shape.</span></div></li>'
      + '<li><span class="eng-step-n">2</span><div><b>Set your scope</b><span>Paste the target IPs / CIDRs for the box or lab (junk is filtered).</span></div></li>'
      + '<li><span class="eng-step-n">3</span><div><b>Launch</b><span>obol opens the coach and ranks your first commands. The phase bar lights up as you collect facts.</span></div></li>'
      + '</ol>'
      + '<button type="button" class="btn-primary eng-jump">Set It Up Below ↓</button>'
      + '</div>';
  }

  function activePanel() {
    var eng = OBOL.store.active();
    if (!eng) return '';
    var prof = eng.profile || {};
    var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
    var exam = OBOL.profile.isExamPlatform(prof.platform);
    var facts = OBOL.store.factSet();
    var ranked = OBOL.pack.nextActions(facts, OBOL.packs.actions());
    // Nothing is "reached" until something is actually known. With no facts yet (a brand-new run,
    // no targets), recon isn't done — it's simply where you start, so mark it the frontier and
    // leave every phase unlit rather than lighting recon/enum on an empty engagement.
    var started = Object.keys(facts.kinds()).length > 0;
    var reached = started ? OBOL.phases.phaseIndex(OBOL.phases.targetPhase(facts)) : -1;
    var frontier = started ? OBOL.phases.frontierIndex(facts) : 0;
    var spine = OBOL.phases.PHASES.map(function (p, i) {
      return '<span class="spine-node ph-' + p + (i <= reached ? ' reached' : '') + (i === frontier ? ' frontier' : '') + '">' + p + '</span>';
    }).join('<span class="spine-sep">›</span>');
    var mt = prof.machine_type ? (OBOL.profile.MACHINE_TYPES[prof.machine_type] || {}).name : '';
    var nt = (eng.targets || []).length, nf = Object.keys(facts.kinds()).length;
    var isCustom = !prof.platform || prof.platform === 'custom';
    return '<div class="eng-active">'
      + '<div class="eng-active-head">'
      + '<div><div class="eng-active-name">' + esc(eng.name) + '</div>'
      + '<div class="eng-badges">'
      // only show a platform badge for a real platform — "Custom" told the user nothing
      + (isCustom ? '' : '<span class="pf-badge ' + (exam ? 'exam' : 'lab') + '">' + esc(preset.name) + (exam ? ' · exam' : '') + '</span>')
      + (mt ? '<span class="pill">' + esc(mt) + '</span>' : '')
      + (prof.osid ? '<span class="pill">OSID ' + esc(prof.osid) + '</span>' : '')
      + '<span class="pill">' + nt + ' Target' + (nt === 1 ? '' : 's') + '</span>'
      + '<span class="pill">' + nf + ' Fact' + (nf === 1 ? '' : 's') + '</span>'
      + '</div></div>'
      + '<a class="btn-primary" href="#/path">Open Coach →</a>'
      + '</div>'
      + '<div class="home-spine">' + spine + '</div>'
      + (ranked.length ? ('<div class="eng-nextmove"><span class="mini-label">Next Move</span> ' + esc(ranked[0].title) + '</div>') : '')
      + engagementPath()
      + '</div>';
  }

  // ── the virtual workspace: obol's model of the operator's Kali working directory, filling over time ──
  function ago(at) {
    if (!at) return '';
    var s = Math.max(0, Math.floor((Date.now() - at) / 1000));
    if (s < 60) return 'Just Now';
    var m = Math.floor(s / 60); if (m < 60) return m + 'm ago';
    var h = Math.floor(m / 60); if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  }
  function factLine(kinds) {
    if (!kinds || !kinds.length) return '';
    var names = kinds.slice(0, 6).map(function (k) { return esc(U.titleCase(OBOL.pack.friendly(k))); });
    return '<div class="ws-file-facts"><span class="mini-label">Proved</span>' + names.join(', ')
      + (kinds.length > 6 ? ' +' + (kinds.length - 6) : '') + '</div>';
  }
  // human file size, e.g. 5.0 kB — only shown for files a disk-sync measured.
  function fsize(n) { n = +n || 0; if (n <= 0) return ''; if (n < 1024) return n + ' B'; if (n < 1048576) return (n / 1024).toFixed(1) + ' kB'; return (n / 1048576).toFixed(1) + ' MB'; }
  // the capture bridge: send the operator to Evidence, pre-addressed to this file's move when it has
  // one (the command prefills), so pasting the output routes through the normal parser → facts pipeline.
  function captureHref(f) { return f.actionId ? ('#/evidence/' + encodeURIComponent(f.actionId)) : '#/evidence'; }

  function fileRow(f, root) {
    var rel = OBOL.vfs.relOf(f.path, root);
    var badge = f.facts.length ? ('<span class="ws-badge">' + f.facts.length + ' Fact' + (f.facts.length === 1 ? '' : 's') + '</span>') : '';
    var suggested = f.status === 'expected' && f.origin === 'suggested';
    // a one-word state tag so the tree reads at a glance without expanding a row.
    var tag = f.status === 'captured' ? '' : suggested ? '<span class="ws-tag ws-tag-sugg">suggested</span>'
      : f.unknown ? '<span class="ws-tag ws-tag-unk">on disk</span>'
      : f.manual ? '<span class="ws-tag ws-tag-man">added</span>'
      : f.confirmed ? '<span class="ws-tag ws-tag-conf">on disk</span>' : '<span class="ws-tag ws-tag-exp">expected</span>';
    var cmdBlock = f.command ? '<div class="ws-file-cmd"><span class="mini-label">Command</span><code>' + esc(f.command) + '</code></div>' : '';
    var body;
    if (f.image) {
      body = '<img class="ws-shot" src="' + esc(f.image) + '" alt="proof screenshot">';
    } else if (f.status === 'captured') {
      // drill-down: the raw command output as a mini terminal, plus what it proved and where to review it.
      var out = String(f.output || '').replace(/\s+$/, '');
      var capped = out.length > 4000 ? out.slice(0, 4000) + '\n… (truncated — full output in the Run Log)' : out;
      body = cmdBlock
        + (capped ? '<pre class="ws-mini-term">' + esc(capped) + '</pre>' : '<div class="ws-file-note">Captured — no text body.</div>')
        + factLine(f.facts)
        + '<a class="ws-file-link" href="#/history">Review in the Run Log →</a>';
    } else if (suggested) {
      // anticipated: the coach is recommending a move that writes this file. obol assumes you are
      // probably about to create it and pencils it in — it becomes real once you run and paste it.
      body = '<div class="ws-file-note">The coach is suggesting a move that creates this file'
        + (f.title ? ' (<strong>' + esc(f.title) + '</strong>)' : '') + '. Pencilled in — run it, then paste the output to capture it.</div>'
        + cmdBlock
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Run it, then capture it here →</a>';
    } else if (f.unknown) {
      // a disk-sync turned this up but obol has no move that made it — stay on the same page, invite it.
      body = '<div class="ws-file-note">Found on your disk by a workspace sync. obol doesn\'t know this one yet'
        + (f.size ? ' (' + esc(fsize(f.size)) + ')' : '') + ' — paste its contents and the parsers will read whatever they recognize.</div>'
        + '<a class="ws-file-link" href="#/evidence">Paste its contents on Evidence →</a>';
    } else if (f.manual) {
      body = '<div class="ws-file-note">You added this file by hand. Paste its contents on Evidence to mint any facts it proves.</div>'
        + '<a class="ws-file-link" href="#/evidence">Capture it on Evidence →</a>';
    } else if (f.confirmed) {
      // used by a later command / seen by a sync → it exists on disk, obol just never received the body.
      body = '<div class="ws-file-note">This file is on your disk, but obol hasn\'t received its output. Paste it on Evidence to capture what it proves.</div>'
        + cmdBlock
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Capture it on Evidence →</a>';
    } else {
      // expected but not captured: obol handed the command but never got the output.
      body = '<div class="ws-file-note">obol handed you a command that writes this file, but hasn\'t received its output yet.</div>'
        + cmdBlock
        + '<a class="ws-file-link" href="' + captureHref(f) + '">Paste its output on Evidence to capture it →</a>';
    }
    var desc = OBOL.vfs.describe ? ('<div class="ws-file-desc">' + esc(OBOL.vfs.describe(f)) + '</div>') : '';
    var cls = 'ws-file ws-' + f.status + (suggested ? ' ws-suggested' : '') + (f.confirmed ? ' ws-confirmed' : '')
      + (f.unknown ? ' ws-unknown' : '') + (f.manual ? ' ws-manual' : '') + (f.flag ? ' ws-flag' : '');
    return '<details class="' + cls + '" data-rel="' + U.attr(rel) + '">'
      + '<summary><span class="ws-dot"></span><span class="ws-file-name">' + esc(f.name) + '</span>' + tag + badge
      + (f.at ? '<span class="ws-when">' + esc(ago(f.at)) + '</span>' : '')
      + '<button type="button" class="ws-rm" data-rel="' + U.attr(rel) + '" title="Remove from workspace" aria-label="Remove ' + U.attr(f.name) + '">×</button>'
      + '</summary>'
      + '<div class="ws-file-body">' + desc + body + '</div></details>';
  }
  // The "Sync from your disk" block: a one-shot snapshot command to run, and a box to paste its listing
  // back. obol reconciles — confirming files it predicted, adopting files it didn't know about.
  function syncBlock(eng) {
    var cmd = (OBOL.workspace && OBOL.workspace.snapshotCmd) ? OBOL.workspace.snapshotCmd(eng) : '';
    if (!cmd) return '';
    return '<details class="ws-sync"><summary>Sync From Your Disk <span class="ws-sync-tag">bulk-match the whole folder</span></summary>'
      + '<p class="ws-sync-hint">Run this in your working directory and paste the output back. obol confirms the files it predicted and adopts any it didn\'t know about (you can then paste their contents to mint facts). Nothing is executed here.</p>'
      + '<div class="ws-sync-cmd"><code id="ws-snap-code">' + esc(cmd) + '</code>'
      + '<button type="button" class="btn-copy ws-snap-copy" data-copy="ws-snap-code">copy</button></div>'
      + '<textarea id="ws-sync-paste" class="ws-sync-paste" rows="4" placeholder="Paste the file list here…" spellcheck="false"></textarea>'
      + '<button type="button" class="btn-primary ws-sync-run">Sync Workspace</button>'
      + '</details>';
  }

  function workspacePanel() {
    var eng = OBOL.store.active();
    if (!eng || !OBOL.vfs) return '';
    var ov = (eng.workspace && eng.workspace.overrides) || {};
    // Until the operator has actually done something (run/pasted a command, added or synced a file), keep
    // the workspace a clean, empty skeleton — a lone pencilled-in "suggested" file on a brand-new run reads
    // as cryptic. Once there is real activity, obol resumes pencilling in what the next moves will create.
    var started = (eng.activities || []).length > 0 || (eng.screenshots || []).length > 0 || ((ov.added || []).length > 0);
    var vfs = OBOL.vfs.build(eng, started ? {} : { suggested: [] });
    var hidden = Object.keys(ov.removed || {}).length;
    var head = '<div class="ws-panel-head"><h2 class="coach-sec-h">Workspace</h2>'
      + (vfs.total ? ('<span class="ws-counts"><span class="ws-c-cap">' + vfs.captured + ' File' + (vfs.captured === 1 ? '' : 's') + ' Captured</span>'
          + (vfs.expected ? ' · <span class="ws-c-exp">' + vfs.expected + ' Pending</span>' : '') + '</span>') : '')
      + '</div>';
    var rootLine = '<div class="ws-root"><code>' + esc(vfs.root) + '</code>'
      + (ov.syncedAt ? '<span class="ws-synced-at">Synced ' + esc(ago(ov.syncedAt)) + '</span>' : '') + '</div>';
    var invite = started
      ? '<p class="ws-invite">A live picture of your Kali working directory. obol pencils in the files the coach\'s next moves'
        + ' will create, then confirms each one once you run it and paste the output on <a href="#/evidence">Evidence</a>.'
        + ' Add or remove files by hand, or sync the whole folder below.</p>'
      : '<p class="ws-invite">This mirrors your Kali working directory. It\'s empty until you start: run a move from'
        + ' <a href="#/path">Next Steps</a> and paste its output on <a href="#/evidence">Evidence</a>, and the files you'
        + ' generate show up here as you go.</p>';
    var tree = vfs.folders.map(function (fo) {
      var files = fo.files.map(function (f) { return fileRow(f, vfs.root); }).join('');
      return '<div class="ws-folder' + (fo.files.length ? '' : ' ws-empty') + '">'
        + '<div class="ws-folder-h"><span class="ws-folder-name">' + esc(fo.label) + '</span>'
        + (fo.files.length ? '<span class="ws-folder-count">' + fo.files.length + '</span>' : '')
        + '<button type="button" class="ws-add" data-folder="' + U.attr(fo.key) + '" title="Add a file to ' + esc(fo.label) + '" aria-label="Add a file to ' + esc(fo.label) + '">+</button></div>'
        + (files || '<div class="ws-folder-empty">Empty</div>') + '</div>';
    }).join('');
    var footer = hidden ? ('<div class="ws-foot"><button type="button" class="ws-restore" data-x>' + hidden + ' Hidden · Restore</button></div>') : '';
    return '<aside class="ws-panel">' + head + rootLine + invite + '<div class="ws-tree">' + tree + '</div>' + footer + syncBlock(eng) + '</aside>';
  }

  // The engagement-wide Attack Path ribbon (identical to a single target's when scope is one host).
  function engagementPath() {
    var flow = OBOL.chainview ? OBOL.chainview.engagement() : '';
    if (!flow) return '';
    return '<div class="eng-apath"><h2 class="coach-sec-h">Attack Path — What Led to What</h2>' + flow + '</div>';
  }

  function libraryList() {
    var rows = OBOL.store.listEngagements().map(function (e) {
      var prof = e.profile || {};
      var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
      var active = e.id === OBOL.store.activeId();
      return '<li class="lib-row' + (active ? ' active' : '') + '">'
        + '<button class="lib-open" data-eng="' + esc(e.id) + '"><span class="lib-name">' + esc(e.name) + '</span>'
        + '<span class="pill">' + esc(preset.name) + '</span>'
        + '<span class="lib-meta">' + (e.targets || []).length + ' Targets · ' + (e.facts || []).length + ' Facts</span></button>'
        + '<button class="lib-del" data-eng="' + esc(e.id) + '" title="Delete">×</button></li>';
    }).join('');
    return '<ul class="lib-list">' + rows + '</ul>';
  }

  function render() {
    var active = OBOL.store.active();
    var prof = (active || {}).profile || {};
    var sel = prof.platform || 'custom';
    var factCount = Object.keys(OBOL.store.factSet().kinds()).length;
    var configured = isConfigured(active, factCount);
    return '<section class="engscreen">'
      + '<h1 class="route-h1">Engagements</h1>'
      + '<p class="route-sub">Pick a platform, set your scope, and launch a run. The profile decides which flags the hunt targets, the proof requirements, and the report shape.'
      + ' <span class="kbd-hint">Tip: press <kbd>' + (navigator.platform && /mac/i.test(navigator.platform) ? '⌘' : 'Ctrl') + '</kbd>+<kbd>K</kbd> anywhere to search commands.</span></p>'
      + '<div class="eng-top">' + (configured ? activePanel() : gettingStarted()) + workspacePanel() + '</div>'
      + '<div class="eng-library"><div class="eng-library-head"><h2 class="coach-sec-h">Engagement Library</h2>'
      + '<details class="eng-danger-toggle"><summary>Manage / Reset</summary>'
      + '<div class="eng-danger"><div class="eng-danger-item"><div class="eng-danger-txt"><strong>Delete All Engagements</strong>'
      + '<span>Remove every saved run and its evidence. Keeps your skin &amp; appearance settings.</span></div>'
      + '<button class="btn-danger" id="eng-clear">Delete All Engagements</button></div>'
      + '<div class="eng-danger-item"><div class="eng-danger-txt"><strong>Full Reset</strong>'
      + '<span>Erase <em>everything</em> obol saved in this browser — engagements, screenshots, and settings — and start completely fresh. A hard refresh (Ctrl+F5) does not do this.</span></div>'
      + '<button class="btn-danger btn-danger-strong" id="eng-reset">Full Reset — Erase All Data</button></div>'
      + '</div></details></div>'
      + libraryList() + '</div>'
      + '<div class="eng-create" id="eng-setup"><h2 class="coach-sec-h">' + (configured ? 'New Engagement' : 'Set up your run') + '</h2>'
      + '<label class="eng-field"><span>Name</span><input id="eng-name" placeholder="Name this run — e.g. “OSCP prep” or “Lab night 3”" autocomplete="off"></label>'
      + '<div class="eng-field"><span>Platform profile</span><div class="pf-grid" id="pf-grid">' + platformCards(sel) + '</div></div>'
      + '<div class="eng-row2">'
      + '<label class="eng-field"><span>Machine type</span><select id="eng-mt">' + machineOptions(prof.machine_type || '') + '</select></label>'
      + '<label class="eng-field pf-osid" id="pf-osid-wrap" style="display:none"><span>OSID (OffSec exam)</span><input id="eng-osid" placeholder="OS-XXXXX"></label>'
      + '<label class="eng-field pf-osid" id="pf-cand-wrap" style="display:none"><span>Candidate</span><input id="eng-cand" placeholder="Your name"></label>'
      + '</div>'
      + '<label class="eng-field"><span>Scope / targets — paste IPs &amp; CIDRs (junk is filtered)</span>'
      + '<textarea id="eng-scope" class="ev-textarea" style="min-height:90px" placeholder="10.10.10.10  10.10.10.20&#10;10.10.10.0/24"></textarea></label>'
      + '<label class="eng-field"><span>Working directory <span class="eng-field-opt">(on your Kali box — optional)</span></span>'
      + '<input id="eng-workdir" autocomplete="off" spellcheck="false" placeholder="' + esc(workdirHint()) + '"></label>'
      + '<div class="eng-field-hint">obol fills output paths from this (<code>scans/</code>, <code>loot/</code>, <code>proof/</code>…) and gives you a one-line setup command. Leave blank for a sensible default.</div>'
      + '<div class="eng-row2">'
      + '<label class="eng-field"><span>Your VM IP <span class="eng-field-opt">(attacker box — optional)</span></span>'
      + '<input id="eng-lhost" autocomplete="off" spellcheck="false" inputmode="decimal" placeholder="e.g. 10.10.14.9"></label>'
      + '<label class="eng-field"><span>Interface</span><select id="eng-iface">'
      + ['tun0', 'tun1', 'tap0', 'eth0', 'wlan0', 'vpn0', 'wg0'].map(function (i) { return '<option value="' + i + '"' + (i === 'tun0' ? ' selected' : '') + '>' + i + '</option>'; }).join('')
      + '<option value="">other / none</option></select></label>'
      + '</div>'
      + '<div class="eng-field-hint">obol fills <code>{{lhost}}</code> in coercion, relay and reverse-shell commands from this, and never mistakes your own box for a target on import. Leave blank and obol learns it from a pasted <code>[tun0:IP]</code> prompt.</div>'
      + '<button id="eng-launch" class="btn-primary">Create &amp; Launch Run →</button>'
      + '</div>'
      + '</section>';
  }

  function syncOsidVisibility() {
    var sel = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
    var preset = OBOL.profile.listPresets().find(function (p) { return p.id === sel; }) || {};
    var show = preset.osid ? '' : 'none';
    var o = document.getElementById('pf-osid-wrap'), c = document.getElementById('pf-cand-wrap');
    if (o) o.style.display = show; if (c) c.style.display = show;
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    // platform card selection styling + OSID reveal
    U.on(mount, 'change', 'input[name="pf-platform"]', function (e, t) {
      mount.querySelectorAll('.pf-card').forEach(function (el) { el.classList.remove('sel'); });
      var card = t.closest('.pf-card'); if (card) card.classList.add('sel');
      syncOsidVisibility();
    });
    syncOsidVisibility();

    // getting-started CTA: scroll to the setup form and focus the name field
    U.on(mount, 'click', '.eng-jump', function () {
      var form = document.getElementById('eng-setup');
      if (form) form.scrollIntoView({ behavior: 'smooth', block: 'start' });
      var nm = document.getElementById('eng-name');
      if (nm) setTimeout(function () { try { nm.focus(); } catch (e) {} }, 300);
    });

    // library: open / delete
    U.on(mount, 'click', '.lib-open', function (e, t) {
      OBOL.store.setActive(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });
    U.on(mount, 'click', '.lib-del', function (e, t) {
      if (!confirm('Delete this engagement? This cannot be undone.')) return;
      OBOL.store.deleteEngagement(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });

    // danger zone: delete all engagements (keeps prefs) / full reset (erase all browser data)
    U.on(mount, 'click', '#eng-clear', function () {
      if (!confirm('Delete ALL engagements and their evidence?\n\nThis cannot be undone. Your appearance settings are kept.')) return;
      OBOL.store.clearEngagements().then(function () { try { U.toast('All engagements deleted — reloading'); } catch (e) {} setTimeout(function () { location.reload(); }, 150); });
    });
    U.on(mount, 'click', '#eng-reset', function () {
      if (!confirm('FULL RESET\n\nErase everything obol saved in this browser — every engagement, screenshot, and setting — and start completely fresh.\n\nThis cannot be undone. Continue?')) return;
      OBOL.store.resetAll().then(function () { try { U.toast('All data cleared — reloading fresh'); } catch (e) {} setTimeout(function () { location.reload(); }, 200); });
    });

    // ── virtual workspace: keep the file tree in sync with the operator's real disk ──
    function updateOverrides(fn, label) {
      OBOL.store.update(function (e) {
        e.workspace = e.workspace || {};
        var ov = e.workspace.overrides = e.workspace.overrides || {};
        ov.added = ov.added || []; ov.removed = ov.removed || {}; ov.onDisk = ov.onDisk || {};
        fn(ov, e);
      }, label || 'workspace');
      OBOL.router.render();
    }
    // remove any file from the view (hide it) — also drop it from the hand-added/synced list.
    U.on(mount, 'click', '.ws-rm', function (e, t) {
      e.preventDefault(); e.stopPropagation();
      var rel = t.getAttribute('data-rel'); if (!rel) return;
      updateOverrides(function (ov) {
        ov.removed[rel] = true;
        ov.added = (ov.added || []).filter(function (a) { return OBOL.vfs.relOf((typeof a === 'string' ? a : a.path), (OBOL.store.active().workspace || {}).root) !== rel; });
      }, 'ws-remove');
    });
    // add a file by hand to a folder, to match something on disk obol didn't predict.
    U.on(mount, 'click', '.ws-add', function (e, t) {
      e.preventDefault();
      var folder = t.getAttribute('data-folder') || 'other';
      var raw = (window.prompt('Add a file to ' + folder + '/ — name it exactly as it is on your disk:', '') || '').trim();
      if (!raw) return;
      var lay = (OBOL.workspace && OBOL.workspace.LAYOUT) || {};
      var name = raw.replace(/^\/+/, '');
      var rel = /[\/]/.test(name) ? name : ((lay[folder] || (folder !== 'other' ? folder : '')) ? ((lay[folder] || folder) + '/' + name) : name);
      updateOverrides(function (ov) {
        delete ov.removed[rel];
        if (!(ov.added || []).some(function (a) { return (typeof a === 'string' ? a : a.path) === rel; })) {
          ov.added.push({ path: rel, source: 'manual', at: Date.now() });
        }
      }, 'ws-add');
      U.toast('Added ' + rel + ' — paste its contents on Evidence to mint facts');
    });
    // restore everything the operator hid.
    U.on(mount, 'click', '.ws-restore', function (e) {
      e.preventDefault();
      updateOverrides(function (ov) { ov.removed = {}; }, 'ws-restore');
    });
    // copy the snapshot command.
    U.on(mount, 'click', '.ws-snap-copy', function (e, t) {
      var el = document.getElementById(t.getAttribute('data-copy'));
      if (el) U.copy(el.textContent).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });
    // ── hover preview card: peek at a file's contents / purpose without expanding the row ──
    (function wireWorkspacePreview() {
      if (!OBOL.vfs || matchMedia('(hover: none)').matches) return; // touch devices use click-to-expand
      var byRel = {};
      try { var vt = OBOL.vfs.build(OBOL.store.active()); (vt.files || []).forEach(function (f) { byRel[OBOL.vfs.relOf(f.path, vt.root)] = f; }); } catch (e) { return; }
      var card = document.getElementById('ws-preview'), fresh = false;
      if (!card) { card = document.createElement('div'); card.id = 'ws-preview'; card.className = 'ws-preview'; card.hidden = true; document.body.appendChild(card); fresh = true; }
      function previewHtml(f) {
        var tag = f.status === 'captured' ? 'captured' : f.origin === 'suggested' ? 'suggested'
          : f.unknown ? 'on disk' : f.manual ? 'added' : f.confirmed ? 'on disk' : 'expected';
        var head = '<div class="ws-pv-head"><span class="ws-pv-name">' + esc(f.name) + '</span><span class="ws-pv-tag ws-pv-' + esc(tag.replace(/\s+/g, '')) + '">' + esc(tag) + '</span></div>'
          + '<div class="ws-pv-desc">' + esc(OBOL.vfs.describe(f)) + '</div>';
        // the capture bridge: a clear, clickable pointer to paste the file's CONTENTS on Evidence — the
        // only way a file's facts get minted (a directory sync confirms existence, never contents).
        var cta = '<a class="ws-pv-cta" href="' + captureHref(f) + '">Paste Its Contents on Evidence →</a>';
        var body;
        if (f.image) body = '<img class="ws-pv-img" src="' + esc(f.image) + '" alt="">';
        else if (f.status === 'captured' && f.output) {
          var lines = String(f.output).replace(/\s+$/, '').split(/\n/);
          var shown = lines.slice(0, 16).join('\n') + (lines.length > 16 ? '\n… ' + (lines.length - 16) + ' more line' + (lines.length - 16 === 1 ? '' : 's') : '');
          body = '<pre class="ws-pv-term">' + esc(shown) + '</pre>';
        } else if (f.origin === 'suggested') body = '<div class="ws-pv-note">Pencilled in by the coach — run the move, then paste its output to capture it.</div>' + (f.command ? '<code class="ws-pv-cmd">' + esc(f.command) + '</code>' : '') + cta;
        else if (f.unknown) body = '<div class="ws-pv-note">Found on your disk by a sync. obol knows it exists but not what\'s inside.</div>' + cta;
        else if (f.manual) body = '<div class="ws-pv-note">Added by hand. Syncing only confirms it exists — to mint facts, paste what\'s inside.</div>' + cta;
        else body = '<div class="ws-pv-note">obol expects this file but hasn\'t received its output yet.</div>' + (f.command ? '<code class="ws-pv-cmd">' + esc(f.command) + '</code>' : '') + cta;
        return head + body;
      }
      function place(row) {
        var r = row.getBoundingClientRect();
        card.style.visibility = 'hidden'; card.hidden = false;
        var cw = card.offsetWidth, ch = card.offsetHeight;
        var left = r.left - cw - 12;                 // prefer left of the right-rail row
        if (left < 8) left = Math.min(r.right + 12, window.innerWidth - cw - 8);
        var top = Math.min(Math.max(8, r.top), window.innerHeight - ch - 8);
        card.style.left = Math.max(8, left) + 'px'; card.style.top = top + 'px';
        card.style.visibility = '';
      }
      function show(row) {
        var rel = row.getAttribute('data-rel'); var f = byRel[rel];
        if (!f) return;
        clearTimeout(card._hideT);
        card.innerHTML = previewHtml(f);
        place(row);
      }
      U.on(mount, 'mouseover', '.ws-file > summary', function (e, t) { show(t.closest('.ws-file')); });
      U.on(mount, 'mouseout', '.ws-file > summary', function () { card._hideT = setTimeout(function () { card.hidden = true; }, 90); });
      if (fresh) {
        card.addEventListener('mouseenter', function () { clearTimeout(card._hideT); });
        card.addEventListener('mouseleave', function () { card.hidden = true; });
      }
    })();

    // paste-back sync: reconcile a find manifest against the model.
    U.on(mount, 'click', '.ws-sync-run', function () {
      var ta = document.getElementById('ws-sync-paste');
      var entries = OBOL.vfs.parseSnapshot(ta ? ta.value : '');
      if (!entries.length) { U.toast('No file list found in that paste', 'err'); return; }
      var r = OBOL.vfs.reconcile(OBOL.store.active(), entries);
      OBOL.store.update(function (e) { e.workspace = e.workspace || {}; e.workspace.overrides = r.overrides; }, 'ws-sync');
      OBOL.router.render();
      U.toast(r.confirmed + ' confirmed · ' + r.adopted + ' new file' + (r.adopted === 1 ? '' : 's') + ' adopted');
    });

    // create & launch
    var launch = document.getElementById('eng-launch');
    if (launch) launch.addEventListener('click', function () {
      var name = (document.getElementById('eng-name').value || '').trim();
      var platform = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
      var mt = (document.getElementById('eng-mt').value || '');
      var osid = (document.getElementById('eng-osid') || {}).value || '';
      var cand = (document.getElementById('eng-cand') || {}).value || '';
      var scopeText = (document.getElementById('eng-scope').value || '');
      var scope = extractScope(scopeText);
      // The operator's own attack box: IP + interface. Feeds {{lhost}} and the import self-IP guard.
      var lhostRaw = ((document.getElementById('eng-lhost') || {}).value || '').trim();
      var lhost = /^(\d{1,3}\.){3}\d{1,3}$/.test(lhostRaw) ? lhostRaw : '';
      var iface = ((document.getElementById('eng-iface') || {}).value || '').trim();
      if (lhostRaw && !lhost) { U.toast('That VM IP doesn\'t look like an IPv4 address — ignoring it', 'err'); }
      if (!name) { name = (OBOL.profile.PRESETS[platform] || {}).name || 'Engagement'; }

      // If the active engagement is still the untouched default, configure it in place rather than
      // spawning a second, empty run behind it. Otherwise create a fresh engagement as before.
      var active = OBOL.store.active();
      var reuse = active && !isConfigured(active, Object.keys(OBOL.store.factSet().kinds()).length);

      // Working directory: what the operator typed, else a NEUTRAL default under ~/engagements named
      // after the engagement itself — not the target IP, and not a deep path remembered from a past run.
      var typed = OBOL.workspace.sanitizeRoot((document.getElementById('eng-workdir') || {}).value || '');
      var root = typed || OBOL.workspace.join(OBOL.workspace.DEFAULT_BASE, OBOL.workspace.slugify(name) || 'engagement');

      var seed = function () {
        // seed targets from bare IPs; keep CIDRs as authorized scope only.
        var hosts = scope.filter(function (s) { return !isCidr(s); });
        var facts = [];
        OBOL.store.update(function (e) {
          if (reuse) {
            e.name = name;
            e.profile = Object.assign(e.profile || {}, { platform: platform, machine_type: mt, osid: osid.trim(), candidate: cand.trim(), scope: scope });
            e.params = e.params || {}; e.params.platform = platform;
          }
          e.workspace = { root: root };
          e.targets = [];
          hosts.forEach(function (ip, i) {
            e.targets.push({ id: 't' + i + '-' + Date.now().toString(36), ip: ip, hostname: '', os: '' });
            facts.push(OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + ip, source: 'engagement' }));
          });
          if (!e.params) e.params = {};
          if (hosts[0]) e.params.target = hosts[0];
          if (scope.length) e.params.scope_defined = true;
          if (lhost) { e.params.lhost = lhost; if (iface) e.params.lhost_iface = iface; }
        }, 'launch');
        if (facts.length) OBOL.store.addFacts(facts, 'launch');
        OBOL.app.renderSidebar();
        U.toast(hosts.length ? ('Launched — ' + hosts.length + ' target(s) scoped') : 'Engagement created — add targets to begin');
        OBOL.router.go('path');
      };

      if (reuse) { seed(); }
      else { OBOL.store.createEngagement(name, { platform: platform, machine_type: mt, osid: osid.trim(), candidate: cand.trim(), scope: scope }).then(seed); }
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.home = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
