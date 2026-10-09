/*!
 * obol ui — routes/cruise.js — CRUISE (experimental), the exam-legal, no-execution port of
 * obol-local's cruise control. The loop with the human as the execution channel: obol hands you a
 * phase-scoped BATCH of safe moves, you run the script on your own box, you paste the output back,
 * facts update, and the next batch generates, round after round, until flags.
 *
 * Engine: OBOL.cruise (plan = frontier cut + mode gate; buildScript = self-delimiting bash). This
 * route is a view over the ONE store, the fact ledger, OBOL.pack.rankActions and the command filler.
 * It never executes and never forks the ranker. Curated runbooks live on at the bottom as Recipes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr ? U.attr(s) : esc(s); }
  function ic(n) { try { return OBOL.ic ? OBOL.ic(n) : ''; } catch (e) { return ''; } }

  var PHASE_LABEL = { recon: 'Recon', enum: 'Enumerate', creds: 'Credentials', access: 'Access', escalate: 'Escalate', loot: 'Loot' };

  function optsFor(eng) {
    return { params: (eng && eng.params) || {}, profile: (eng && eng.profile) || {}, workspace: OBOL.workspace.tokens(eng) };
  }
  function modeOf(eng) {
    var m = eng && eng.ui && eng.ui.cruiseMode;
    return (m === 'lab') ? 'lab' : 'exam';
  }

  function fill(action, facts, opts, idx) {
    try { return OBOL.command.fillCommand(action, facts, opts, idx || 0); }
    catch (e) { return { tool: action.tool || '', filled: action.command || '', note: '' }; }
  }

  function tierChip(tier) {
    if (tier === 'active') return '<span class="cr-tier cr-tier-active" title="Lands or escalates access">active</span>';
    if (tier === 'manual') return '<span class="cr-tier cr-tier-manual" title="Interactive or manual">manual</span>';
    return '<span class="cr-tier cr-tier-safe" title="Safe enumeration">safe</span>';
  }

  // One command row: number, title, tool tag, filled command + copy, note, unfilled-token hint.
  function cmdRow(n, item, facts, opts) {
    var a = item.action;
    var f = fill(a, facts, opts, item.cmdIndex);
    var unfilled = [];
    try { unfilled = OBOL.command.unfilledTokens(f.filled) || []; } catch (e) {}
    var warn = unfilled.length
      ? '<div class="cmd-needs">needs: ' + unfilled.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(', ') + '</div>' : '';
    var note = f.note ? '<div class="cmd-note">' + esc(f.note) + '</div>' : '';
    return '<li class="cr-cmd">'
      + '<div class="cr-cmd-head"><span class="cr-cmd-n">' + n + '</span>'
      + '<span class="cr-cmd-title">' + esc(a.title || a.id) + '</span>'
      + tierChip(item.tier) + '<span class="cr-cmd-id" title="pack move">' + esc(a.id) + '</span></div>'
      + '<div class="cmd"><div class="cmd-head"><span class="cmd-tag">' + esc(f.tool || 'cmd') + '</span>'
      + '<button class="btn-copy" data-copy="' + attr(f.filled) + '" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code>' + esc(f.filled) + '</code></pre>' + note + warn + '</div></li>';
  }

  function phaseBand(plan) {
    var lbl = (PHASE_LABEL[plan.phase] || plan.phase || 'Next').toUpperCase();
    var n = plan.batch.length;
    var count = n ? (n + ' safe step' + (n === 1 ? '' : 's') + ' ready') : 'no safe steps right now';
    return '<div class="cr-band cr-ph-' + esc(plan.phase || 'recon') + '">'
      + '<span class="cr-band-l">' + esc(lbl) + ' Batch</span>'
      + '<span class="cr-band-d">' + esc(count) + ', independent of each other, run them in any order</span>'
      + '<div class="cr-band-act">'
      + (n ? '<button class="btn-ghost cr-copyall" title="Copy all commands">Copy All</button>'
        + '<button class="btn-primary cr-dl">' + ic('download') + ' Download .sh</button>' : '')
      + '</div></div>';
  }

  function checkpointCard(cp, facts, opts, mode) {
    if (!cp) return '';
    var a = cp.action;
    var f = fill(a, facts, opts, 0);
    var swap = (mode === 'exam' && cp.tier === 'active')
      ? '<button class="btn-ghost cr-mode-lab cr-cp-lab">Switch To Lab To Batch This</button>' : '';
    return '<div class="cr-checkpoint">'
      + '<div class="cr-cp-head"><span class="cr-cp-l">Cruise Stops Here</span>'
      + '<span class="cr-cp-title">' + esc(a.title || a.id) + '</span></div>'
      + '<p class="cr-cp-why">' + esc(cp.reason) + '</p>'
      + '<div class="cmd"><div class="cmd-head"><span class="cmd-tag">' + esc(f.tool || 'cmd') + '</span>'
      + '<button class="btn-copy" data-copy="' + attr(f.filled) + '" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code>' + esc(f.filled) + '</code></pre></div>'
      + swap + '</div>';
  }

  function unlocksStrip(plan) {
    if (!plan.unlocks || !plan.unlocks.length) return '';
    var names = plan.unlocks.slice(0, 5).map(function (u) { return '<span class="cr-unlock">' + esc(u.action.title || u.action.id) + '</span>'; }).join('');
    return '<div class="cr-unlocks"><span class="cr-unlocks-l">' + ic('chain') + ' Running This Should Unlock</span>' + names + '</div>';
  }

  function modeToggle(mode) {
    function b(m, label, sub) {
      var on = (mode === m);
      return '<button class="cr-mode' + (on ? ' is-on' : '') + '" data-cr-mode="' + m + '" aria-pressed="' + on + '">'
        + '<span class="cr-mode-t">' + label + '</span><span class="cr-mode-s">' + sub + '</span></button>';
    }
    return '<div class="cr-modes" role="group" aria-label="Cruise mode">'
      + b('exam', 'Exam', 'Safe enumeration only, exam legal')
      + b('lab', 'Lab', 'Batches past a foothold, not exam legal')
      + '</div>';
  }

  function loopStrip() {
    var steps = [
      ['1', 'Get Your Batch', 'obol lists the safe moves you can run right now.'],
      ['2', 'Run It On Kali', 'Download the script (or copy the commands) and run them on your box.'],
      ['3', 'Paste The Output Back', 'Drop the whole terminal output into the box below.'],
      ['4', 'obol Advances', 'Facts update and the next batch appears. Repeat until flags.'],
    ];
    return '<ol class="cr-loop">' + steps.map(function (s) {
      return '<li class="cr-loop-step"><span class="cr-loop-n">' + s[0] + '</span>'
        + '<div><div class="cr-loop-t">' + s[1] + '</div><div class="cr-loop-d">' + s[2] + '</div></div></li>';
    }).join('') + '</ol>';
  }

  function pastePanel() {
    return '<div class="cr-paste">'
      + '<label class="cr-paste-l" for="cr-paste-box">Paste Your Terminal Output, obol Advances</label>'
      + '<textarea id="cr-paste-box" class="cr-paste-box" spellcheck="false" placeholder="Paste everything your cruise script printed (the ===== OBOL STEP markers help obol segment it)."></textarea>'
      + '<div class="cr-paste-row"><button class="btn-primary cr-ingest">Ingest And Advance</button>'
      + '<span class="cr-paste-msg" role="status"></span></div></div>';
  }

  // ── Recipes (the curated runbooks, kept from the old Playbooks tab) ──────────────────────────────
  function recipeBatch(pb) {
    var steps = OBOL.playbooks.resolveSteps(pb);
    return steps.filter(function (s) { return s.action; }).map(function (s) {
      return { action: s.action, cmdIndex: (s.cmd || 1) - 1, tier: OBOL.cruise.tierOf(s.action) };
    });
  }
  function recipeCard(pb, facts, opts, isApp) {
    var batch = recipeBatch(pb);
    var head = '<summary class="cr-recipe-sum">'
      + '<span class="cr-recipe-t">' + esc(pb.title || pb.name) + '</span>'
      + (pb.phase ? '<span class="ph-chip ph-' + esc(pb.phase) + '">' + esc(pb.phase) + '</span>' : '')
      + (isApp ? '<span class="cr-recipe-app" title="First step is offered on your current facts">applicable now</span>' : '')
      + '<span class="cr-recipe-n">' + batch.length + ' step' + (batch.length === 1 ? '' : 's') + '</span></summary>';
    var body = '<div class="cr-recipe-body">'
      + (pb.description ? '<p class="cr-recipe-desc">' + esc(pb.description) + '</p>' : '')
      + '<div class="cr-recipe-bar"><button class="btn-primary cr-recipe-dl" data-recipe="' + attr(pb.name) + '">' + ic('download') + ' Download .sh</button></div>'
      + '<ol class="cr-cmds">' + batch.map(function (it, i) { return cmdRow(i + 1, it, facts, opts); }).join('') + '</ol></div>';
    return '<details class="cr-recipe" data-recipe="' + attr(pb.name) + '">' + head + body + '</details>';
  }

  function recipesSection(facts, opts) {
    var all = (OBOL.playbooks && OBOL.playbooks.list) ? OBOL.playbooks.list() : [];
    if (!all.length) return '';
    var appSet = {};
    try { (OBOL.playbooks.applicable(facts) || []).forEach(function (p) { appSet[p.name] = true; }); } catch (e) {}
    var ordered = all.slice().sort(function (a, b) {
      var aa = appSet[a.name] ? 0 : 1, ba = appSet[b.name] ? 0 : 1;
      if (aa !== ba) return aa - ba;
      if ((a.phase || '') !== (b.phase || '')) return (a.phase || '').localeCompare(b.phase || '');
      return a.name.localeCompare(b.name);
    });
    return '<details class="cr-recipes">'
      + '<summary class="cr-recipes-sum"><span class="cr-recipes-l">Recipes</span>'
      + '<span class="cr-recipes-d">Curated runbooks for common box shapes, a fixed ordered batch you can export whole.</span></summary>'
      + '<div class="cr-recipes-list">' + ordered.map(function (pb) { return recipeCard(pb, facts, opts, !!appSet[pb.name]); }).join('') + '</div>'
      + '</details>';
  }

  function emptyState() {
    return '<div class="cr-empty">'
      + '<p>Cruise needs a target to plan around. Add one in the sidebar params, or paste a scan on '
      + '<a href="#/evidence">Evidence</a> (or the header Paste), and your first batch appears here.</p></div>';
  }

  function render(ctx) {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var opts = optsFor(eng);
    var mode = modeOf(eng);
    var pack = OBOL.packs.actions();
    var plan = OBOL.cruise.plan(facts, pack, { mode: mode });

    var html = '<section class="cruise">';
    html += '<div class="cr-top"><h1 class="route-h1">Cruise <span class="cr-exp">Experimental</span></h1></div>';
    html += '<p class="route-sub">Cruise is obol on autopilot, hands-off but legal. It hands you a batch of the safe '
      + 'moves you can run right now, you run them on your own box and paste the output back, obol learns the new facts '
      + 'and hands you the next batch, round after round until flags. obol never runs anything itself, you review and run '
      + 'every command, and it always stops and asks before anything that lands a shell or sprays credentials.</p>';

    html += modeToggle(mode);
    html += loopStrip();

    var hasPlan = plan.batch.length || plan.checkpoint || plan.counts.ready;
    if (!eng || !hasPlan) {
      html += emptyState();
      html += recipesSection(facts, opts);
      return html + '</section>';
    }

    html += '<div class="cr-main">';
    html += phaseBand(plan);
    if (plan.batch.length) {
      html += '<ol class="cr-cmds">' + plan.batch.map(function (it, i) { return cmdRow(i + 1, it, facts, opts); }).join('') + '</ol>';
    } else {
      html += '<div class="cr-nobatch">No safe steps to batch right now. Your next move is the checkpoint below, run it when you are ready.</div>';
    }
    html += unlocksStrip(plan);
    html += checkpointCard(plan.checkpoint, facts, opts, mode);
    html += pastePanel();
    html += '</div>';

    html += recipesSection(facts, opts);
    return html + '</section>';
  }

  function download(name, text) {
    var blob = new Blob([text], { type: 'text/x-shellscript' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function currentCtx() {
    var eng = OBOL.store.active();
    return { eng: eng, facts: OBOL.store.factSet(), opts: optsFor(eng), mode: modeOf(eng), pack: OBOL.packs.actions() };
  }

  function setMode(m) {
    OBOL.store.update(function (eng) {
      eng.ui = eng.ui || {};
      eng.ui.cruiseMode = (m === 'lab') ? 'lab' : 'exam';
    }, 'cruise-mode');
    OBOL.router.render();
  }

  function mounted(ctx) {
    var mount = ctx.mount;

    U.on(mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    U.on(mount, 'click', '[data-cr-mode]', function (e, t) { e.preventDefault(); setMode(t.getAttribute('data-cr-mode')); });
    U.on(mount, 'click', '.cr-cp-lab', function (e) { e.preventDefault(); setMode('lab'); });

    U.on(mount, 'click', '.cr-dl', function (e) {
      e.preventDefault();
      var c = currentCtx();
      var plan = OBOL.cruise.plan(c.facts, c.pack, { mode: c.mode });
      if (!plan.batch.length) { U.toast('No batch to export', 'err'); return; }
      var script = OBOL.cruise.buildScript(plan.batch, { pack: c.pack, facts: c.facts, params: c.opts.params, profile: c.opts.profile, workspace: c.opts.workspace, mode: c.mode, phase: plan.phase });
      download('cruise-' + (plan.phase || 'batch') + '-' + c.mode + '.sh', script);
      U.toast('Exported cruise batch');
    });

    U.on(mount, 'click', '.cr-copyall', function (e) {
      e.preventDefault();
      var c = currentCtx();
      var plan = OBOL.cruise.plan(c.facts, c.pack, { mode: c.mode });
      var lines = plan.batch.map(function (it) { return fill(it.action, c.facts, c.opts, it.cmdIndex).filled; }).filter(Boolean);
      U.copy(lines.join('\n')).then(function (ok) { U.toast(ok ? (lines.length + ' commands copied') : 'Copy failed', ok ? '' : 'err'); });
    });

    U.on(mount, 'click', '.cr-recipe-dl', function (e, t) {
      e.preventDefault();
      var name = t.getAttribute('data-recipe');
      var pb = OBOL.playbooks.get(name);
      if (!pb) { U.toast('Recipe not found', 'err'); return; }
      var c = currentCtx();
      var batch = recipeBatch(pb);
      var script = OBOL.cruise.buildScript(batch, { pack: c.pack, facts: c.facts, params: c.opts.params, profile: c.opts.profile, workspace: c.opts.workspace, mode: c.mode, phase: pb.phase, name: pb.title });
      download('recipe-' + name + '.sh', script);
      U.toast('Exported ' + name + '.sh');
    });

    U.on(mount, 'click', '.cr-ingest', function (e) {
      e.preventDefault();
      var box = mount.querySelector('#cr-paste-box');
      var msg = mount.querySelector('.cr-paste-msg');
      var text = (box && box.value) || '';
      if (!text.trim()) { if (msg) { msg.textContent = 'Paste some output first.'; msg.className = 'cr-paste-msg err'; } return; }
      if (msg) { msg.textContent = 'Reading…'; msg.className = 'cr-paste-msg'; }
      var fin = function (r) {
        if (!r || !r.ok) { if (msg) { msg.textContent = 'Could not read that (' + ((r && r.reason) || 'error') + ').'; msg.className = 'cr-paste-msg err'; } return; }
        var added = (r.added != null) ? r.added : 0;
        U.toast(added ? ('Advanced: ' + added + ' new fact' + (added === 1 ? '' : 's')) : 'Read, no new facts');
        OBOL.router.render();
      };
      if (OBOL.ingest.ensureParsers) {
        OBOL.ingest.ensureParsers().then(function (okp) {
          var r;
          try {
            r = okp && OBOL.ingest.importSession ? OBOL.ingest.importSession(text, { target: 'auto', fileName: '' }) : null;
            if (r && r.ok && r.imported === 0) r = OBOL.ingest.run({ text: text, source: 'cruise' });
            else if (!r) r = OBOL.ingest.run({ text: text, source: 'cruise' });
          } catch (x) { try { r = OBOL.ingest.run({ text: text, source: 'cruise' }); } catch (y) { r = { ok: false, reason: (y && y.message) || 'error' }; } }
          fin(r);
        });
      } else {
        var r; try { r = OBOL.ingest.run({ text: text, source: 'cruise' }); } catch (x) { r = { ok: false, reason: (x && x.message) || 'error' }; }
        fin(r);
      }
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.cruise = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
