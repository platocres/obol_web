/*!
 * obol ui — routes/checklist.js — the attack-chain checklist: the FULL pack catalogue of EVERY command
 * obol has inventoried, grouped by phase (collapsible) then by the move the commands share (collapsible
 * sub-group), each command its own tickable row. Three signals per command: a manual tick (persisted),
 * a "ran" marker that grays a command obol detects in this engagement's Run Log, and a "needs: ..." hint
 * when a command still has unfilled tokens. Any command can be added to the Playbook, a slide-out builder
 * (right side) that generates a parameterized, logged bash script to run locally. Static, browser-local,
 * no execution: the script is a copy / download / save-to-Workspace artifact the human runs themselves.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr(s); }
  function ic(n) { return (OBOL.ic && OBOL.ic(n)) || ''; }

  // ---- persistence: collapse state (per phase / per move) + playbook open state, per engagement ----
  function engId() { return (OBOL.store && OBOL.store.activeId && OBOL.store.activeId()) || ''; }
  function openKey(id) { return 'obol.ck:' + engId() + ':' + id; }
  function isOpen(id, def) { try { var v = localStorage.getItem(openKey(id)); return v == null ? def : v === '1'; } catch (e) { return def; } }
  function pbOpen() { try { var v = localStorage.getItem('obol.pb.open:' + engId()); return v === '1'; } catch (e) { return false; } }
  function setPbOpen(on) { try { localStorage.setItem('obol.pb.open:' + engId(), on ? '1' : '0'); } catch (e) {} }

  function cmdsOf(a) { return (a.commands && a.commands.length) ? a.commands : [{ run: a.command, tool: a.tool }]; }

  // ---- the playbook builder (slide-out panel + floating toggle) ----
  function playbookPanel(eng, facts, params) {
    var pb = (eng && eng.playbook) || [];
    var pack = OBOL.packs.actions();
    var items = OBOL.playbook.resolve(pb, pack);
    var opts = { params: params, profile: eng && eng.profile, workspace: OBOL.workspace.tokens(eng) };
    var list = items.length ? items.map(function (it, i) {
      var r = OBOL.playbook.renderLine(it, facts, opts);
      return '<div class="pb-item" data-pbi="' + i + '"><span class="pb-n">' + (i + 1) + '</span>'
        + '<div class="pb-b"><div class="pb-t">' + esc(it.title) + '</div>'
        + '<code class="pb-c" data-copy="' + attr(r.run) + '" title="Click to copy this line">' + esc(r.run) + '</code></div>'
        + '<div class="pb-ops"><button type="button" data-pb-up="' + i + '" title="Move up" aria-label="Move up">&#9650;</button>'
        + '<button type="button" data-pb-down="' + i + '" title="Move down" aria-label="Move down">&#9660;</button>'
        + '<button type="button" class="pb-del" data-pb-del="' + i + '" title="Remove" aria-label="Remove">&#10005;</button></div></div>';
    }).join('') : '<div class="pb-empty">No commands yet. On the checklist, click the ' + ic('chain') + ' on any command to build a run order here, then generate a script.</div>';
    var foot = items.length
      ? '<div class="pb-foot"><button type="button" class="pb-gen" data-pb-copy>' + ic('clip') + ' Copy Script</button>'
        + '<button type="button" class="pb-gen ghost" data-pb-download>' + ic('download') + ' Download .sh</button>'
        + '<button type="button" class="pb-gen ghost" data-pb-save>Save To Workspace</button>'
        + '<button type="button" class="pb-gen ghost pb-clear" data-pb-clear>Clear</button></div>'
      : '';
    var open = pbOpen();
    var fab = open ? '' : '<button type="button" class="pb-fab" data-pb-toggle aria-expanded="false">' + ic('chain')
      + ' Playbook<span class="pb-fab-n">' + items.length + '</span></button>';
    return fab
      + '<aside class="pb-panel' + (open ? ' open' : '') + '" id="pb-panel" aria-label="Playbook builder">'
      + '<div class="pb-head"><span class="pb-title">Playbook</span><span class="pb-count">' + items.length + '</span>'
      + '<button type="button" class="pb-close" data-pb-toggle title="Close" aria-label="Close">&#10005;</button></div>'
      + '<div class="pb-sub">A run order you assemble. Generate a parameterized bash script (target, lhost, lport and creds fill from your sidebar params; logging built in).</div>'
      + '<div class="pb-list">' + list + '</div>' + foot + '</aside>';
  }

  function render() {
    var eng = OBOL.store.active();
    var facts = OBOL.store.factSet();
    var params = (eng && eng.params) || {};
    var ticks = (eng && eng.checkTicks) || {};
    var activities = (eng && eng.activities) || [];
    var pbSet = {}; ((eng && eng.playbook) || []).forEach(function (p) { pbSet[p.id + '#' + p.idx] = 1; });
    var pack = OBOL.packs.actions();
    var ws = OBOL.workspace.tokens(eng);

    var byPhase = {}; OBOL.phases.PHASES.forEach(function (p) { byPhase[p] = []; });
    pack.forEach(function (a) { (byPhase[OBOL.phases.phaseOfAction(a)] = byPhase[OBOL.phases.phaseOfAction(a)] || []).push(a); });

    var totalCmds = 0, doneCmds = 0, ranCmds = 0;
    pack.forEach(function (a) {
      var cs = cmdsOf(a);
      totalCmds += cs.length;
      for (var i = 0; i < cs.length; i++) { if (ticks[a.id + '#' + i]) doneCmds++; }
    });

    var html = '<section class="checklist">'
      + '<h1 class="route-h1">Checklist</h1>'
      + '<p class="route-sub">Every command obol has inventoried, grouped by attack-chain phase then by move. Tick a command when you run it; a command obol already saw in your Run Log is <span class="chk-ran-k">grayed</span>. Add any command to the <strong>Playbook</strong> (lower right) to build a runnable script. ' + totalCmds + ' commands across ' + pack.length + ' moves, ' + doneCmds + ' ticked.</p>';

    OBOL.phases.PHASES.forEach(function (p) {
      var moves = (byPhase[p] || []).slice().sort(function (a, b) { return b.priority - a.priority; });
      if (!moves.length) return;
      var phaseCmds = 0; moves.forEach(function (a) { phaseCmds += cmdsOf(a).length; });
      html += '<details class="chk-phase" data-ck="ph:' + p + '"' + (isOpen('ph:' + p, true) ? ' open' : '') + '>'
        + '<summary class="chk-phase-h"><span class="ph-chip ph-' + p + '">' + p + '</span>'
        + '<span class="chk-ph-n">' + moves.length + ' move' + (moves.length === 1 ? '' : 's') + ' &middot; ' + phaseCmds + ' command' + (phaseCmds === 1 ? '' : 's') + '</span></summary>'
        + '<div class="chk-phase-body">';

      moves.forEach(function (a) {
        var variants = OBOL.command.fillAll(a, facts, { params: params, profile: (eng && eng.profile), workspace: ws });
        var n = variants.length, moveDone = 0;
        for (var d = 0; d < n; d++) { if (ticks[a.id + '#' + d]) moveDone++; }
        var rows = variants.map(function (v, idx) {
          var filled = v.filled || '';
          var key = a.id + '#' + idx;
          var unfilled = filled ? OBOL.command.unfilledTokens(filled) : [];
          var ran = (activities.length && filled) ? OBOL.command.commandWasRun(filled, activities, params) : false;
          var on = !!ticks[key];
          var inPb = !!pbSet[key];
          var cmd = filled
            ? '<code class="chk-cmd ' + (unfilled.length ? 'chk-needs' : 'chk-ready') + '" data-copy="' + attr(filled)
              + '" title="' + (unfilled.length ? ('needs: ' + esc(unfilled.join(', '))) : 'Click to copy') + '">' + esc(filled) + '</code>'
            : '<span class="chk-nocmd">no command</span>';
          var note = (v.note || '') ? '<span class="chk-note">' + esc(v.note) + '</span>' : '';
          return '<div class="chk-row' + (on ? ' done' : '') + (ran ? ' ran' : '') + '">'
            + '<label class="chk-tick"><input type="checkbox" data-chk="' + attr(key) + '"' + (on ? ' checked' : '') + ' aria-label="Mark run"></label>'
            + cmd
            + '<div class="chk-row-r">' + (ran ? '<span class="chk-ran" title="obol detected this command in your Run Log">ran</span>' : '') + note
            + '<button type="button" class="chk-add' + (inPb ? ' on' : '') + '" data-pb-add="' + attr(key) + '" title="' + (inPb ? 'In the playbook' : 'Add to playbook') + '" aria-label="Add to playbook">' + ic('chain') + (inPb ? '<span class="chk-add-k">In</span>' : '') + '</button></div>'
            + '</div>';
        }).join('');
        html += '<details class="chk-move" data-ck="mv:' + esc(a.id) + '"' + (isOpen('mv:' + a.id, true) ? ' open' : '') + '>'
          + '<summary class="chk-move-h"><span class="chk-mv-t">' + esc(a.title) + '</span>'
          + '<span class="chk-mv-n">' + moveDone + '/' + n + '</span>'
          + '<button type="button" class="chk-addall" data-pb-addmove="' + attr(a.id) + '" title="Add every command in this move to the playbook">' + ic('chain') + ' All</button></summary>'
          + '<div class="chk-cmds">' + rows + '</div></details>';
      });
      html += '</div></details>';
    });

    html += playbookPanel(eng, facts, params);
    html += '</section>';
    return html;
  }

  // ---- store mutations (then re-render; the panel/collapse state lives in localStorage so it holds) ----
  function parseKey(k) { var i = String(k).lastIndexOf('#'); return { id: k.slice(0, i), idx: +k.slice(i + 1) }; }
  function togglePlaybook(key) {
    var pk = parseKey(key);
    OBOL.store.update(function (eng) {
      eng.playbook = eng.playbook || [];
      var at = -1; eng.playbook.forEach(function (p, i) { if (p.id === pk.id && p.idx === pk.idx) at = i; });
      if (at >= 0) eng.playbook.splice(at, 1); else eng.playbook.push({ id: pk.id, idx: pk.idx });
    }, 'playbook');
  }
  function addMove(id) {
    OBOL.store.update(function (eng) {
      eng.playbook = eng.playbook || [];
      var a = null, pack = OBOL.packs.actions(); for (var i = 0; i < pack.length; i++) { if (pack[i].id === id) { a = pack[i]; break; } }
      if (!a) return;
      var cs = cmdsOf(a);
      for (var j = 0; j < cs.length; j++) {
        var has = eng.playbook.some(function (p) { return p.id === id && p.idx === j; });
        if (!has) eng.playbook.push({ id: id, idx: j });
      }
    }, 'playbook');
  }
  function movePb(i, dir) {
    OBOL.store.update(function (eng) {
      var pb = eng.playbook || []; var j = i + dir; if (j < 0 || j >= pb.length) return;
      var t = pb[i]; pb[i] = pb[j]; pb[j] = t;
    }, 'playbook');
  }
  function delPb(i) { OBOL.store.update(function (eng) { (eng.playbook || []).splice(i, 1); }, 'playbook'); }
  function clearPb() { OBOL.store.update(function (eng) { eng.playbook = []; }, 'playbook'); }

  function currentScript() {
    var eng = OBOL.store.active() || {}, facts = OBOL.store.factSet();
    var items = OBOL.playbook.resolve(eng.playbook || [], OBOL.packs.actions());
    return OBOL.playbook.buildScript(items, { params: eng.params || {}, facts: facts, profile: eng.profile, workspace: OBOL.workspace.tokens(eng), name: eng.name || '' });
  }
  function downloadScript() {
    try {
      var eng = OBOL.store.active() || {};
      var stem = (String(eng.name || 'engagement').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'engagement');
      var blob = new Blob([currentScript()], { type: 'text/x-shellscript;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = 'obol-playbook-' + stem + '.sh';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { try { URL.revokeObjectURL(url); } catch (e) {} }, 1200);
      return true;
    } catch (e) { return false; }
  }
  function saveToWorkspace() {
    var text = currentScript(), rel = 'obol-playbook.sh';
    OBOL.store.update(function (eng) {
      eng.workspace = eng.workspace || {}; eng.workspace.overrides = eng.workspace.overrides || {};
      var added = eng.workspace.overrides.added = eng.workspace.overrides.added || [];
      var at = -1; added.forEach(function (x, i) { if (x && x.path === rel) at = i; });
      var rec = { path: rel, source: 'manual', at: Date.now(), content: text };
      if (at >= 0) added[at] = rec; else added.push(rec);
    }, 'ws');
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    if (!mount._ckBound) {
      mount._ckBound = true;
      U.on(mount, 'change', 'input[data-chk]', function (e, t) {
        var id = t.getAttribute('data-chk'), on = t.checked;
        OBOL.store.update(function (eng) { eng.checkTicks = eng.checkTicks || {}; if (on) eng.checkTicks[id] = true; else delete eng.checkTicks[id]; }, 'checklist');
        var row = t.closest('.chk-row'); if (row) row.classList.toggle('done', on);
        var mv = t.closest('.chk-move'); if (mv) { var n = mv.querySelectorAll('input[data-chk]').length, d = mv.querySelectorAll('input[data-chk]:checked').length, lbl = mv.querySelector('.chk-mv-n'); if (lbl) lbl.textContent = d + '/' + n; }
      });
      U.on(mount, 'click', '[data-copy]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
      });
      U.on(mount, 'click', '[data-pb-add]', function (e, t) { e.preventDefault(); e.stopPropagation(); togglePlaybook(t.getAttribute('data-pb-add')); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-addmove]', function (e, t) { e.preventDefault(); e.stopPropagation(); addMove(t.getAttribute('data-pb-addmove')); setPbOpen(true); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-toggle]', function (e, t) { e.preventDefault(); e.stopPropagation(); setPbOpen(!pbOpen()); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-up]', function (e, t) { e.preventDefault(); e.stopPropagation(); movePb(+t.getAttribute('data-pb-up'), -1); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-down]', function (e, t) { e.preventDefault(); e.stopPropagation(); movePb(+t.getAttribute('data-pb-down'), 1); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-del]', function (e, t) { e.preventDefault(); e.stopPropagation(); delPb(+t.getAttribute('data-pb-del')); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-clear]', function (e, t) { e.preventDefault(); e.stopPropagation(); clearPb(); OBOL.router.render(); });
      U.on(mount, 'click', '[data-pb-copy]', function (e, t) { e.preventDefault(); e.stopPropagation(); U.copy(currentScript()).then(function (ok) { U.toast(ok ? 'Script copied' : 'Copy failed', ok ? '' : 'err'); }); });
      U.on(mount, 'click', '[data-pb-download]', function (e, t) { e.preventDefault(); e.stopPropagation(); var ok = downloadScript(); U.toast(ok ? 'Downloaded playbook.sh' : 'Download failed', ok ? '' : 'err'); });
      U.on(mount, 'click', '[data-pb-save]', function (e, t) { e.preventDefault(); e.stopPropagation(); saveToWorkspace(); U.toast('Saved to Workspace: obol-playbook.sh'); });
    }
    // anchor the slide-out panel to the top of the content area (below the app header + context bar) so
    // those stay usable while the playbook is open; on narrow screens it falls back to a full-height drawer.
    var pn = mount.querySelector('#pb-panel');
    if (pn) {
      if (window.innerWidth > 860) {
        var top = Math.max(0, Math.round(mount.getBoundingClientRect().top));
        pn.style.top = top + 'px'; pn.style.height = (window.innerHeight - top) + 'px';
      } else { pn.style.top = ''; pn.style.height = ''; }
    }
    // persist each collapsible's open state (toggle does not bubble); bind once per node.
    Array.prototype.forEach.call(mount.querySelectorAll('details[data-ck]'), function (d) {
      if (d._ckToggle) return; d._ckToggle = true;
      d.addEventListener('toggle', function () { try { localStorage.setItem(openKey(d.getAttribute('data-ck')), d.open ? '1' : '0'); } catch (x) {} });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.checklist = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
