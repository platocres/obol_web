/*!
 * obol ui - routes/checklist.js - the attack-chain checklist: the FULL pack catalogue of EVERY command
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
  // command scope: "all" (every inventoried command) or "oscp" (hide out-of-scope / exam-illegal moves).
  function ckScope() { try { return localStorage.getItem('obol.ck.scope:' + engId()) === 'oscp' ? 'oscp' : 'all'; } catch (e) { return 'all'; } }
  function setCkScope(s) { try { localStorage.setItem('obol.ck.scope:' + engId(), s === 'oscp' ? 'oscp' : 'all'); } catch (e) {} }
  function inScope(id) { return !(OBOL.OSCP_SCOPE && OBOL.OSCP_SCOPE.exclude && OBOL.OSCP_SCOPE.exclude[id]); }

  function cmdsOf(a) { return (a.commands && a.commands.length) ? a.commands : [{ run: a.command, tool: a.tool }]; }

  // Build one shared resolution frame per render/interaction so filling N commands or playbook rows
  // reuses a single FactSet projection and credential lookup instead of scanning all facts per command.
  function makeRenderCtx() {
    var eng = OBOL.store.active();
    var rawFacts = OBOL.store.factSet();
    var params = (eng && eng.params) || {};
    var resolved = (OBOL.context && OBOL.context.resolve)
      ? OBOL.context.resolve({ engagement: eng, facts: rawFacts, params: params })
      : null;
    var facts = resolved ? resolved.facts : rawFacts;
    var ticks = (eng && eng.checkTicks) || {};
    var activities = (eng && eng.activities) || [];
    var pb = (eng && eng.playbook) || [];
    var pbSet = {};
    for (var i = 0; i < pb.length; i++) { pbSet[pb[i].id + '#' + pb[i].idx] = 1; }
    var ws = OBOL.workspace.tokens(eng);
    var fullPack = OBOL.packs.actions();
    var byId = {};
    for (var j = 0; j < fullPack.length; j++) { byId[fullPack[j].id] = fullPack[j]; }
    return {
      eng: eng,
      facts: facts,
      params: params,
      ticks: ticks,
      activities: activities,
      pb: pb,
      pbSet: pbSet,
      ws: ws,
      fullPack: fullPack,
      byId: byId,
      fillOpts: { params: params, profile: eng && eng.profile, workspace: ws },
    };
  }

  function renderPlaybookItemsHtml(items, ctx) {
    if (!items.length) {
      return '<div class="pb-empty">No commands yet. On the checklist, click the ' + ic('chain') + ' on any command to build a run order here, then generate a script.</div>';
    }
    return items.map(function (it, i) {
      var r = OBOL.playbook.renderLine(it, ctx.facts, ctx.fillOpts);
      return '<div class="pb-item" data-pbi="' + i + '"><span class="pb-n">' + (i + 1) + '</span>'
        + '<div class="pb-b"><div class="pb-t">' + esc(it.title) + '</div>'
        + '<code class="pb-c" data-copy="' + attr(r.run) + '" title="Click to copy this line">' + esc(r.run) + '</code></div>'
        + '<div class="pb-ops"><button type="button" data-pb-up="' + i + '" title="Move up" aria-label="Move up">&#9650;</button>'
        + '<button type="button" data-pb-down="' + i + '" title="Move down" aria-label="Move down">&#9660;</button>'
        + '<button type="button" class="pb-del" data-pb-del="' + i + '" title="Remove" aria-label="Remove">&#10005;</button></div></div>';
    }).join('');
  }

  // ---- the playbook builder (slide-out panel + floating toggle, both persistent in DOM for 0ms toggles) ----
  function playbookPanel(ctx) {
    var items = OBOL.playbook.resolve(ctx.pb, ctx.fullPack);
    var list = renderPlaybookItemsHtml(items, ctx);
    var open = pbOpen();
    var foot = '<div class="pb-foot" id="pb-foot"' + (items.length ? '' : ' hidden') + '>'
      + '<button type="button" class="pb-gen" data-pb-copy>' + ic('clip') + ' Copy Script</button>'
      + '<button type="button" class="pb-gen ghost" data-pb-download>' + ic('download') + ' Download .sh</button>'
      + '<button type="button" class="pb-gen ghost" data-pb-save>Save To Workspace</button>'
      + '<button type="button" class="pb-gen ghost pb-clear" data-pb-clear>Clear</button></div>';
    var fab = '<button type="button" class="pb-fab" id="pb-fab" data-pb-toggle aria-controls="pb-panel" aria-expanded="' + (open ? 'true' : 'false') + '"' + (open ? ' hidden' : '') + '>' + ic('chain')
      + ' Playbook<span class="pb-fab-n">' + items.length + '</span></button>';
    return fab
      + '<aside class="pb-panel' + (open ? ' open' : '') + '" id="pb-panel" aria-label="Playbook builder" aria-hidden="' + (open ? 'false' : 'true') + '">'
      + '<div class="pb-head"><span class="pb-title">Playbook</span><span class="pb-count">' + items.length + '</span>'
      + '<button type="button" class="pb-close" data-pb-toggle title="Close" aria-label="Close">&#10005;</button></div>'
      + '<div class="pb-sub">A run order you assemble. Generate a parameterized bash script (target, lhost, lport and creds fill from your sidebar params; logging built in).</div>'
      + '<div class="pb-list">' + list + '</div>' + foot + '</aside>';
  }

  function renderMoveRows(a, ctx) {
    var variants = OBOL.command.fillAll(a, ctx.facts, ctx.fillOpts);
    var hasActs = ctx.activities.length > 0;
    return variants.map(function (v, idx) {
      var filled = v.filled || '';
      var key = a.id + '#' + idx;
      var unfilled = filled ? OBOL.command.unfilledTokens(filled) : [];
      var ran = (hasActs && filled) ? OBOL.command.commandWasRun(filled, ctx.activities, ctx.params) : false;
      var on = !!ctx.ticks[key];
      var inPb = !!ctx.pbSet[key];
      var cmd = filled
        ? '<code class="chk-cmd ' + (unfilled.length ? 'chk-needs' : 'chk-ready') + '" data-copy="' + attr(filled)
          + '" title="' + (unfilled.length ? ('needs: ' + esc(unfilled.join(', '))) : 'Click to copy') + '">' + esc(filled) + '</code>'
        : '<span class="chk-nocmd">no command</span>';
      var note = (v.note || '') ? '<span class="chk-note">' + esc(v.note) + '</span>' : '';
      return '<div class="chk-row' + (on ? ' done' : '') + (ran ? ' ran' : '') + '">'
        + '<label class="chk-tick"><input type="checkbox" data-chk="' + attr(key) + '"' + (on ? ' checked' : '') + ' aria-label="Mark run"></label>'
        + cmd
        + '<div class="chk-row-r">' + (ran ? '<span class="chk-ran" title="OBOL detected this command in your Run Log">ran</span>' : '') + note
        + '<button type="button" class="chk-add' + (inPb ? ' on' : '') + '" data-pb-add="' + attr(key) + '" title="' + (inPb ? 'In the playbook' : 'Add to playbook') + '" aria-label="Add to playbook">' + ic('chain') + (inPb ? '<span class="chk-add-k">In</span>' : '') + '</button></div>'
        + '</div>';
    }).join('');
  }

  function hydrateMoveEl(moveEl, ctx) {
    if (!moveEl || !moveEl.hasAttribute || !moveEl.hasAttribute('data-cmds-lazy')) return;
    var id = moveEl.getAttribute('data-move-id');
    var c = ctx || makeRenderCtx();
    var a = c.byId[id];
    var box = moveEl.querySelector('.chk-cmds');
    if (a && box) box.innerHTML = renderMoveRows(a, c);
    moveEl.removeAttribute('data-cmds-lazy');
  }

  function render() {
    var ctx = makeRenderCtx();
    var ticks = ctx.ticks;
    var fullPack = ctx.fullPack;
    var scope = ckScope();
    var pack = scope === 'oscp' ? fullPack.filter(function (a) { return inScope(a.id); }) : fullPack;
    var hidden = fullPack.length - pack.length;

    var byPhase = {}; OBOL.phases.PHASES.forEach(function (p) { byPhase[p] = []; });
    pack.forEach(function (a) { (byPhase[OBOL.phases.phaseOfAction(a)] = byPhase[OBOL.phases.phaseOfAction(a)] || []).push(a); });

    var totalCmds = 0, doneCmds = 0;
    pack.forEach(function (a) {
      var cs = cmdsOf(a);
      totalCmds += cs.length;
      for (var i = 0; i < cs.length; i++) { if (ticks[a.id + '#' + i]) doneCmds++; }
    });

    var toggle = '<div class="chk-tools">'
      + '<button type="button" class="chk-xa" data-ckall="collapse" title="Collapse every phase and move">Collapse All</button>'
      + '<button type="button" class="chk-xa" data-ckall="expand" title="Expand every phase and move">Expand All</button>'
      + '<div class="chk-scope" role="group" aria-label="Command scope"><span class="mini-label">Show</span>'
      + '<button type="button" class="cks-btn' + (scope === 'all' ? ' active' : '') + '" data-ckscope="all">All</button>'
      + '<button type="button" class="cks-btn' + (scope === 'oscp' ? ' active' : '') + '" data-ckscope="oscp">OSCP</button></div></div>';

    var scopeNote = scope === 'oscp'
      ? ' <span class="chk-scope-note">OSCP view: hiding ' + hidden + ' moves that are out of the PEN-200 exam scope or exam-illegal.</span>'
      : '';
    var html = '<section class="checklist">'
      + '<div class="chk-top"><h1 class="route-h1">Checklist</h1>' + toggle + '</div>'
      + '<p class="route-sub">Every command OBOL has inventoried, grouped by attack-chain phase then by move. Tick a command when you run it; a command OBOL already saw in your Run Log is <span class="chk-ran-k">grayed</span>. Add any command to the <strong>Playbook</strong> (lower right) to build a runnable script. ' + totalCmds + ' commands across ' + pack.length + ' moves, <span id="chk-done-n">' + doneCmds + '</span> ticked.' + scopeNote + '</p>';

    var railItems = [];
    OBOL.phases.PHASES.forEach(function (p) {
      var moves = (byPhase[p] || []).slice().sort(function (a, b) { return b.priority - a.priority; });
      if (!moves.length) return;
      var phaseCmds = 0; moves.forEach(function (a) { phaseCmds += cmdsOf(a).length; });
      railItems.push({ p: p, moves: moves.length, cmds: phaseCmds });
      var phOpen = isOpen('ph:' + p, false);
      html += '<details class="chk-phase cri-' + p + '" data-ck="ph:' + p + '"' + (phOpen ? ' open' : '') + '>'
        + '<summary class="chk-phase-h"><span class="ph-chip ph-' + p + '">' + p + '</span>'
        + '<span class="chk-ph-n">' + moves.length + ' move' + (moves.length === 1 ? '' : 's') + ' &middot; ' + phaseCmds + ' command' + (phaseCmds === 1 ? '' : 's') + '</span></summary>'
        + '<div class="chk-phase-body">';

      moves.forEach(function (a) {
        var cs = cmdsOf(a), n = cs.length, moveDone = 0;
        for (var d = 0; d < n; d++) { if (ticks[a.id + '#' + d]) moveDone++; }
        var mvOpen = isOpen('mv:' + a.id, false);
        // Only fill and render command rows for moves that are actually open; closed moves hydrate on toggle.
        var rows = mvOpen ? renderMoveRows(a, ctx) : '';
        html += '<details class="chk-move" data-ck="mv:' + esc(a.id) + '" data-move-id="' + attr(a.id) + '"' + (mvOpen ? ' open' : ' data-cmds-lazy="1"') + '>'
          + '<summary class="chk-move-h"><span class="chk-mv-t">' + esc(a.title) + '</span>'
          + '<span class="chk-mv-n">' + moveDone + '/' + n + '</span>'
          + '<button type="button" class="chk-addall" data-pb-addmove="' + attr(a.id) + '" title="Add every command in this move to the playbook">' + ic('chain') + ' All</button></summary>'
          + '<div class="chk-cmds">' + rows + '</div></details>';
      });
      html += '</div></details>';
    });

    html += phaseRail(railItems);
    html += playbookPanel(ctx);
    html += '</section>';
    return html;
  }

  // a sticky left rail to jump between phases: a collapsed tab that expands to the phase list. Teal
  // neon glass, a hue no phase pill uses, so it reads as navigation chrome, not another phase.
  function railOpen() { try { return localStorage.getItem('obol.ck.rail:' + engId()) === '1'; } catch (e) { return false; } }
  function setRailOpen(on) { try { localStorage.setItem('obol.ck.rail:' + engId(), on ? '1' : '0'); } catch (e) {} }
  function phaseRail(items) {
    if (!items.length) return '';
    var open = railOpen();
    var list = items.map(function (it) {
      return '<button type="button" class="chk-rail-item cri-' + it.p + '" data-jump="ph:' + it.p + '">'
        + '<span class="chk-rail-l">' + it.p + '</span>'
        + '<span class="chk-rail-n">' + it.moves + '</span></button>';
    }).join('');
    return '<div class="chk-rail' + (open ? ' open' : '') + '" id="chk-rail">'
      + '<button type="button" class="chk-rail-tab" data-rail-toggle aria-label="Jump to phase" title="Jump to phase">' + ic('branch') + '<span class="chk-rail-tabt">Phases</span></button>'
      + '<div class="chk-rail-panel"><div class="chk-rail-h"><span>Jump To Phase</span>'
      + '<button type="button" class="chk-rail-x" data-rail-toggle aria-label="Close" title="Close">&#10005;</button></div>'
      + '<div class="chk-rail-list">' + list + '</div></div></div>';
  }

  // ---- store mutations (updated surgically in-place without tearing down the 1,900-row checklist) ----
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

  // Batch DOM reads before DOM writes so positioning the drawer + phase rail never causes layout thrashing.
  function anchorChrome(mount, onlyPanel) {
    var pn = mount.querySelector('#pb-panel');
    var rail = onlyPanel ? null : mount.querySelector('#chk-rail');
    if (!pn && !rail) return;
    var winW = (typeof window !== 'undefined' && window.innerWidth) || 0;
    var winH = (typeof window !== 'undefined' && window.innerHeight) || 0;
    var wide = winW > 860;
    var viewEl = (typeof document !== 'undefined' && document.getElementById('view')) || mount.firstElementChild || mount;
    var rect = (wide && viewEl && viewEl.getBoundingClientRect) ? viewEl.getBoundingClientRect() : null;
    if (pn) {
      if (wide && rect) {
        var top = Math.max(0, Math.round(rect.top));
        pn.style.top = top + 'px';
        pn.style.height = Math.max(0, winH - top) + 'px';
      } else {
        pn.style.top = '';
        pn.style.height = '';
      }
    }
    if (rail) {
      if (wide && rect) {
        rail.style.left = Math.max(0, Math.round(rect.left)) + 'px';
      } else {
        rail.style.left = '';
      }
    }
  }

  function syncPlaybookOpen(mount, open) {
    var pn = mount.querySelector('#pb-panel');
    var fab = mount.querySelector('.pb-fab');
    var active = (typeof document !== 'undefined' && document.activeElement) || null;
    if (open) {
      anchorChrome(mount, true);
      if (pn) {
        pn.classList.add('open');
        pn.setAttribute('aria-hidden', 'false');
      }
      var fabFocused = !!(fab && active === fab);
      if (fab) {
        fab.setAttribute('aria-expanded', 'true');
        fab.hidden = true;
      }
      if (fabFocused && pn) {
        var closeBtn = pn.querySelector('.pb-close');
        if (closeBtn && closeBtn.focus) { try { closeBtn.focus({ preventScroll: true }); } catch (e) {} }
      }
    } else {
      var pnFocused = !!(pn && active && pn.contains && pn.contains(active));
      if (fab) {
        fab.hidden = false;
        fab.setAttribute('aria-expanded', 'false');
      }
      if (pnFocused && fab && fab.focus) {
        try { fab.focus({ preventScroll: true }); } catch (e) {}
      }
      if (pn) {
        pn.classList.remove('open');
        pn.setAttribute('aria-hidden', 'true');
      }
    }
  }

  function syncAddButton(btn, inPb) {
    if (!btn) return;
    var wasOn = btn.classList.contains('on');
    if (wasOn === inPb) return;
    btn.classList.toggle('on', inPb);
    btn.setAttribute('title', inPb ? 'In the playbook' : 'Add to playbook');
    var badge = btn.querySelector('.chk-add-k');
    if (inPb && !badge && typeof document !== 'undefined') {
      var sp = document.createElement('span');
      sp.className = 'chk-add-k';
      sp.textContent = 'In';
      btn.appendChild(sp);
    } else if (!inPb && badge && badge.parentNode) {
      badge.parentNode.removeChild(badge);
    }
  }

  function syncPlaybookUI(mount) {
    var ctx = makeRenderCtx();
    var items = OBOL.playbook.resolve(ctx.pb, ctx.fullPack);
    var countStr = String(items.length);
    var fabCount = mount.querySelector('.pb-fab-n');
    if (fabCount) fabCount.textContent = countStr;
    var headCount = mount.querySelector('.pb-count');
    if (headCount) headCount.textContent = countStr;
    var listEl = mount.querySelector('.pb-list');
    if (listEl) listEl.innerHTML = renderPlaybookItemsHtml(items, ctx);
    var footEl = mount.querySelector('#pb-foot');
    if (footEl) footEl.hidden = !items.length;
    var btns = mount.querySelectorAll('button.chk-add[data-pb-add]');
    for (var i = 0; i < btns.length; i++) {
      var k = btns[i].getAttribute('data-pb-add');
      syncAddButton(btns[i], !!ctx.pbSet[k]);
    }
    syncPlaybookOpen(mount, pbOpen());
  }

  function recountDoneCmds() {
    var eng = OBOL.store.active();
    var ticks = (eng && eng.checkTicks) || {};
    var scope = ckScope();
    var fullPack = OBOL.packs.actions();
    var pack = scope === 'oscp' ? fullPack.filter(function (a) { return inScope(a.id); }) : fullPack;
    var done = 0;
    for (var i = 0; i < pack.length; i++) {
      var a = pack[i], cs = cmdsOf(a);
      for (var j = 0; j < cs.length; j++) { if (ticks[a.id + '#' + j]) done++; }
    }
    return done;
  }

  function currentScript() {
    var ctx = makeRenderCtx();
    var items = OBOL.playbook.resolve(ctx.pb, ctx.fullPack);
    return OBOL.playbook.buildScript(items, { params: ctx.params, facts: ctx.facts, profile: ctx.eng && ctx.eng.profile, workspace: ctx.ws, name: (ctx.eng && ctx.eng.name) || '' });
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
      U.on(mount, 'click', '[data-ckscope]', function (e, t) { e.preventDefault(); e.stopPropagation(); setCkScope(t.getAttribute('data-ckscope')); OBOL.router.render(); });
      // collapse / expand every phase and move at once (hydrate lazy moves once with a shared context, no re-render)
      U.on(mount, 'click', '[data-ckall]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        var want = t.getAttribute('data-ckall') === 'expand';
        if (want) {
          var sharedCtx = makeRenderCtx();
          mount._bulkHydrateCtx = sharedCtx;
          Array.prototype.forEach.call(mount.querySelectorAll('details.chk-move[data-cmds-lazy]'), function (mv) {
            hydrateMoveEl(mv, sharedCtx);
          });
        }
        Array.prototype.forEach.call(mount.querySelectorAll('details[data-ck]'), function (d) {
          d.open = want; try { localStorage.setItem(openKey(d.getAttribute('data-ck')), want ? '1' : '0'); } catch (x) {}
        });
        Promise.resolve().then(function () { mount._bulkHydrateCtx = null; });
      });
      // phase jump rail: toggle open/closed; jump to a phase (open it + scroll it into view)
      U.on(mount, 'click', '[data-rail-toggle]', function (e, t) { e.preventDefault(); e.stopPropagation(); setRailOpen(!railOpen()); var r = mount.querySelector('#chk-rail'); if (r) r.classList.toggle('open', railOpen()); });
      U.on(mount, 'click', '[data-jump]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        var key = t.getAttribute('data-jump');
        var ph = mount.querySelector('details[data-ck="' + key + '"]');
        if (ph) { ph.open = true; try { localStorage.setItem(openKey(key), '1'); } catch (x) {} try { ph.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (y) { ph.scrollIntoView(); } }
      });
      U.on(mount, 'change', 'input[data-chk]', function (e, t) {
        var id = t.getAttribute('data-chk'), on = t.checked;
        OBOL.store.update(function (eng) { eng.checkTicks = eng.checkTicks || {}; if (on) eng.checkTicks[id] = true; else delete eng.checkTicks[id]; }, 'checklist');
        var row = t.closest('.chk-row'); if (row) row.classList.toggle('done', on);
        var mv = t.closest('.chk-move'); if (mv) { var n = mv.querySelectorAll('input[data-chk]').length, d = mv.querySelectorAll('input[data-chk]:checked').length, lbl = mv.querySelector('.chk-mv-n'); if (lbl) lbl.textContent = d + '/' + n; }
        var doneEl = mount.querySelector('#chk-done-n'); if (doneEl) doneEl.textContent = String(recountDoneCmds());
      });
      U.on(mount, 'click', '[data-copy]', function (e, t) {
        e.preventDefault(); e.stopPropagation();
        U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
      });
      U.on(mount, 'click', '[data-pb-add]', function (e, t) { e.preventDefault(); e.stopPropagation(); togglePlaybook(t.getAttribute('data-pb-add')); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-addmove]', function (e, t) { e.preventDefault(); e.stopPropagation(); addMove(t.getAttribute('data-pb-addmove')); setPbOpen(true); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-toggle]', function (e, t) { e.preventDefault(); e.stopPropagation(); var next = !pbOpen(); setPbOpen(next); syncPlaybookOpen(mount, next); });
      U.on(mount, 'click', '[data-pb-up]', function (e, t) { e.preventDefault(); e.stopPropagation(); movePb(+t.getAttribute('data-pb-up'), -1); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-down]', function (e, t) { e.preventDefault(); e.stopPropagation(); movePb(+t.getAttribute('data-pb-down'), 1); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-del]', function (e, t) { e.preventDefault(); e.stopPropagation(); delPb(+t.getAttribute('data-pb-del')); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-clear]', function (e, t) { e.preventDefault(); e.stopPropagation(); clearPb(); syncPlaybookUI(mount); });
      U.on(mount, 'click', '[data-pb-copy]', function (e, t) { e.preventDefault(); e.stopPropagation(); U.copy(currentScript()).then(function (ok) { U.toast(ok ? 'Script copied' : 'Copy failed', ok ? '' : 'err'); }); });
      U.on(mount, 'click', '[data-pb-download]', function (e, t) { e.preventDefault(); e.stopPropagation(); var ok = downloadScript(); U.toast(ok ? 'Downloaded playbook.sh' : 'Download failed', ok ? '' : 'err'); });
      U.on(mount, 'click', '[data-pb-save]', function (e, t) { e.preventDefault(); e.stopPropagation(); saveToWorkspace(); U.toast('Saved to Workspace: obol-playbook.sh'); });
      // Pre-hydrate lazy move rows synchronously on summary click before <details> paints open (zero empty-frame flash).
      U.on(mount, 'click', 'summary.chk-move-h', function (e, t) {
        var mv = t && t.parentNode;
        if (mv && !mv.open && mv.hasAttribute && mv.hasAttribute('data-cmds-lazy')) {
          hydrateMoveEl(mv);
        }
      });
      // Single capture-phase toggle listener handles all 360+ <details data-ck> disclosures and programmatic d.open = true.
      if (mount.addEventListener) {
        mount.addEventListener('toggle', function (e) {
          var d = e && e.target;
          if (!d || !d.getAttribute) return;
          var ck = d.getAttribute('data-ck');
          if (!ck) return;
          try { localStorage.setItem(openKey(ck), d.open ? '1' : '0'); } catch (x) {}
          if (d.open && d.hasAttribute && d.hasAttribute('data-cmds-lazy')) {
            hydrateMoveEl(d, mount._bulkHydrateCtx || makeRenderCtx());
          }
        }, true);
      }
    }
    anchorChrome(mount, false);
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.checklist = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
