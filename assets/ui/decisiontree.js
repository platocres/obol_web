/*!
 * obol ui - decisiontree.js - OBOL.decisionTreeView
 *
 * The left-to-right DECISION MAP renderer for the by-port forest (OBOL.decisionMap.decisionTree). One
 * reusable component, mounted wherever a port-rooted decision view is wanted (the Learn by-port view
 * now; the target view and an engagement-wide forest later). Self-contained: own pan/zoom/wheel, own
 * semantic LOD (labels resolve as you zoom in), own tidy LTR layout, service-family color coding,
 * port + service filter chips, and collapsible subtrees. No dependencies beyond OBOL.decisionMap + OBOL.ic.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var ic = function (n, c) { return (OBOL.ic ? OBOL.ic(n, c) : ''); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (m) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[m]; }); }
  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var COLX = 204, ROWY = 28, NW = 178, NH = 22, PAD = 24;

  // ---- layout: a tidy left-to-right tree over the forest (scan -> ports -> moves -> hand-off leaves) ----
  function layout(forest, state) {
    var nodes = [], edges = [], rowCursor = { y: 0 };
    var collapsed = state.collapsed || {};

    var nodeById = {};
    var tree = buildModel(forest, state);
    (function walk(node, depth) {
      var kids = node.children || [];
      var isCollapsed = collapsed[node.id] && kids.length;
      var y;
      if (!kids.length || isCollapsed) { y = rowCursor.y * ROWY + PAD; rowCursor.y += 1; }
      else { var ys = kids.map(function (k) { return walk(k, depth + 1); }); y = (ys[0] + ys[ys.length - 1]) / 2; }
      var x = PAD + depth * COLX;
      var n = { id: node.id, label: node.label, kind: node.kind, lane: node.lane || '', fam: node.fam || node.lane || '', spine: !!node.spine,
        meta: node.meta || '', x: x, y: y, cx: x + NW / 2, cy: y + NH / 2,
        hasKids: kids.length > 0, collapsed: !!isCollapsed, count: kids.length, children: kids };
      nodeById[node.id] = n; nodes.push(n);
      return y;
    })(tree, 0);

    nodes.forEach(function (n) {
      if (n.collapsed) return;
      (n.children || []).forEach(function (k) {
        var kn = nodeById[k.id]; if (!kn) return;
        edges.push({ x1: n.x + NW, y1: n.cy, x2: kn.x, y2: kn.cy, spine: n.spine && kn.spine, fam: kn.fam || n.fam || '' });
      });
    });
    var maxX = 0, maxY = 0;
    nodes.forEach(function (n) { maxX = Math.max(maxX, n.x + NW); maxY = Math.max(maxY, n.y + NH); });
    return { nodes: nodes, edges: edges, width: maxX + PAD, height: maxY + PAD, byId: nodeById };
  }

  function buildModel(forest, state) {
    var want = state.ports && state.ports.length ? state.ports : null;
    var portNodes = forest.ports
      .filter(function (p) { return !want || want.indexOf(p.key) >= 0; })
      .map(function (p) {
        var spine = {}; (p.spine || []).forEach(function (id) { spine[id] = 1; });
        var fam = p.fam || '';
        function moveNode(id) {
          var n = p.nodes[id];
          var kids = (n.children || []).map(moveNode);
          (n.handoffs || []).forEach(function (h) { kids.push({ id: p.key + ':ho:' + h.fact, label: '-> ' + h.label, kind: 'handoff', lane: 'access', fam: 'access', children: [] }); });
          return { id: id, label: n.title, kind: 'move', lane: n.laneKey || laneOf(n), fam: fam || n.laneKey || '', spine: !!spine[id], meta: n.fork || '', children: kids };
        }
        return { id: 'port:' + p.key, label: (p.port ? p.port + '  ' : '') + p.label, kind: 'port', lane: fam, fam: fam,
          spine: true, children: (p.roots || []).map(moveNode) };
      });
    return { id: 'scan', label: 'Port scan', kind: 'scan', fam: 'recon', spine: true, children: portNodes };
  }
  function laneOf(n) { return (n && n.laneKey) || ''; }

  // ---- svg ----
  function nodeSvg(n) {
    var cls = 'dt-node dt-' + n.kind + (n.lane ? ' lane-' + n.lane : '') + (n.fam ? ' dt-fam-' + n.fam : '') + (n.spine ? ' dt-spine' : '') + (n.collapsed ? ' dt-folded' : '');
    var label = n.collapsed ? (n.label + '  (+' + n.count + ')') : n.label;
    var caret = n.hasKids ? '<circle class="dt-caret" cx="' + (n.x + NW - 10) + '" cy="' + n.cy + '" r="7"/>'
      + '<text class="dt-caret-t" x="' + (n.x + NW - 10) + '" y="' + (n.cy + 3.5) + '">' + (n.collapsed ? '+' : '-') + '</text>' : '';
    return '<g class="' + cls + '" data-dtnode="' + esc(n.id) + '" data-cx="' + n.cx + '" data-cy="' + n.cy + '" data-kind="' + n.kind + '">'
      + '<rect class="dt-box" x="' + n.x + '" y="' + n.y + '" width="' + NW + '" height="' + NH + '" rx="5"/>'
      + '<text class="dt-label" x="' + (n.x + 8) + '" y="' + (n.cy + 4) + '">' + esc(label.length > 27 ? label.slice(0, 26) + '...' : label) + '</text>'
      + caret + '</g>';
  }
  function edgeD(e) {
    var mx = (e.x1 + e.x2) / 2;
    return 'M' + e.x1 + ',' + e.y1 + ' C' + mx + ',' + e.y1 + ' ' + mx + ',' + e.y2 + ' ' + e.x2 + ',' + e.y2;
  }
  function buildSvg(lay) {
    var edges = lay.edges.map(function (e) {
      return '<path class="dt-edge' + (e.spine ? ' dt-edge-spine' : '') + (e.fam ? ' dt-edge-fam-' + e.fam : '') + '" d="' + edgeD(e) + '"/>';
    }).join('');
    var nodes = lay.nodes.map(nodeSvg).join('');
    return '<svg id="dt-view" class="dt-view" data-w="' + lay.width + '" data-h="' + lay.height + '" width="' + lay.width + '" height="' + lay.height + '" viewBox="0 0 ' + lay.width + ' ' + lay.height + '">'
      + '<g class="dt-edges">' + edges + '</g><g class="dt-nodes">' + nodes + '</g></svg>';
  }

  // ---- controls ----
  function shortPortLabel(p) {
    if (p.short) return p.short;
    var pt = String(p.port || '').split('/')[0];
    var lbl = String(p.label || '').split(',')[0].replace(/\s*\(.*?\)/g, '').trim();
    return pt ? (pt + ' ' + lbl) : lbl;
  }

  function chips(forest, state) {
    var want = state.ports || [];
    var resetBtn = want.length ? '<button type="button" class="dt-chip-reset" data-dt="clear-ports">All Ports</button>' : '';
    return resetBtn + forest.ports.map(function (p) {
      var on = want.indexOf(p.key) >= 0;
      var famCls = p.fam ? (' dt-chip-fam-' + p.fam) : '';
      return '<button type="button" class="dt-chip' + famCls + (on ? ' on' : '') + '" data-dt-chip="' + esc(p.key) + '" title="' + esc((p.port ? p.port + ' - ' : '') + p.label) + '">'
        + '<span class="dt-chip-port">' + esc(shortPortLabel(p)) + '</span>'
        + '</button>';
    }).join('');
  }
  function controls(forest, state) {
    return '<div class="dt-bar">'
      + '<button type="button" class="dt-btn dt-btn-cards" data-dt="cards">' + ic('box') + ' Cards View</button>'
      + '<div class="dt-zoom"><button type="button" class="dt-btn" data-dt="out" title="Zoom out">-</button>'
      + '<button type="button" class="dt-btn" data-dt="fit" title="Fit map to view">Fit</button>'
      + '<button type="button" class="dt-btn" data-dt="in" title="Zoom in">+</button>'
      + '<button type="button" class="dt-btn" data-dt="collapse">Collapse</button>'
      + '<button type="button" class="dt-btn" data-dt="expand">Expand all</button></div>'
      + '<div class="dt-filter"><span class="dt-filter-l">Filter by Port &amp; Service</span><div class="dt-filter-chips">' + chips(forest, state) + '</div></div>'
      + '</div>';
  }
  function legend() {
    return '<div class="dt-legend">'
      + '<span class="dt-lg dt-lg-spine">Primary recommended path</span>'
      + '<span class="dt-lg dt-lg-handoff">-&gt; Hand-off to post-foothold lane</span>'
      + '<span class="dt-lg">Click any move to study it · Click + / - or a port chip to focus its tree</span>'
      + '</div>';
  }

  // Compute smart default collapsed state when viewing all ports unfiltered so the initial Fit zoom is readable
  function defaultCollapsedForForest(forest) {
    var col = {};
    (forest.ports || []).forEach(function (p) {
      // Keep the port node itself open so its 1st-level entry moves show, but fold deep branches under entry moves
      // when the port has many moves (e.g., 80/443 HTTP, 135/445 SMB, 389 LDAP) so initial Fit zoom stays legible
      var moveCount = (p.order || []).length;
      if (moveCount > 6) {
        (p.roots || []).forEach(function (rid) {
          var rn = p.nodes && p.nodes[rid];
          if (rn && ((rn.children && rn.children.length) || (rn.handoffs && rn.handoffs.length))) {
            col[rid] = true;
          }
        });
      }
    });
    return col;
  }

  // ---- mount + wire ----
  function mount(el, opts) {
    opts = opts || {};
    function resolveFacts() {
      if (opts && opts.facts) return opts.facts;
      if (OBOL.state && typeof OBOL.state.facts === 'function') return OBOL.state.facts();
      if (OBOL.store && typeof OBOL.store.factSet === 'function') return OBOL.store.factSet();
      return null;
    }
    var forest0 = OBOL.decisionMap.decisionTree({ ports: null, facts: resolveFacts() });
    var initPorts = (opts.ports || (lsGet('obol.dt.ports', '') ? lsGet('obol.dt.ports').split(',').filter(Boolean) : []));
    var state = {
      ports: initPorts,
      lens: 'methodology',
      collapsed: initPorts.length ? {} : defaultCollapsedForForest(forest0),
    };
    var pz = { k: 1, tx: 0, ty: 0 }, fitted = false;

    function render() {
      var curFacts = resolveFacts();
      var forest = state.ports.length ? OBOL.decisionMap.decisionTree({ ports: state.ports, facts: curFacts }) : OBOL.decisionMap.decisionTree({ ports: null, facts: curFacts });
      var lay = layout(forest, state);
      el.innerHTML = controls(forest0, state)
        + '<div class="dt-stage" id="dt-stage" data-lens="methodology" tabindex="0" role="group" aria-label="Port decision map, pan and zoom">'
        + '<div class="dt-pan" id="dt-pan">' + buildSvg(lay) + '</div>'
        + '<div class="dt-hover" id="dt-hover" hidden></div>'
        + legend() + '</div>';
      wire(lay, forest);
    }

    function wire(lay) {
      var stage = el.querySelector('#dt-stage'), pan = el.querySelector('#dt-pan'), hover = el.querySelector('#dt-hover');
      var W = lay.width, H = lay.height;
      function apply() {
        pan.style.transform = 'translate(' + pz.tx + 'px,' + pz.ty + 'px) scale(' + pz.k + ')';
        stage.setAttribute('data-lod', pz.k < 0.32 ? 'far' : (pz.k < 0.75 ? 'mid' : 'near'));
      }
      function fit() {
        var r = stage.getBoundingClientRect();
        var k = Math.min((r.width - 24) / W, (r.height - 28) / H, 1.15);
        k = Math.max(k, 0.25);
        pz = { k: k, tx: Math.max(12, (r.width - W * k) / 2), ty: 14 };
        apply();
      }
      function zoomAround(mx, my, f) { var nk = Math.max(0.18, Math.min(2.6, pz.k * f)), ratio = nk / pz.k; pz.tx = mx - (mx - pz.tx) * ratio; pz.ty = my - (my - pz.ty) * ratio; pz.k = nk; apply(); }
      if (!fitted) { fit(); fitted = true; } else apply();

      var down = null, moved = false;
      stage.addEventListener('pointerdown', function (e) { var g = e.target.closest && e.target.closest('.dt-node'); down = { x: e.clientX, y: e.clientY, tx: pz.tx, ty: pz.ty, node: g }; moved = false; try { stage.setPointerCapture(e.pointerId); } catch (x) {} });
      stage.addEventListener('pointermove', function (e) {
        if (down) { var dx = e.clientX - down.x, dy = e.clientY - down.y; if (Math.abs(dx) + Math.abs(dy) > 4) moved = true; pz.tx = down.tx + dx; pz.ty = down.ty + dy; apply(); if (hover) hover.hidden = true; return; }
        var g = e.target.closest && e.target.closest('.dt-node'); if (g) showHover(g, e); else if (hover && !hover.hidden) hover.hidden = true;
      });
      stage.addEventListener('pointerup', function (e) {
        var wasMoved = moved, g = down && down.node; down = null; if (wasMoved || !g) return;
        var id = g.getAttribute('data-dtnode'), kind = g.getAttribute('data-kind');
        var caret = e.target.closest && e.target.closest('.dt-caret, .dt-caret-t');
        if (kind === 'move' && !caret && opts.onOpen) { opts.onOpen(id); return; }
        state.collapsed[id] = !state.collapsed[id]; render();
      });
      stage.addEventListener('pointerleave', function () { if (hover) hover.hidden = true; });
      stage.addEventListener('wheel', function (e) { e.preventDefault(); var r = stage.getBoundingClientRect(); zoomAround(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.14 : 0.88); }, { passive: false });

      function showHover(g, e) {
        if (!hover) return; var id = g.getAttribute('data-dtnode'), kind = g.getAttribute('data-kind');
        var n = lay.byId[id]; if (!n) { hover.hidden = true; return; }
        var html = '<div class="dth-t">' + esc(n.label) + '</div>';
        if (kind === 'move') {
          var cell = (OBOL.study && OBOL.study.cellFor && OBOL.study.cellFor(id)) || {};
          if (cell.whatItIs) html += '<div class="dth-d">' + esc(cell.whatItIs.length > 200 ? cell.whatItIs.slice(0, 197) + '...' : cell.whatItIs) + '</div>';
          if (n.meta) html += '<div class="dth-fork">' + ic('spark') + ' ' + esc(n.meta) + '</div>';
          html += '<div class="dth-open">Click to open this module · Click +/- dot to toggle branches</div>';
        } else if (kind === 'handoff') { html += '<div class="dth-d">Continues in the post-foothold map for what you now hold.</div>'; }
        else if (kind === 'port') { html += '<div class="dth-d">Open service port. Click to fold or unfold the moves it unlocks.</div>'; }
        hover.innerHTML = html; hover.hidden = false;
        var r = stage.getBoundingClientRect(), cw = hover.offsetWidth || 280, ch = hover.offsetHeight || 90;
        var x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
        if (x + cw > r.width - 6) x = e.clientX - r.left - cw - 14;
        if (y + ch > r.height - 6) y = r.height - ch - 8;
        hover.style.left = Math.max(6, x) + 'px'; hover.style.top = Math.max(6, y) + 'px';
      }
    }

    el.addEventListener('click', function (e) {
      var t = e.target.closest && e.target.closest('[data-dt],[data-dt-chip]'); if (!t) return;
      if (t.hasAttribute('data-dt-chip')) {
        var k = t.getAttribute('data-dt-chip'), i = state.ports.indexOf(k);
        if (i >= 0) state.ports.splice(i, 1); else state.ports.push(k);
        state.collapsed = state.ports.length ? {} : defaultCollapsedForForest(forest0);
        lsSet('obol.dt.ports', state.ports.join(',')); fitted = false; render(); return;
      }
      var a = t.getAttribute('data-dt');
      if (a === 'clear-ports') {
        state.ports = [];
        state.collapsed = defaultCollapsedForForest(forest0);
        lsSet('obol.dt.ports', '');
        fitted = false; render(); return;
      }
      if (a === 'cards' && opts.onCards) { opts.onCards(); return; }
      var stage = el.querySelector('#dt-stage'), pan = el.querySelector('#dt-pan'), svg = el.querySelector('#dt-view');
      if (a === 'collapse') {
        var f = (state.ports.length ? OBOL.decisionMap.decisionTree({ ports: state.ports, facts: resolveFacts() }) : forest0);
        f.ports.forEach(function (p) { state.collapsed['port:' + p.key] = true; });
        fitted = false; render(); return;
      }
      if (a === 'expand') { state.collapsed = {}; fitted = false; render(); return; }
      if (!stage || !svg) return;
      var W = +svg.getAttribute('data-w'), H = +svg.getAttribute('data-h'), r = stage.getBoundingClientRect();
      function reapply() { pan.style.transform = 'translate(' + pz.tx + 'px,' + pz.ty + 'px) scale(' + pz.k + ')'; stage.setAttribute('data-lod', pz.k < 0.32 ? 'far' : (pz.k < 0.75 ? 'mid' : 'near')); }
      if (a === 'in' || a === 'out') { var mk = Math.max(0.18, Math.min(2.6, pz.k * (a === 'in' ? 1.22 : 0.82))), ratio = mk / pz.k; pz.tx = r.width / 2 - (r.width / 2 - pz.tx) * ratio; pz.ty = r.height / 2 - (r.height / 2 - pz.ty) * ratio; pz.k = mk; reapply(); }
      else if (a === 'fit') { var k = Math.max(0.25, Math.min((r.width - 24) / W, (r.height - 28) / H, 1.15)); pz = { k: k, tx: Math.max(12, (r.width - W * k) / 2), ty: 14 }; reapply(); }
    });

    render();
    return { render: render };
  }

  OBOL.decisionTreeView = { mount: mount, layout: layout, buildModel: buildModel };
})(typeof window !== 'undefined' ? window : this);
