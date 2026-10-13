/*!
 * obol ui — decisiontree.js — OBOL.decisionTreeView
 *
 * The left-to-right DECISION MAP renderer for the by-port forest (OBOL.decisionMap.decisionTree). One
 * reusable component, mounted wherever a port-rooted decision view is wanted (the Learn by-port view
 * now; the target view and an engagement-wide forest later). Self-contained: own pan/zoom/wheel, own
 * semantic LOD (labels resolve as you zoom in), own tidy LTR layout, filter chips, a parser-coverage
 * lens, and collapsible subtrees. No dependencies beyond OBOL.decisionMap + OBOL.ic.
 *
 * Design intent (docs/DECISION-MAP.md): first paint is the whole forest at a far fit-zoom — the
 * impressive "mass" — but navigable, because LOD hides detail at distance and the ranker's spine is lit
 * so the path that matters is always visible. A port's tree ends at a hand-off leaf (→ a post-foothold
 * interchange) rather than inlining the endgame. The parser lens recolors nodes by whether obol can
 * read each move's result, turning the map into a coverage X-ray.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var ic = function (n, c) { return (OBOL.ic ? OBOL.ic(n, c) : ''); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (m) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[m]; }); }
  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var COLX = 196, ROWY = 26, NW = 170, NH = 20, PAD = 24;

  // ---- layout: a tidy left-to-right tree over the forest (scan → ports → moves → hand-off leaves) ----
  function layout(forest, state) {
    var nodes = [], edges = [], rowCursor = { y: 0 };
    var collapsed = state.collapsed || {};

    var nodeById = {};
    // build the tree model first
    var tree = buildModel(forest, state);
    // first pass places everything and records nodes (parent y = midpoint of its children: tidy LTR)
    (function walk(node, depth) {
      var kids = node.children || [];
      var isCollapsed = collapsed[node.id] && kids.length;
      var y;
      if (!kids.length || isCollapsed) { y = rowCursor.y * ROWY + PAD; rowCursor.y += 1; }
      else { var ys = kids.map(function (k) { return walk(k, depth + 1); }); y = (ys[0] + ys[ys.length - 1]) / 2; }
      var x = PAD + depth * COLX;
      var n = { id: node.id, label: node.label, kind: node.kind, lane: node.lane || '', spine: !!node.spine,
        parse: node.parse || '', meta: node.meta || '', reach: node.reach || null, x: x, y: y, cx: x + NW / 2, cy: y + NH / 2,
        hasKids: kids.length > 0, collapsed: !!isCollapsed, count: kids.length, children: kids };
      nodeById[node.id] = n; nodes.push(n);
      return y;
    })(tree, 0);
    // edges from the placed nodes
    nodes.forEach(function (n) {
      if (n.collapsed) return;
      (n.children || []).forEach(function (k) {
        var kn = nodeById[k.id]; if (!kn) return;
        edges.push({ x1: n.x + NW, y1: n.cy, x2: kn.x, y2: kn.cy, spine: n.spine && kn.spine });
      });
    });
    var maxX = 0, maxY = 0;
    nodes.forEach(function (n) { maxX = Math.max(maxX, n.x + NW); maxY = Math.max(maxY, n.y + NH); });
    return { nodes: nodes, edges: edges, width: maxX + PAD, height: maxY + PAD, byId: nodeById };
  }

  // Build the renderable tree model from the engine forest. Each port's internal DAG is flattened to a
  // tree (a move's primary parent is its earliest in-port producer; see decisionmap.js). Hand-off facts
  // become terminal leaf nodes pointing at the post-foothold interchange.
  function buildModel(forest, state) {
    var want = state.ports && state.ports.length ? state.ports : null;
    var portNodes = forest.ports
      .filter(function (p) { return !want || want.indexOf(p.key) >= 0; })
      .map(function (p) {
        var spine = {}; (p.spine || []).forEach(function (id) { spine[id] = 1; });
        function moveNode(id) {
          var n = p.nodes[id];
          var kids = (n.children || []).map(moveNode);
          (n.handoffs || []).forEach(function (h) { kids.push({ id: p.key + ':ho:' + h.fact, label: '→ ' + h.label, kind: 'handoff', lane: 'access', children: [] }); });
          return { id: id, label: n.title, kind: 'move', lane: n.laneKey || laneOf(n), spine: !!spine[id], parse: n.parse, meta: n.fork || '', children: kids };
        }
        return { id: 'port:' + p.key, label: (p.port ? p.port + '  ' : '') + p.label, kind: 'port', lane: p.fam || '',
          spine: true, reach: (OBOL.FLAG_REACH || {})[p.key] || null, children: (p.roots || []).map(moveNode) };
      });
    return { id: 'scan', label: 'Port scan', kind: 'scan', spine: true, children: portNodes };
  }
  function laneOf(n) { return (n && n.laneKey) || ''; }

  // ---- svg ----
  function nodeSvg(n) {
    var cls = 'dt-node dt-' + n.kind + (n.lane ? ' lane-' + n.lane : '') + (n.spine ? ' dt-spine' : '') + (n.parse ? ' parse-' + n.parse : '') + (n.collapsed ? ' dt-folded' : '');
    var label = n.collapsed ? (n.label + '  (+' + n.count + ')') : n.label;
    var caret = n.hasKids ? '<circle class="dt-caret" cx="' + (n.x + NW - 9) + '" cy="' + n.cy + '" r="7"/>'
      + '<text class="dt-caret-t" x="' + (n.x + NW - 9) + '" y="' + (n.cy + 3.5) + '">' + (n.collapsed ? '+' : '−') + '</text>' : '';
    // Flag-reachability badge on a port node: three chips (User flag / Root flag / Domain control),
    // each green when the engine proves that milestone reachable from this port, red on a gap. This is
    // the by-port → flag map made visible: a red chip is a user who would be stranded here.
    var badge = '';
    if (n.kind === 'port' && n.reach) {
      var chips = [['U', n.reach.userFlag], ['R', n.reach.rootFlag]];
      if (n.reach.domain !== null && n.reach.domain !== undefined) chips.push(['D', n.reach.domain]);
      badge = '<g class="dt-reach" aria-label="flag reachability">' + chips.map(function (c, i) {
        var bx = n.x + NW + 4 + i * 15, ok = c[1];
        return '<rect class="dt-chip dt-chip-' + (ok ? 'ok' : 'gap') + '" x="' + bx + '" y="' + (n.cy - 7) + '" width="13" height="14" rx="3"/>'
          + '<text class="dt-chip-t" x="' + (bx + 6.5) + '" y="' + (n.cy + 3.5) + '">' + c[0] + '</text>';
      }).join('') + '</g>';
    }
    return '<g class="' + cls + '" data-dtnode="' + esc(n.id) + '" data-cx="' + n.cx + '" data-cy="' + n.cy + '" data-kind="' + n.kind + '">'
      + '<rect class="dt-box" x="' + n.x + '" y="' + n.y + '" width="' + NW + '" height="' + NH + '" rx="5"/>'
      + '<text class="dt-label" x="' + (n.x + 8) + '" y="' + (n.cy + 3.5) + '">' + esc(label.length > 26 ? label.slice(0, 25) + '…' : label) + '</text>'
      + caret + badge + '</g>';
  }
  function edgeD(e) {
    var mx = (e.x1 + e.x2) / 2;
    return 'M' + e.x1 + ',' + e.y1 + ' C' + mx + ',' + e.y1 + ' ' + mx + ',' + e.y2 + ' ' + e.x2 + ',' + e.y2;
  }
  function buildSvg(lay) {
    var edges = lay.edges.map(function (e) { return '<path class="dt-edge' + (e.spine ? ' dt-edge-spine' : '') + '" d="' + edgeD(e) + '"/>'; }).join('');
    var nodes = lay.nodes.map(nodeSvg).join('');
    return '<svg id="dt-view" class="dt-view" data-w="' + lay.width + '" data-h="' + lay.height + '" width="' + lay.width + '" height="' + lay.height + '" viewBox="0 0 ' + lay.width + ' ' + lay.height + '">'
      + '<g class="dt-edges">' + edges + '</g><g class="dt-nodes">' + nodes + '</g></svg>';
  }

  // ---- controls ----
  function chips(forest, state) {
    var want = state.ports || [];
    return forest.ports.map(function (p) {
      var on = !want.length || want.indexOf(p.key) >= 0;
      return '<button type="button" class="dt-chip' + (on && want.length ? ' on' : '') + '" data-dt-chip="' + esc(p.key) + '">' + esc((p.port || p.label)) + '</button>';
    }).join('');
  }
  function controls(forest, state) {
    return '<div class="dt-bar">'
      + '<button type="button" class="dt-btn" data-dt="cards">' + ic('box') + ' Cards</button>'
      + '<div class="dt-lens"><span class="dt-lens-l">Lens</span>'
      + '<button type="button" class="dt-seg' + (state.lens === 'methodology' ? ' on' : '') + '" data-dt-lens="methodology">Methodology</button>'
      + '<button type="button" class="dt-seg' + (state.lens === 'parser' ? ' on' : '') + '" data-dt-lens="parser">Parser cover</button></div>'
      + '<div class="dt-zoom"><button type="button" class="dt-btn" data-dt="out">−</button>'
      + '<button type="button" class="dt-btn" data-dt="fit">Fit</button>'
      + '<button type="button" class="dt-btn" data-dt="in">+</button>'
      + '<button type="button" class="dt-btn" data-dt="collapse">Collapse all</button>'
      + '<button type="button" class="dt-btn" data-dt="expand">Expand all</button></div>'
      + '<div class="dt-filter"><span class="dt-filter-l">Ports</span>' + chips(forest, state) + '</div>'
      + '</div>';
  }
  function legend(state) {
    if (state.lens === 'parser') {
      return '<div class="dt-legend"><span class="dt-lg parse-verified">obol reads the result</span>'
        + '<span class="dt-lg parse-partial">partly readable</span>'
        + '<span class="dt-lg parse-gap">parse gap (unreadable)</span>'
        + '<span class="dt-lg parse-noproduce">enum / no fact</span></div>';
    }
    return '<div class="dt-legend"><span class="dt-lg dt-lg-spine">the coach’s next move</span>'
      + '<span class="dt-lg dt-lg-handoff">→ hand-off to a post-foothold map</span>'
      + '<span class="dt-lg">click a node to open it · the dot folds its branches</span></div>';
  }

  // ---- mount + wire ----
  function mount(el, opts) {
    opts = opts || {};
    var forest0 = OBOL.decisionMap.decisionTree({ ports: null, facts: opts.facts });
    var state = {
      ports: (opts.ports || (lsGet('obol.dt.ports', '') ? lsGet('obol.dt.ports').split(',').filter(Boolean) : [])),
      lens: opts.lens || lsGet('obol.dt.lens', 'methodology'),
      collapsed: {},
    };
    var pz = { k: 1, tx: 0, ty: 0 }, fitted = false;

    function render() {
      var forest = state.ports.length ? OBOL.decisionMap.decisionTree({ ports: state.ports }) : forest0;
      var lay = layout(forest, state);
      el.innerHTML = controls(forest0, state)
        + '<div class="dt-stage" id="dt-stage" data-lens="' + esc(state.lens) + '" tabindex="0" role="group" aria-label="Port decision map, pan and zoom">'
        + '<div class="dt-pan" id="dt-pan">' + buildSvg(lay) + '</div>'
        + '<div class="dt-hover" id="dt-hover" hidden></div>'
        + legend(state) + '</div>';
      wire(lay, forest);
    }

    function wire(lay, forest) {
      var stage = el.querySelector('#dt-stage'), pan = el.querySelector('#dt-pan'), hover = el.querySelector('#dt-hover');
      var W = lay.width, H = lay.height;
      function apply() { pan.style.transform = 'translate(' + pz.tx + 'px,' + pz.ty + 'px) scale(' + pz.k + ')'; stage.setAttribute('data-lod', pz.k < 0.55 ? 'far' : (pz.k < 0.95 ? 'mid' : 'near')); }
      function fit() { var r = stage.getBoundingClientRect(); var k = Math.min((r.width - 20) / W, (r.height - 20) / H, 1.1); k = Math.max(k, 0.12); pz = { k: k, tx: (r.width - W * k) / 2, ty: 12 }; apply(); }
      function zoomAround(mx, my, f) { var nk = Math.max(0.12, Math.min(2.6, pz.k * f)), ratio = nk / pz.k; pz.tx = mx - (mx - pz.tx) * ratio; pz.ty = my - (my - pz.ty) * ratio; pz.k = nk; apply(); }
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
        // otherwise fold/unfold this node's branches
        state.collapsed[id] = !state.collapsed[id]; render();
      });
      stage.addEventListener('pointerleave', function () { if (hover) hover.hidden = true; });
      stage.addEventListener('wheel', function (e) { e.preventDefault(); var r = stage.getBoundingClientRect(); zoomAround(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 0.89); }, { passive: false });

      function showHover(g, e) {
        if (!hover) return; var id = g.getAttribute('data-dtnode'), kind = g.getAttribute('data-kind');
        var n = lay.byId[id]; if (!n) { hover.hidden = true; return; }
        var html = '<div class="dth-t">' + esc(n.label) + '</div>';
        if (kind === 'move') {
          var cell = (OBOL.study && OBOL.study.cellFor && OBOL.study.cellFor(id)) || {};
          if (cell.whatItIs) html += '<div class="dth-d">' + esc(cell.whatItIs.length > 200 ? cell.whatItIs.slice(0, 197) + '…' : cell.whatItIs) + '</div>';
          if (n.meta) html += '<div class="dth-fork">' + ic('spark') + ' ' + esc(n.meta) + '</div>';
          if (state.lens === 'parser') {
            var sig = (OBOL.PARSER_SIGNATURES && findSig(id)) || null;
            html += '<div class="dth-parse parse-' + n.parse + '">' + parseLabel(n.parse) + '</div>';
            if (sig) html += '<div class="dth-looks">obol looks for: ' + esc(sig) + '</div>';
          }
          html += '<div class="dth-open">click to open this move</div>';
        } else if (kind === 'handoff') { html += '<div class="dth-d">Continues in the post-foothold map for what you now hold.</div>'; }
        else if (kind === 'port') { html += '<div class="dth-d">An open port. Click to fold/unfold the moves it opens.</div>'; }
        hover.innerHTML = html; hover.hidden = false;
        var r = stage.getBoundingClientRect(), cw = hover.offsetWidth || 280, ch = hover.offsetHeight || 90;
        var x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
        if (x + cw > r.width - 6) x = e.clientX - r.left - cw - 14;
        if (y + ch > r.height - 6) y = r.height - ch - 8;
        hover.style.left = Math.max(6, x) + 'px'; hover.style.top = Math.max(6, y) + 'px';
      }
    }

    // controls (delegated on el, survive re-render)
    el.addEventListener('click', function (e) {
      var t = e.target.closest && e.target.closest('[data-dt],[data-dt-lens],[data-dt-chip]'); if (!t) return;
      if (t.hasAttribute('data-dt-lens')) { state.lens = t.getAttribute('data-dt-lens'); lsSet('obol.dt.lens', state.lens); render(); return; }
      if (t.hasAttribute('data-dt-chip')) {
        var k = t.getAttribute('data-dt-chip'), i = state.ports.indexOf(k);
        if (i >= 0) state.ports.splice(i, 1); else state.ports.push(k);
        lsSet('obol.dt.ports', state.ports.join(',')); fitted = false; render(); return;
      }
      var a = t.getAttribute('data-dt');
      if (a === 'cards' && opts.onCards) { opts.onCards(); return; }
      var stage = el.querySelector('#dt-stage'), pan = el.querySelector('#dt-pan'), svg = el.querySelector('#dt-view');
      if (a === 'collapse') { var f = (state.ports.length ? OBOL.decisionMap.decisionTree({ ports: state.ports }) : forest0); f.ports.forEach(function (p) { state.collapsed['port:' + p.key] = true; }); render(); return; }
      if (a === 'expand') { state.collapsed = {}; render(); return; }
      if (!stage || !svg) return;
      var W = +svg.getAttribute('data-w'), H = +svg.getAttribute('data-h'), r = stage.getBoundingClientRect();
      function reapply() { pan.style.transform = 'translate(' + pz.tx + 'px,' + pz.ty + 'px) scale(' + pz.k + ')'; stage.setAttribute('data-lod', pz.k < 0.55 ? 'far' : (pz.k < 0.95 ? 'mid' : 'near')); }
      if (a === 'in' || a === 'out') { var mk = Math.max(0.12, Math.min(2.6, pz.k * (a === 'in' ? 1.2 : 0.83))), ratio = mk / pz.k; pz.tx = r.width / 2 - (r.width / 2 - pz.tx) * ratio; pz.ty = r.height / 2 - (r.height / 2 - pz.ty) * ratio; pz.k = mk; reapply(); }
      else if (a === 'fit') { var k = Math.max(0.12, Math.min((r.width - 20) / W, (r.height - 20) / H, 1.1)); pz = { k: k, tx: (r.width - W * k) / 2, ty: 12 }; reapply(); }
    });

    render();
    return { render: render };
  }

  function parseLabel(s) { return s === 'verified' ? 'obol can read this result' : s === 'partial' ? 'result partly readable' : s === 'gap' ? 'parse gap: nothing reads this result' : 'enumeration move (no fact to read)'; }
  function findSig(moveId) {
    // the plain-language "looks for" of whichever signature emits one of this move's produced facts
    try {
      var m = (OBOL.packs.actions() || []).filter(function (a) { return a.id === moveId; })[0]; if (!m) return '';
      var prod = m.produces || [], S = OBOL.PARSER_SIGNATURES || {};
      var keys = Object.keys(S);
      for (var i = 0; i < keys.length; i++) {
        var emits = S[keys[i]].emits || [];
        for (var j = 0; j < prod.length; j++) {
          for (var e = 0; e < emits.length; e++) {
            var em = emits[e];
            if (em === prod[j] || (em.charAt(em.length - 1) === '.' && prod[j].indexOf(em) === 0)) return S[keys[i]].looksFor;
          }
        }
      }
    } catch (x) {}
    return '';
  }

  OBOL.decisionTreeView = { mount: mount, layout: layout, buildModel: buildModel };
})(typeof window !== 'undefined' ? window : this);
