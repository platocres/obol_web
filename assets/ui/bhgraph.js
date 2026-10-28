/*!
 * obol ui - bhgraph.js - the interactive BloodHound attack-path graph (
 * domainGraphSVG): typed nodes laid out by depth, drag-to-move nodes, wheel-zoom, background-pan,
 * MemberOf (traversal, muted) vs control (abusable, highlighted) edges with labels, the domain
 * goal + owned source highlighted, and per-path highlight chips. Pure DOM (no library).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var ICON = {
    user: '\uD83D\uDC64',
    group: '\uD83D\uDC65',
    computer: '\uD83D\uDDA5',
    domain: '\uD83C\uDF10',
    object: '\u2b24',
    gpo: '\uD83D\uDCDC',
    ou: '\uD83D\uDCC2',
    container: '\uD83D\uDCE6',
    certtemplate: '\uD83D\uDD11',
    ca: '\uD83C\uDFDB'
  };
  var NW = 150, NH = 34, COLW = 240, ROW = 90, PADX = 24, PADY = 38;
  var R = 20;   // node circle radius (BloodHound-style round nodes, label underneath)

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function isMemberOf(edge) { return String(edge || '').toLowerCase() === 'memberof'; }
  function trunc(s, n) { s = String(s || ''); return s.length <= (n || 16) ? s : s.slice(0, (n || 16) - 1) + '\u2026'; }

  // Lay out nodes into depth columns, vertically centered against the tallest column; return {id:{x,y}}.
  // Goal nodes are right-aligned into the rightmost column and sparse depth indices are compacted.
  function layout(graph) {
    var nodes = (graph && graph.nodes) || [];
    var nonGoalMax = 0, hasNonGoal = false;
    nodes.forEach(function (n) {
      var isGoal = !!(n.goal || n.role === 'goal');
      var d = typeof n.depth === 'number' && !isNaN(n.depth) ? n.depth : 0;
      if (!isGoal) {
        hasNonGoal = true;
        if (d > nonGoalMax) nonGoalMax = d;
      }
    });
    var rawByDepth = {};
    var hasEdges = !!(graph && graph.edges && graph.edges.length);
    nodes.forEach(function (n) {
      var isGoal = !!(n.goal || n.role === 'goal');
      var d = typeof n.depth === 'number' && !isNaN(n.depth) ? n.depth : 0;
      if (isGoal) {
        d = Math.max(d, hasNonGoal ? nonGoalMax + 1 : (hasEdges ? 1 : 0));
      }
      var col = (rawByDepth[d] = rawByDepth[d] || []);
      col.push(n);
    });
    var sortedDepths = Object.keys(rawByDepth).map(Number).sort(function (a, b) { return a - b; });
    var byDepth = {}, maxRows = 1;
    sortedDepths.forEach(function (origD, compactIdx) {
      var col = rawByDepth[origD];
      byDepth[compactIdx] = col;
      if (col.length > maxRows) maxRows = col.length;
    });
    var pos = {};
    var maxX = 0, maxY = 0;
    Object.keys(byDepth).forEach(function (d) {
      var col = byDepth[d];
      var offsetY = ((maxRows - col.length) * ROW) / 2;
      col.forEach(function (n, i) {
        var x = PADX + (+d) * COLW;
        var y = PADY + offsetY + i * ROW;
        pos[n.id] = { x: x, y: y, col: +d };
        if (x + NW > maxX) maxX = x + NW;
        if (y + NH > maxY) maxY = y + NH;
      });
    });
    var width = Math.max(maxX + PADX, 720);
    var height = Math.max(maxY + PADY + 28, 240);
    Object.defineProperty(pos, 'width', { value: width, enumerable: false, writable: true, configurable: true });
    Object.defineProperty(pos, 'height', { value: height, enumerable: false, writable: true, configurable: true });
    return pos;
  }

  function center(p) { return { x: p.x + NW / 2, y: p.y + NH / 2 }; }
  function isMultiColumnSpan(a, b) {
    return Math.abs(b.x - a.x) > COLW * 1.15;
  }
  // Draw the edge from circle boundary to circle boundary so the arrowhead sits just outside the target
  // node (visible), not buried under it. If an edge spans across intermediate depth columns,
  // arc it smoothly above intermediate columns so it stays legible.
  function edgePath(pos, e) {
    if (!pos || !e || !pos[e.from] || !pos[e.to]) return '';
    var a = center(pos[e.from]), b = center(pos[e.to]);
    var dx = b.x - a.x, dy = b.y - a.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
    var ux = dx / len, uy = dy / len;
    var x1 = a.x + ux * R, y1 = a.y + uy * R;
    var x2 = b.x - ux * R, y2 = b.y - uy * R;
    if (isMultiColumnSpan(a, b)) {
      var cx = (x1 + x2) / 2;
      var cy = Math.max(18, Math.min(y1, y2) - 46);
      return 'M' + x1 + ',' + y1 + ' Q' + cx + ',' + cy + ' ' + x2 + ',' + y2;
    }
    return 'M' + x1 + ',' + y1 + ' L' + x2 + ',' + y2;
  }

  // Place edge labels at t=0.35 on multi-column spans so they sit between column d and d+1
  // instead of colliding with intermediate column nodes at t=0.5.
  function edgeLabelPoint(pos, from, to, idx) {
    if (!pos || !pos[from] || !pos[to]) return { x: 0, y: 0 };
    var a = center(pos[from]), b = center(pos[to]);
    var stagger = idx ? ((idx % 2 === 1 ? -1 : 1) * 9) : 0;
    if (isMultiColumnSpan(a, b)) {
      var spanCols = Math.max(2, Math.round(Math.abs(b.x - a.x) / COLW));
      var t = Math.min(0.35, 0.48 / spanCols), inv = 1 - t;
      var cx = (a.x + b.x) / 2;
      var cy = Math.max(18, Math.min(a.y, b.y) - 46);
      var bx = inv * inv * a.x + 2 * inv * t * cx + t * t * b.x;
      var by = inv * inv * a.y + 2 * inv * t * cy + t * t * b.y;
      return { x: Math.round(bx), y: Math.round(by - 6 + stagger) };
    }
    var tLinear = 0.54;
    return {
      x: Math.round(a.x + (b.x - a.x) * tLinear),
      y: Math.round(a.y + (b.y - a.y) * tLinear - 6 + stagger)
    };
  }

  function chipLabel(hops, idx, multiSrc) {
    if (!hops || !hops.length) return 'path ' + (idx + 1);
    var src = hops[0].from;
    var abuse = hops.filter(function (h) { return !isMemberOf(h.edge); });
    var pivot = '';
    if (!abuse.length) {
      pivot = hops[hops.length - 1].to;
    } else if (abuse.length === 1) {
      pivot = abuse[0].from === src ? abuse[0].to : abuse[0].from;
    } else {
      pivot = abuse[0].to;
    }
    var prefix = 'path ' + (idx + 1) + ' \u00b7 ';
    if (multiSrc) prefix += trunc(src, 14) + ' \u2192 ';
    else if (abuse.length) prefix += 'via ';
    return prefix + trunc(pivot, 22) + ' (' + hops.length + 'h)';
  }

  function pathBannerHtml(hops, idx) {
    if (!hops || !hops.length) return '';
    var chain = '<span class="bh-rn owned">' + esc(hops[0].from) + '</span>';
    hops.forEach(function (h, hi) {
      var isGoal = hi === hops.length - 1;
      var isMem = isMemberOf(h.edge);
      var edgeTxt = h.edge + (h.alt_edges && h.alt_edges.length > 1 ? ' (+' + (h.alt_edges.length - 1) + ')' : '');
      chain += '<span class="bh-re' + (isMem ? '' : ' abuse') + '">' + esc(edgeTxt) + '</span>'
        + '<span class="bh-rn' + (isGoal ? ' goal' : '') + '">' + esc(h.to) + '</span>';
    });
    return '<span class="bh-pb-tag">Path ' + (idx + 1) + ' (' + hops.length + ' hop' + (hops.length === 1 ? '' : 's') + ')</span><div class="bh-route-chain">' + chain + '</div>';
  }

  // Render the graph into `container`. opts.onNodeClick(nodeId) and opts.onPathSelect(pathIdx) optional.
  function renderInto(container, graph, opts) {
    opts = opts || {};
    if (!graph || !graph.nodes || !graph.nodes.length) {
      container.innerHTML = '<div class="coach-empty">No attack path to graph, set an owned principal to derive paths.</div>';
      return;
    }
    var pos = layout(graph);
    var goalIds = {}; graph.nodes.forEach(function (n) { if (n.type === 'domain' || n.goal || n.role === 'goal') goalIds[n.id] = 1; });
    // Progress overlay: colour every node on the canvas by your real/what-if status, not just the path
    // source. opts.owned (a map of UPPER short name -> 1) marks the accounts you hold; opts.reached marks
    // the ones an owned account already controls. With no overlay given, fall back to the old depth-0 rule.
    var ownedSet = opts.owned || null, reachedSet = opts.reached || null, inspectedSet = opts.inspected || null;
    var ownedIds = {}; graph.nodes.forEach(function (n) {
      var up = String(n.id).toUpperCase();
      if (ownedSet ? ownedSet[up] : (n.depth === 0 && !n.deadEnd)) ownedIds[n.id] = 1;
    });
    var inspectedIds = {};
    if (inspectedSet) graph.nodes.forEach(function (n) {
      var up = String(n.id).toUpperCase();
      if (inspectedSet[up] && !ownedIds[n.id] && !goalIds[n.id]) inspectedIds[n.id] = 1;
    });
    var reachedIds = {};
    if (reachedSet) graph.nodes.forEach(function (n) {
      var up = String(n.id).toUpperCase();
      if (reachedSet[up] && !ownedIds[n.id] && !goalIds[n.id] && !inspectedIds[n.id]) reachedIds[n.id] = 1;
    });

    // Per-node lookup + outgoing edges, for the hover card (full name, role, and what it can abuse).
    var nodeById = {}; graph.nodes.forEach(function (n) { nodeById[n.id] = n; });
    var outEdges = {}; (graph.edges || []).forEach(function (e) { (outEdges[e.from] = outEdges[e.from] || []).push(e); });

    var svgNS = 'http://www.w3.org/2000/svg';
    var vbWidth = pos.width || 720;
    var vbHeight = pos.height || 240;

    // path chips + active path detail banner
    var chipRow = '';
    var pathList = graph.paths || [];
    var deadEnds = graph.deadEnds || [];
    if (graph.count > 0 || deadEnds.length > 0) {
      var srcs = {};
      pathList.forEach(function (p) { if (p && p[0] && p[0].from) srcs[p[0].from] = 1; });
      var multiSrc = Object.keys(srcs).length > 1 || deadEnds.length > 0;
      var chips = [];
      for (var i = 0; i < graph.count; i++) {
        var cLbl = chipLabel(pathList[i], i, multiSrc);
        chips.push('<button class="bh-chip" data-path="' + i + '">' + esc(cLbl) + '</button>');
      }
      deadEnds.forEach(function (dId) {
        chips.push('<button class="bh-chip deadend" data-deadend="' + esc(dId) + '">' + esc(trunc(dId, 16)) + ' \u00b7 0 paths (dead-end)</button>');
      });
      var deadNote = deadEnds.length
        ? (' <b>' + esc(deadEnds.join(', ')) + '</b> ' + (deadEnds.length === 1 ? 'has' : 'have') + ' 0 outbound paths to Domain Admin (shown on the left as dead-end).')
        : '';
      chipRow = '<div class="bh-chips"><button class="bh-chip active" data-path="all">all paths (' + graph.count + ')</button>' + chips.join('') + '</div>'
        + '<div class="bh-path-banner"><span class="bh-pb-hint">Showing all ' + graph.count + ' distinct path' + (graph.count === 1 ? '' : 's') + '. Click a path chip above to isolate its route and step-by-step commands.' + deadNote + '</span></div>';
    }

    var legendHtml = '<div class="bh-legend-bar">'
      + '<div class="bh-leg-group"><span class="bh-leg-title">Lines:</span>'
      + '<span class="bh-leg-item" title="Passive group membership - inherited automatically, no command needed"><svg width="28" height="10" class="bh-leg-svg"><line x1="1" y1="5" x2="27" y2="5" class="bh-leg-line-mem"/></svg> <b>Dotted grey</b> = <code>MemberOf</code> (group membership, automatic)</span>'
      + '<span class="bh-leg-item" title="Active ACL or control permission - requires running an exploit command"><svg width="28" height="10" class="bh-leg-svg"><line x1="1" y1="5" x2="27" y2="5" class="bh-leg-line-abuse"/></svg> <b>Solid red</b> = Abusable ACL (requires command)</span>'
      + '</div>'
      + '<div class="bh-leg-group"><span class="bh-leg-title">Circles:</span>'
      + '<span class="bh-leg-item" title="Account you hold credentials for or marked as Owned / What-If"><span class="bh-leg-d owned"></span> <b>Solid green</b> = Owned / What-If</span>'
      + '<span class="bh-leg-item" title="Group or object an owned account already controls via membership or ACL"><span class="bh-leg-d reached"></span> <b>Dashed cyan</b> = Reached (already controlled)</span>'
      + (Object.keys(inspectedIds).length ? '<span class="bh-leg-item" title="Currently selected in the Inspect dropdown"><span class="bh-leg-d inspected"></span> <b>Dashed amber</b> = Inspecting</span>' : '')
      + '<span class="bh-leg-item" title="Domain Admins group or the Domain root object"><span class="bh-leg-d goal"></span> <b>Solid red</b> = Domain Admin Goal</span>'
      + '<span class="bh-leg-item"><span class="bh-leg-d user"></span> User (' + ICON.user + ')</span>'
      + '<span class="bh-leg-item"><span class="bh-leg-d group"></span> Group (' + ICON.group + ')</span>'
      + '<span class="bh-leg-item"><span class="bh-leg-d computer"></span> Computer (' + ICON.computer + ')</span>'
      + '</div>'
      + '<div class="bh-hint">Drag nodes to rearrange \u00b7 scroll to zoom \u00b7 drag background to pan \u00b7 click any node to inspect it.</div>'
      + '</div>';

    container.innerHTML = chipRow + '<div class="bh-graph-wrap"><svg class="bh-graph" xmlns="' + svgNS + '" width="100%" '
      + 'viewBox="0 0 ' + vbWidth + ' ' + vbHeight + '">'
      + '<defs>'
      + '<marker id="bh-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      + '<path d="M0,0 L10,5 L0,10 z" class="bh-arrowhead"/></marker>'
      + '<marker id="bh-arrow-abuse" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      + '<path d="M0,0 L10,5 L0,10 z" class="bh-arrowhead-abuse"/></marker>'
      + '</defs>'
      + '<g class="bh-viewport"></g></svg></div>'
      + legendHtml;

    var svg = container.querySelector('svg.bh-graph');
    var vp = container.querySelector('.bh-viewport');

    // Merge parallel edges between the same (from, to) pair so multiple ACL rights between the same
    // two principals never draw overlapping labels on the exact same line.
    var mergedEdges = [], pairMap = {};
    (graph.edges || []).forEach(function (e) {
      var isMem = isMemberOf(e.edge);
      var pKey = e.from + '\u0000' + e.to + '\u0000' + (isMem ? 'M' : 'A');
      var m = pairMap[pKey];
      if (!m) {
        m = { from: e.from, to: e.to, isMem: isMem, edges: [], paths: [], edgeByPath: {} };
        pairMap[pKey] = m;
        mergedEdges.push(m);
      }
      var allRightNames = (e.alt_edges && e.alt_edges.length) ? e.alt_edges : [e.edge];
      allRightNames.forEach(function (rn) { if (m.edges.indexOf(rn) < 0) m.edges.push(rn); });
      (e.paths || []).forEach(function (pi) {
        if (m.paths.indexOf(pi) < 0) m.paths.push(pi);
        if (!m.edgeByPath[pi]) m.edgeByPath[pi] = e.edge;
      });
    });

    // edges first (under nodes)
    var abuseIdx = 0;
    mergedEdges.forEach(function (m) {
      var g = document.createElementNS(svgNS, 'g');
      g.setAttribute('class', 'bh-edge ' + (m.isMem ? 'bh-edge-member' : 'bh-edge-abuse'));
      g.setAttribute('data-paths', m.paths.join(','));
      var path = document.createElementNS(svgNS, 'path');
      path.setAttribute('d', edgePath(pos, m));
      path.setAttribute('marker-end', m.isMem ? 'url(#bh-arrow)' : 'url(#bh-arrow-abuse)');
      path.setAttribute('data-from', m.from); path.setAttribute('data-to', m.to);
      g.appendChild(path);
      if (!m.isMem) {
        var pt = edgeLabelPoint(pos, m.from, m.to, abuseIdx++);
        var defaultLbl = m.edges.length > 1 ? (m.edges[0] + ' +' + (m.edges.length - 1)) : m.edges[0];
        var lbl = document.createElementNS(svgNS, 'text');
        lbl.setAttribute('class', 'bh-edge-label');
        lbl.setAttribute('x', pt.x); lbl.setAttribute('y', pt.y);
        lbl.setAttribute('text-anchor', 'middle');
        lbl.setAttribute('data-default-label', defaultLbl);
        lbl.setAttribute('data-path-map', JSON.stringify(m.edgeByPath));
        lbl.textContent = defaultLbl;
        lbl.setAttribute('data-from', m.from); lbl.setAttribute('data-to', m.to);
        if (m.edges.length > 1) {
          var tEl = document.createElementNS(svgNS, 'title');
          tEl.textContent = m.edges.join(', ');
          g.appendChild(tEl);
        }
        g.appendChild(lbl);
      }
      vp.appendChild(g);
    });

    // nodes
    graph.nodes.forEach(function (n) {
      var g = document.createElementNS(svgNS, 'g');
      g.setAttribute('class', 'bh-node bh-type-' + n.type + (goalIds[n.id] ? ' goal' : '') + (ownedIds[n.id] ? ' owned' : '') + (inspectedIds[n.id] ? ' inspected' : '') + (reachedIds[n.id] ? ' reached' : '') + (n.deadEnd ? ' deadend' : ''));
      g.setAttribute('data-id', n.id);
      g.setAttribute('data-paths', (n.paths || []).join(','));
      g.setAttribute('transform', 'translate(' + pos[n.id].x + ',' + pos[n.id].y + ')');
      var cx = NW / 2, cy = NH / 2;
      // round node (BloodHound-style): a typed circle with its icon centred, and the NAME underneath.
      var circle = document.createElementNS(svgNS, 'circle');
      circle.setAttribute('cx', cx); circle.setAttribute('cy', cy); circle.setAttribute('r', R);
      g.appendChild(circle);
      var ico = document.createElementNS(svgNS, 'text');
      ico.setAttribute('class', 'bh-node-ico'); ico.setAttribute('x', cx); ico.setAttribute('y', cy + 6);
      ico.setAttribute('text-anchor', 'middle'); ico.textContent = ICON[n.type] || ICON.object;
      g.appendChild(ico);
      var lbl = document.createElementNS(svgNS, 'text');
      lbl.setAttribute('class', 'bh-node-lbl'); lbl.setAttribute('x', cx); lbl.setAttribute('y', cy + R + 15);
      lbl.setAttribute('text-anchor', 'middle'); lbl.textContent = trunc(n.label, 20);
      g.appendChild(lbl);
      if (n.deadEnd) {
        var sub = document.createElementNS(svgNS, 'text');
        sub.setAttribute('class', 'bh-node-sub'); sub.setAttribute('x', cx); sub.setAttribute('y', cy + R + 27);
        sub.setAttribute('text-anchor', 'middle'); sub.textContent = '(no path to DA)';
        g.appendChild(sub);
      }
      var title = document.createElementNS(svgNS, 'title'); title.textContent = n.label + ' (' + n.type + (n.deadEnd ? ' - 0 paths to DA' : '') + ')';
      g.appendChild(title);
      vp.appendChild(g);
    });

    // hover card (full name + role + abusable relationships), appended to the container so it is
    // cleared on the next render; position:fixed keeps it above the graph without being clipped.
    var card = document.createElement('div');
    card.className = 'bh-nodecard';
    card.style.display = 'none';
    container.appendChild(card);

    wire(svg, vp, pos, opts, { card: card, nodeById: nodeById, outEdges: outEdges, goalIds: goalIds, ownedIds: ownedIds, inspectedIds: inspectedIds, reachedIds: reachedIds, pathList: pathList, count: graph.count, deadEnds: deadEnds });
  }

  var TYPE_NAME = {
    user: 'User',
    group: 'Group',
    computer: 'Computer',
    domain: 'Domain',
    gpo: 'GPO',
    ou: 'OU',
    container: 'Container',
    certtemplate: 'Cert Template',
    ca: 'Cert Authority',
    object: 'Object'
  };
  // Build the hover-card HTML for a node: full (untruncated) name, type, role, path membership, and
  // the outgoing relationships (grey MemberOf, red abusable control) so a chopped-off group is legible.
  function nodeCardHtml(n, ctx) {
    var roles = '';
    if (ctx.ownedIds[n.id]) roles += '<span class="bh-nc-tag owned">owned</span>';
    if (ctx.inspectedIds && ctx.inspectedIds[n.id]) roles += '<span class="bh-nc-tag inspected">inspecting</span>';
    if (ctx.reachedIds && ctx.reachedIds[n.id]) roles += '<span class="bh-nc-tag reached">reached</span>';
    if (ctx.goalIds[n.id]) roles += '<span class="bh-nc-tag goal">domain goal</span>';
    if (n.deadEnd) roles += '<span class="bh-nc-tag deadend">0 paths</span>';
    var out = (ctx.outEdges[n.id] || []);
    var rels = out.slice(0, 6).map(function (e) {
      var t = ctx.nodeById[e.to], toLabel = t ? t.label : e.to;
      var member = isMemberOf(e.edge);
      return '<li class="' + (member ? 'mem' : 'abuse') + '"><span class="bh-nc-edge">' + esc(e.edge)
        + '</span> ' + esc(toLabel) + '</li>';
    }).join('');
    var relsBlock = out.length
      ? '<div class="bh-nc-rels-h">' + (out.length > 6 ? 'Relationships (first 6 of ' + out.length + ')' : 'Relationships') + '</div>'
        + '<ul class="bh-nc-rels">' + rels + '</ul>'
      : '';
    var paths = (n.paths || []).length;
    var pathLine = paths
      ? '<div class="bh-nc-paths">On ' + paths + ' attack path' + (paths === 1 ? '' : 's') + '</div>'
      : (n.deadEnd ? '<div class="bh-nc-paths deadend">0 outbound paths to Domain Admin (dead-end account)</div>' : '');
    return '<div class="bh-nc-h">' + esc((ICON[n.type] || ICON.object) + ' ' + (n.label || n.id)) + '</div>'
      + '<div class="bh-nc-sub">' + esc(TYPE_NAME[n.type] || n.type || 'object') + roles + '</div>'
      + pathLine
      + relsBlock;
  }

  function wire(svg, vp, pos, opts, ctx) {
    ctx = ctx || {};
    var scale = 1, tx = 0, ty = 0;
    var dragNode = null, dragId = null, panning = false, last = null, moved = false;

    function apply() { vp.setAttribute('transform', 'translate(' + tx + ',' + ty + ') scale(' + scale + ')'); }
    function svgPoint(evt) {
      var r = svg.getBoundingClientRect();
      var vb = svg.viewBox.baseVal;
      var sx = vb.width / r.width, sy = vb.height / r.height;
      return { x: (evt.clientX - r.left) * sx, y: (evt.clientY - r.top) * sy };
    }
    function redrawEdges(id) {
      vp.querySelectorAll('path[data-from="' + cssEsc(id) + '"], path[data-to="' + cssEsc(id) + '"]').forEach(function (p) {
        p.setAttribute('d', edgePath(pos, { from: p.getAttribute('data-from'), to: p.getAttribute('data-to') }));
      });
      vp.querySelectorAll('text.bh-edge-label[data-from="' + cssEsc(id) + '"], text.bh-edge-label[data-to="' + cssEsc(id) + '"]').forEach(function (t) {
        var pt = edgeLabelPoint(pos, t.getAttribute('data-from'), t.getAttribute('data-to'));
        t.setAttribute('x', pt.x); t.setAttribute('y', pt.y);
      });
    }
    function cssEsc(s) { return String(s).replace(/["\\]/g, '\\$&'); }

    svg.addEventListener('pointerdown', function (e) {
      var node = e.target.closest('.bh-node');
      moved = false;
      if (node) { dragNode = node; dragId = node.getAttribute('data-id'); }
      else { panning = true; }
      last = svgPoint(e);
      svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener('pointermove', function (e) {
      if (!dragNode && !panning) return;
      var p = svgPoint(e); var dx = p.x - last.x, dy = p.y - last.y; last = p;
      if (Math.abs(dx) + Math.abs(dy) > 1) moved = true;
      if (dragNode) {
        pos[dragId].x += dx / scale; pos[dragId].y += dy / scale;
        dragNode.setAttribute('transform', 'translate(' + pos[dragId].x + ',' + pos[dragId].y + ')');
        redrawEdges(dragId);
      } else if (panning) { tx += dx; ty += dy; apply(); }
    });
    svg.addEventListener('pointerup', function (e) {
      if (dragNode && !moved && opts.onNodeClick) opts.onNodeClick(dragId);
      dragNode = null; dragId = null; panning = false;
      try { svg.releasePointerCapture(e.pointerId); } catch (x) {}
    });
    svg.addEventListener('wheel', function (e) {
      e.preventDefault();
      var factor = e.deltaY < 0 ? 1.1 : 0.9;
      var p = svgPoint(e);
      // zoom around pointer
      tx = p.x - (p.x - tx) * factor; ty = p.y - (p.y - ty) * factor;
      scale = Math.max(0.3, Math.min(3, scale * factor));
      apply();
    }, { passive: false });

    // hover card: full node identity + relationships, positioned by the cursor (hidden while dragging).
    function hideCard() { if (ctx.card) { ctx.card.style.display = 'none'; ctx.card._id = null; } }
    if (ctx.card) {
      svg.addEventListener('mousemove', function (e) {
        if (dragNode || panning) { hideCard(); return; }
        var node = e.target.closest('.bh-node'); if (!node) { hideCard(); return; }
        var id = node.getAttribute('data-id'), n = ctx.nodeById[id];
        if (!n) { hideCard(); return; }
        if (ctx.card._id !== id) { ctx.card.innerHTML = nodeCardHtml(n, ctx); ctx.card._id = id; ctx.card.style.display = 'block'; }
        var cw = ctx.card.offsetWidth || 240, ch = ctx.card.offsetHeight || 120;
        var x = e.clientX + 14, y = e.clientY + 14;
        if (x + cw > window.innerWidth - 8) x = e.clientX - cw - 14;
        if (y + ch > window.innerHeight - 8) y = window.innerHeight - ch - 8;
        ctx.card.style.left = Math.max(8, x) + 'px'; ctx.card.style.top = Math.max(8, y) + 'px';
      });
      svg.addEventListener('mouseleave', hideCard);
      svg.addEventListener('pointerdown', hideCard);
    }

    // path highlight chips
    var hostContainer = svg.parentElement.parentElement;
    var chipsWrap = hostContainer.querySelector('.bh-chips');
    var bannerEl = hostContainer.querySelector('.bh-path-banner');
    if (chipsWrap) chipsWrap.addEventListener('click', function (e) {
      var b = e.target.closest('.bh-chip'); if (!b) return;
      chipsWrap.querySelectorAll('.bh-chip').forEach(function (x) { x.classList.remove('active'); });
      b.classList.add('active');
      var deadId = b.getAttribute('data-deadend');
      if (deadId) {
        vp.querySelectorAll('.bh-node, .bh-edge').forEach(function (el) {
          var on = el.getAttribute('data-id') === deadId;
          el.classList.toggle('dim', !on); el.classList.toggle('hot', on);
        });
        if (bannerEl) {
          bannerEl.innerHTML = '<span class="bh-pb-tag deadend">0 Paths</span><span class="bh-pb-hint"><b>' + esc(deadId) + '</b> has no outbound path to Domain Admin in this BloodHound collection (standard account with 0 outbound ACL or privileged group edges).</span>';
        }
        if (opts.onNodeClick) opts.onNodeClick(deadId);
        return;
      }
      var sel = b.getAttribute('data-path');
      vp.querySelectorAll('.bh-node, .bh-edge').forEach(function (el) {
        if (sel === 'all') { el.classList.remove('dim', 'hot'); return; }
        var paths = (el.getAttribute('data-paths') || '').split(',');
        var on = paths.indexOf(sel) >= 0;
        el.classList.toggle('dim', !on); el.classList.toggle('hot', on);
      });
      vp.querySelectorAll('text.bh-edge-label').forEach(function (lbl) {
        var defLbl = lbl.getAttribute('data-default-label') || lbl.textContent;
        if (sel === 'all') { lbl.textContent = defLbl; return; }
        try {
          var pMap = JSON.parse(lbl.getAttribute('data-path-map') || '{}');
          if (pMap[sel]) lbl.textContent = pMap[sel];
        } catch (x) {}
      });
      if (bannerEl) {
        if (sel === 'all') {
          var dEnds = ctx.deadEnds || [];
          var dNote = dEnds.length ? (' <b>' + esc(dEnds.join(', ')) + '</b> ' + (dEnds.length === 1 ? 'has' : 'have') + ' 0 outbound paths to Domain Admin (shown on the left as dead-end).') : '';
          bannerEl.innerHTML = '<span class="bh-pb-hint">Showing all ' + (ctx.count || 0) + ' distinct path' + ((ctx.count || 0) === 1 ? '' : 's') + '. Click a path chip above to isolate its route and step-by-step commands.' + dNote + '</span>';
        } else {
          var pi = Number(sel);
          var pHops = (ctx.pathList && ctx.pathList[pi]) || [];
          bannerEl.innerHTML = pathBannerHtml(pHops, pi);
        }
      }
      if (opts.onPathSelect) opts.onPathSelect(sel === 'all' ? null : Number(sel));
    });
  }

  OBOL.bhgraph = { renderInto: renderInto, layout: layout, edgePath: edgePath, edgeLabelPoint: edgeLabelPoint, ICONS: ICON };
})(typeof globalThis !== 'undefined' ? globalThis : this);
