/*!
 * obol ui — bhgraph.js — the interactive BloodHound attack-path graph (parity with obol-local's
 * domainGraphSVG): typed nodes laid out by depth, drag-to-move nodes, wheel-zoom, background-pan,
 * MemberOf (traversal, muted) vs control (abusable, highlighted) edges with labels, the domain
 * goal + owned source highlighted, and per-path highlight chips. Pure DOM (no library).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var ICON = { user: '\uD83D\uDC64', group: '\uD83D\uDC65', computer: '\uD83D\uDDA5', domain: '\uD83C\uDF10', object: '\u2b24', gpo: '\uD83D\uDCDC' };
  var NW = 150, NH = 34, COLW = 210, ROW = 64, PADX = 24, PADY = 30;

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function isMemberOf(edge) { return String(edge || '').toLowerCase() === 'memberof'; }
  function trunc(s, n) { s = String(s || ''); return s.length <= (n || 16) ? s : s.slice(0, (n || 16) - 1) + '\u2026'; }

  // Lay out nodes into depth columns; return a positions map {id:{x,y}}.
  function layout(graph) {
    var byDepth = {};
    graph.nodes.forEach(function (n) { (byDepth[n.depth] = byDepth[n.depth] || []).push(n); });
    var pos = {};
    Object.keys(byDepth).forEach(function (d) {
      byDepth[d].forEach(function (n, i) { pos[n.id] = { x: PADX + (+d) * COLW, y: PADY + i * ROW }; });
    });
    return pos;
  }

  function center(p) { return { x: p.x + NW / 2, y: p.y + NH / 2 }; }
  function edgePath(pos, e) {
    var a = center(pos[e.from]), b = center(pos[e.to]);
    if (!pos[e.from] || !pos[e.to]) return '';
    return 'M' + a.x + ',' + a.y + ' L' + b.x + ',' + b.y;
  }

  // Render the graph into `container`. opts.onNodeClick(nodeId) optional.
  function renderInto(container, graph, opts) {
    opts = opts || {};
    if (!graph || !graph.nodes || !graph.nodes.length) {
      container.innerHTML = '<div class="coach-empty">No attack path to graph — set an owned principal to derive paths.</div>';
      return;
    }
    var pos = layout(graph);
    var goalIds = {}; graph.nodes.forEach(function (n) { if (n.type === 'domain') goalIds[n.id] = 1; });
    var ownedIds = {}; graph.nodes.forEach(function (n) { if (n.depth === 0) ownedIds[n.id] = 1; });

    var svgNS = 'http://www.w3.org/2000/svg';
    var maxX = 0, maxY = 0;
    Object.keys(pos).forEach(function (k) { maxX = Math.max(maxX, pos[k].x + NW); maxY = Math.max(maxY, pos[k].y + NH); });

    // path chips
    var chipRow = '';
    if (graph.count > 1) {
      var chips = [];
      for (var i = 0; i < graph.count; i++) chips.push('<button class="bh-chip" data-path="' + i + '">path ' + (i + 1) + '</button>');
      chipRow = '<div class="bh-chips"><button class="bh-chip active" data-path="all">all paths</button>' + chips.join('') + '</div>';
    }

    container.innerHTML = chipRow + '<div class="bh-graph-wrap"><svg class="bh-graph" xmlns="' + svgNS + '" width="100%" '
      + 'viewBox="0 0 ' + (maxX + PADX) + ' ' + (maxY + PADY) + '">'
      + '<defs><marker id="bh-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      + '<path d="M0,0 L10,5 L0,10 z" class="bh-arrowhead"/></marker></defs>'
      + '<g class="bh-viewport"></g></svg></div>'
      + '<div class="bh-hint">Drag nodes to rearrange · scroll to zoom · drag the background to pan · red edges are abusable control, grey is MemberOf.</div>';

    var svg = container.querySelector('svg.bh-graph');
    var vp = container.querySelector('.bh-viewport');

    // edges first (under nodes)
    graph.edges.forEach(function (e, i) {
      var g = document.createElementNS(svgNS, 'g');
      g.setAttribute('class', 'bh-edge ' + (isMemberOf(e.edge) ? 'bh-edge-member' : 'bh-edge-abuse'));
      g.setAttribute('data-paths', (e.paths || []).join(','));
      var path = document.createElementNS(svgNS, 'path');
      path.setAttribute('d', edgePath(pos, e));
      path.setAttribute('marker-end', 'url(#bh-arrow)');
      path.setAttribute('data-from', e.from); path.setAttribute('data-to', e.to);
      g.appendChild(path);
      if (!isMemberOf(e.edge)) {
        var a = center(pos[e.from]), b = center(pos[e.to]);
        var lbl = document.createElementNS(svgNS, 'text');
        lbl.setAttribute('class', 'bh-edge-label');
        lbl.setAttribute('x', (a.x + b.x) / 2); lbl.setAttribute('y', (a.y + b.y) / 2 - 3);
        lbl.setAttribute('text-anchor', 'middle');
        lbl.textContent = e.edge;
        lbl.setAttribute('data-from', e.from); lbl.setAttribute('data-to', e.to);
        g.appendChild(lbl);
      }
      vp.appendChild(g);
    });

    // nodes
    graph.nodes.forEach(function (n) {
      var g = document.createElementNS(svgNS, 'g');
      g.setAttribute('class', 'bh-node bh-type-' + n.type + (goalIds[n.id] ? ' goal' : '') + (ownedIds[n.id] ? ' owned' : ''));
      g.setAttribute('data-id', n.id);
      g.setAttribute('data-paths', (n.paths || []).join(','));
      g.setAttribute('transform', 'translate(' + pos[n.id].x + ',' + pos[n.id].y + ')');
      var rect = document.createElementNS(svgNS, 'rect');
      rect.setAttribute('width', NW); rect.setAttribute('height', NH); rect.setAttribute('rx', 7);
      g.appendChild(rect);
      var txt = document.createElementNS(svgNS, 'text');
      txt.setAttribute('x', 10); txt.setAttribute('y', NH / 2 + 4);
      txt.textContent = (ICON[n.type] || '') + ' ' + trunc(n.label, 15);
      var title = document.createElementNS(svgNS, 'title'); title.textContent = n.label + ' (' + n.type + ')';
      g.appendChild(txt); g.appendChild(title);
      vp.appendChild(g);
    });

    wire(svg, vp, pos, opts);
  }

  function wire(svg, vp, pos, opts) {
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
        var a = center(pos[t.getAttribute('data-from')]), b = center(pos[t.getAttribute('data-to')]);
        t.setAttribute('x', (a.x + b.x) / 2); t.setAttribute('y', (a.y + b.y) / 2 - 3);
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

    // path highlight chips
    var chipsWrap = svg.parentElement.parentElement.querySelector('.bh-chips');
    if (chipsWrap) chipsWrap.addEventListener('click', function (e) {
      var b = e.target.closest('.bh-chip'); if (!b) return;
      chipsWrap.querySelectorAll('.bh-chip').forEach(function (x) { x.classList.remove('active'); });
      b.classList.add('active');
      var sel = b.getAttribute('data-path');
      vp.querySelectorAll('.bh-node, .bh-edge').forEach(function (el) {
        if (sel === 'all') { el.classList.remove('dim', 'hot'); return; }
        var paths = (el.getAttribute('data-paths') || '').split(',');
        var on = paths.indexOf(sel) >= 0;
        el.classList.toggle('dim', !on); el.classList.toggle('hot', on);
      });
    });
  }

  OBOL.bhgraph = { renderInto: renderInto, layout: layout };
})(typeof globalThis !== 'undefined' ? globalThis : this);
