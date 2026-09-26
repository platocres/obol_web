/*!
 * obol engine — graph.js
 * The path graph: one model projected from facts + pack, rendered as a self-contained inline
 * SVG (phase columns L→R, proven/future facts, done/next/locked actions, curved edges).
 * Faithful JS port of obol-local/obol/graph.py build_graph_model + build_graph_svg. Node/edge
 * colors are CSS classes (not hardcoded) so the active skin themes the graph.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var P = OBOL.phases;

  function nid(s) { return s.replace(/[^a-zA-Z0-9_]/g, '_'); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function friendly(k) { return OBOL.pack.friendly(k); }

  // Compute the forward-path model. include_all shows the whole methodology DAG.
  function buildGraphModel(facts, pack, includeAll) {
    var live = {};
    OBOL.pack.nextActions(facts, pack).forEach(function (a) { live[a.id] = true; });
    var nodes = [], edges = [], seen = {};

    function factNode(kind) {
      var id = nid('f_' + kind);
      if (!seen[id]) {
        seen[id] = true;
        nodes.push({ id: id, type: 'fact', label: friendly(kind), kind: kind,
          state: facts.has(kind) ? 'proven' : 'future', phase: P.phaseOfKind(kind) });
      }
      return id;
    }

    pack.forEach(function (a) {
      var done = a.settled(facts);
      if (!(done || live[a.id] || includeAll)) return;
      var state = done ? 'done' : (live[a.id] ? 'next' : 'locked');
      var anid = nid('a_' + a.id);
      nodes.push({ id: anid, type: 'action', label: a.title, action_id: a.id, state: state, phase: P.phaseOfAction(a) });
      a.requires_all.concat(a.requires_any).forEach(function (k) {
        if (includeAll || facts.has(k)) edges.push({ from: factNode(k), to: anid });
      });
      a.produces.forEach(function (k) { edges.push({ from: anid, to: factNode(k) }); });
    });

    return { phases: P.PHASES.slice(), nodes: nodes, edges: edges };
  }

  var NW = 178, NH = 42, COLW = 214, ROW = 56, PADX = 22, PADY = 46;

  function trunc(label, limit) {
    limit = limit || 24;
    return label.length <= limit ? label : label.slice(0, limit - 1).replace(/\s+$/, '') + '…';
  }

  function buildGraphSvg(facts, pack, includeAll) {
    var model = buildGraphModel(facts, pack, includeAll);
    var byPhase = {}; P.PHASES.forEach(function (p) { byPhase[p] = []; });
    model.nodes.forEach(function (n) { (byPhase[n.phase] = byPhase[n.phase] || []).push(n); });
    var cols = P.PHASES.filter(function (p) { return byPhase[p] && byPhase[p].length; });
    if (!cols.length) {
      return '<svg viewBox="0 0 320 60" width="320" height="60" xmlns="http://www.w3.org/2000/svg">'
        + '<text x="12" y="34" class="g-empty" font-size="13">Nothing on the path yet — add a target or paste a scan.</text></svg>';
    }
    var pos = {};
    cols.forEach(function (p, ci) {
      byPhase[p].forEach(function (n, ri) { pos[n.id] = { x: PADX + ci * COLW, y: PADY + ri * ROW, node: n }; });
    });
    var tallest = Math.max.apply(null, cols.map(function (p) { return byPhase[p].length; }));
    var height = PADY + tallest * ROW + 14;
    var width = PADX * 2 + (cols.length - 1) * COLW + NW;

    var edges = model.edges.map(function (e) {
      var a = pos[e.from], b = pos[e.to];
      if (!a || !b) return '';
      var x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, mx = (x1 + x2) / 2;
      var future = b.node.type === 'fact' && b.node.state === 'future';
      return '<path d="M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2 + '" '
        + 'fill="none" class="g-edge' + (future ? ' g-edge-future' : '') + '"/>';
    }).join('');

    var headers = cols.map(function (p, ci) {
      var cx = PADX + ci * COLW;
      return '<text x="' + (cx + NW / 2) + '" y="24" text-anchor="middle" class="g-head ph-text-' + p + '" '
        + 'font-size="11" font-weight="700" letter-spacing="1.2">' + p.toUpperCase() + '</text>'
        + '<line x1="' + cx + '" y1="32" x2="' + (cx + NW) + '" y2="32" class="g-head-rule ph-stroke-' + p + '"/>';
    }).join('');

    // Title Case node labels for display (fact labels come lowercase from friendly()); the pack's
    // own action titles pass through unchanged where already capitalized.
    var tc = (OBOL.util && OBOL.util.titleCase) ? OBOL.util.titleCase : function (x) { return x; };
    var nodeSvg = Object.keys(pos).map(function (id) {
      var m = pos[id], n = m.node, rx = n.type === 'fact' ? 16 : 6;
      var cls = 'g-node g-' + n.type + '-' + n.state, lbl = tc(n.label);
      return '<g class="' + cls + '">'
        + '<rect x="' + m.x + '" y="' + m.y + '" width="' + NW + '" height="' + NH + '" rx="' + rx + '"/>'
        + '<text x="' + (m.x + NW / 2) + '" y="' + (m.y + NH / 2 + 4) + '" text-anchor="middle" font-size="12">'
        + '<title>' + esc(lbl) + '</title>' + esc(trunc(lbl)) + '</text></g>';
    }).join('');

    return '<svg viewBox="0 0 ' + width + ' ' + height + '" width="' + width + '" height="' + height + '" '
      + 'preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg" class="obol-graph" '
      + 'font-family="system-ui,sans-serif">' + headers + edges + nodeSvg + '</svg>';
  }

  OBOL.graph = { buildGraphModel: buildGraphModel, buildGraphSvg: buildGraphSvg };
})(typeof globalThis !== 'undefined' ? globalThis : this);
