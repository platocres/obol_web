/*!
 * obol engine — graph.js
 * The path graph: one model projected from facts + pack, rendered as a self-contained inline
 * SVG (phase columns L→R, proven/future facts, done/next/locked actions, curved edges).
 * Node/edge
 * colors are CSS classes (not hardcoded) so the active skin themes the graph.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var P = OBOL.phases;

  function nid(s) { return s.replace(/[^a-zA-Z0-9_]/g, '_'); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function attr(s) { return esc(s).replace(/"/g, '&quot;'); }
  function friendly(k) { return OBOL.pack.friendly(k); }
  // The named technique a proven fact represents, from the findings catalog (so a milestone reads
  // "DCSync Replication Abuse", not "loot.ntds"/"Ntds"). Only mapped kinds relabel; the rest stay friendly.
  function techniqueForKind(kind) {
    var cat = root.OBOL && root.OBOL.findingsCatalog; if (!cat) return null;
    for (var i = 0; i < cat.length; i++) {
      var m = cat[i].match || {}, ks = (m.facts_any || []).concat(m.facts_all || []);
      if (ks.indexOf(kind) >= 0) return cat[i].title;
    }
    return null;
  }

  // Compute the forward-path model. include_all shows the whole methodology DAG.
  function buildGraphModel(facts, pack, includeAll) {
    var nodes = [], edges = [], seen = {}, edgeSeen = {};

    function factNode(kind) {
      var id = nid('f_' + kind);
      if (!seen[id]) {
        seen[id] = true;
        nodes.push({ id: id, type: 'fact', label: techniqueForKind(kind) || friendly(kind), kind: kind,
          technique: techniqueForKind(kind) || '',
          state: facts.has(kind) ? 'proven' : 'future', phase: /^(?:objective|proof)\./.test(kind) ? 'loot' : P.phaseOfKind(kind) });
      }
      return id;
    }

    function addEdge(from, to) {
      var key = from + '->' + to;
      if (edgeSeen[key]) return;
      edgeSeen[key] = true;
      edges.push({ from: from, to: to });
    }

    var actionsToRender = pack;
    if (!includeAll) {
      var rankMap = {};
      if (root.OBOL && root.OBOL.pack && typeof root.OBOL.pack.rankActions === 'function') {
        try {
          var rankedList = root.OBOL.pack.rankActions(facts, pack) || [];
          rankedList.forEach(function (ra, idx) { if (ra && ra.id) rankMap[ra.id] = idx; });
        } catch (e) {}
      }
      var nextByPhase = {};
      var keptIds = {};
      pack.forEach(function (a, origIdx) {
        var elig = a.eligible(facts);
        var done = elig && a.settled(facts);
        var next = !done && elig && !a.obsolete(facts);
        if (done) { keptIds[a.id] = true; return; }
        if (!next) return;
        var actPhase = (a.produces || []).some(function (k) { return /^(?:objective|proof)\./.test(k); }) ? 'loot' : P.phaseOfAction(a);
        var reqs = (a.requires_all || []).concat(a.requires_any || []);
        var hasProvenNonInfra = reqs.some(function (k) { return k !== 'target.configured' && facts.has(k); });
        var rIdx = (a.id in rankMap) ? rankMap[a.id] : (1000 + origIdx);
        (nextByPhase[actPhase] = nextByPhase[actPhase] || []).push({ a: a, proven: hasProvenNonInfra ? 0 : 1, rIdx: rIdx });
      });
      Object.keys(nextByPhase).forEach(function (ph) {
        var list = nextByPhase[ph];
        list.sort(function (x, y) { return (x.proven - y.proven) || (x.rIdx - y.rIdx); });
        list.slice(0, 8).forEach(function (item) { keptIds[item.a.id] = true; });
      });
      actionsToRender = pack.filter(function (a) { return !!keptIds[a.id]; });
    }

    actionsToRender.forEach(function (a) {
      var elig = a.eligible(facts);
      var done = elig && a.settled(facts);
      var next = !done && elig && !a.obsolete(facts);
      if (!(done || next || includeAll)) return;
      var state = done ? 'done' : (next ? 'next' : 'locked');
      var anid = nid('a_' + a.id);
      var actPhase = (a.produces || []).some(function (k) { return /^(?:objective|proof)\./.test(k); }) ? 'loot' : P.phaseOfAction(a);
      nodes.push({ id: anid, type: 'action', label: a.title, action_id: a.id, state: state, phase: actPhase });
      var reqs = a.requires_all.concat(a.requires_any);
      reqs.forEach(function (k) {
        if (includeAll || facts.has(k)) addEdge(factNode(k), anid);
      });
      if (a.credential_probe) {
        var anyDirect = a.requires_any.some(function (k) { return facts.has(k); });
        if (!anyDirect && (includeAll || facts.has('credential.available') || facts.has('loot.ntds'))) {
          var credKind = facts.has('loot.ntds') ? 'loot.ntds' : 'credential.available';
          addEdge(factNode(credKind), anid);
        }
      }
      a.produces.forEach(function (k) { addEdge(anid, factNode(k)); });
    });

    return { phases: P.PHASES.slice(), nodes: nodes, edges: edges };
  }

  // The legend/filter category a node belongs to (matches the five legend swatches): proven|goal for
  // facts, done|next|locked for actions. Used to tag nodes and their edges so the legend can filter them.
  function catOfNode(n) { return n.type === 'fact' ? (n.state === 'proven' ? 'proven' : 'goal') : n.state; }

  var NW = 178, NH = 42, COLW = 214, ROW = 56, PADX = 22, PADY = 46;

  function trunc(label, limit) {
    limit = limit || 24;
    return label.length <= limit ? label : label.slice(0, limit - 1).replace(/\s+$/, '') + '…';
  }

  function buildGraphSvg(facts, pack, includeAll) {
    var model = buildGraphModel(facts, pack, includeAll);
    var byPhase = {}; P.PHASES.forEach(function (p) { byPhase[p] = []; });
    model.nodes.forEach(function (n) {
      var col = (n.phase in byPhase) ? n.phase : (n.phase === 'lateral' ? 'escalate' : P.DEFAULT_PHASE);
      (byPhase[col] = byPhase[col] || []).push(n);
    });
    var cols = P.PHASES.filter(function (p) { return byPhase[p] && byPhase[p].length; });
    if (!cols.length) {
      return '<svg viewBox="0 0 320 60" width="320" height="60" xmlns="http://www.w3.org/2000/svg">'
        + '<text x="12" y="34" class="g-empty" font-size="13">Nothing on the path yet, add a target or paste a scan.</text></svg>';
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
      // Tag with both endpoints' categories so a legend filter hides an edge when either end is hidden.
      var ecls = 'g-edge' + (future ? ' g-edge-future' : '') + ' gedge-from-' + catOfNode(a.node) + ' gedge-to-' + catOfNode(b.node);
      return '<path d="M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2 + '" '
        + 'fill="none" class="' + ecls + '"/>';
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
      var cls = 'g-node g-' + n.type + '-' + n.state + ' gcat-' + catOfNode(n), lbl = tc(n.label);
      return '<g class="' + cls + '" data-nid="' + attr(id) + '" tabindex="0" role="button">'
        + '<rect x="' + m.x + '" y="' + m.y + '" width="' + NW + '" height="' + NH + '" rx="' + rx + '"/>'
        + '<text x="' + (m.x + NW / 2) + '" y="' + (m.y + NH / 2 + 4) + '" text-anchor="middle" font-size="12">'
        + '<title>' + esc(lbl) + '</title>' + esc(trunc(lbl)) + '</text></g>';
    }).join('');

    return '<svg viewBox="0 0 ' + width + ' ' + height + '" width="' + width + '" height="' + height + '" '
      + 'preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg" class="obol-graph" '
      + 'font-family="system-ui,sans-serif">' + headers + edges + nodeSvg + '</svg>';
  }

  function techniqueEntryForKind(kind) {
    var cat = root.OBOL && root.OBOL.findingsCatalog; if (!cat) return null;
    for (var i = 0; i < cat.length; i++) {
      var m = cat[i].match || {}, ks = (m.facts_any || []).concat(m.facts_all || []);
      if (ks.indexOf(kind) >= 0) return cat[i];
    }
    return null;
  }
  function firstRunnableCommand(a, facts, opts) {
    if (!a) return '';
    var cmds = (a.commands && a.commands.length) ? a.commands : (a.command ? [{ run: a.command }] : []);
    if (!cmds.length) return '';
    var firstUnblocked = '';
    for (var i = 0; i < cmds.length; i++) {
      try {
        var f = OBOL.command.fillCommand(a, facts, opts || {}, i);
        var rendered = f.filled || f.run || '';
        if (f.blocked) continue;
        if (!firstUnblocked) firstUnblocked = rendered;
        if (rendered && !/\{\{[^}]+\}\}/.test(rendered)) return rendered;
      } catch (e) {}
    }
    if (firstUnblocked) return firstUnblocked;
    try {
      var f0 = OBOL.command.fillCommand(a, facts, opts || {}, 0);
      return f0.filled || f0.run || '';
    } catch (e2) {
      return (cmds[0] && cmds[0].run) || a.command || '';
    }
  }
  function actionCommand(a, facts, opts) {
    return firstRunnableCommand(a, facts, opts);
  }
  function stripTokens(s) {
    return String(s || '').replace(/\{\{subject\}\}/g, 'the affected account').replace(/\{\{domain\}\}/g, 'the domain')
      .replace(/\{\{target\}\}/g, 'the target').replace(/\{\{\w+\}\}/g, '').replace(/\s{2,}/g, ' ').trim();
  }
  // Per-node hover content: what it is, why it matters, and the command to run (facts + pack + catalog +
  // narratives). Keyed by the same data-nid the SVG carries. Consumed by OBOL.graphtip.
  function buildNodeInfo(facts, pack, opts) {
    opts = opts || {};
    var tc = (OBOL.util && OBOL.util.titleCase) ? OBOL.util.titleCase : function (x) { return x; };
    var model = buildGraphModel(facts, pack, opts.includeAll);
    var byAction = {}; pack.forEach(function (a) { byAction[a.id] = a; });
    var live = OBOL.pack.nextActions(facts, pack);
    var info = {};
    model.nodes.forEach(function (n) {
      if (n.type === 'action') {
        var a = byAction[n.action_id]; if (!a) return;
        info[n.id] = {
          title: tc(a.title), kind: 'action', phase: n.phase, state: n.state,
          note: n.state === 'done' ? 'Completed, this move’s result is proven.'
            : (n.state === 'next' ? 'Ready now, run this to advance.' : 'Locked, prerequisites not yet proven.'),
          explain: a.hypothesis || '', command: actionCommand(a, facts, opts), command_label: '', refs: (a.refs || []).slice(0, 3),
        };
      } else {
        var ent = techniqueEntryForKind(n.kind);
        var narr = ent && root.OBOL && root.OBOL.narratives && root.OBOL.narratives[ent.key];
        var explain = (narr && narr.explanation) ? stripTokens(narr.explanation)
          : (ent ? (ent.title + 'see the Findings section for detail.') : ('A proven fact on the path: ' + tc(friendly(n.kind)) + '.'));
        var nextA = null;
        for (var i = 0; i < live.length; i++) { if (live[i].requires_all.concat(live[i].requires_any).indexOf(n.kind) >= 0) { nextA = live[i]; break; } }
        info[n.id] = {
          title: tc(n.label), kind: 'fact', phase: n.phase, state: n.state,
          note: n.state === 'proven' ? 'Proven on this engagement.' : 'Not yet proven, the pending goal of the move that produces it.',
          explain: explain, command: nextA ? actionCommand(nextA, facts, opts) : '',
          command_label: nextA ? ('Run next: ' + tc(nextA.title)) : '', refs: ent ? (ent.refs || []).slice(0, 3) : [],
        };
      }
    });
    return info;
  }

  OBOL.graph = {
    buildGraphModel: buildGraphModel,
    buildGraphSvg: buildGraphSvg,
    buildNodeInfo: buildNodeInfo,
    techniqueForKind: techniqueForKind,
    firstRunnableCommand: firstRunnableCommand
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
