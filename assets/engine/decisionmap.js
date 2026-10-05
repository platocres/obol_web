/*!
 * obol engine — decisionmap.js — OBOL.decisionMap
 *
 * The by-port DECISION MAP: a port-rooted, left-to-right decision forest derived from the same move
 * graph and the same ranker that power the coach, so the map can never contradict Next Steps.
 *
 * Why this exists (read docs/DECISION-MAP.md before changing it): it is both a teaching surface AND a
 * self-diagnostic. Because it is DERIVED (never hand-drawn), three classes of coverage gap show up on
 * it automatically, which is the whole point:
 *   - coverage gap  — a technique that *should* exist for a port but no move represents it
 *                     (found by diffing against data/coverage-expected.js).
 *   - wiring gap    — a move exists but isn't connected: it produces a fact nothing needs (dead-end),
 *                     requires a fact nothing produces (unreachable), or lands a foothold with no
 *                     hand-off to a post-exploitation map.
 *   - parse gap     — a move exists and is wired, but no parser can read its output into the fact it
 *                     claims to produce, so running it never advances the coach ("write-only" node).
 *                     Derived empirically by running each move's fixture through the real parsers.
 *
 * Nothing here is authored per-port by hand. The only authored layers are the one-line fork conditions
 * (data/decision-forks.js), the plain-language parser "looks for" lines (data/parser-signatures.js),
 * and the expected-coverage spec (data/coverage-expected.js) — each lint-gated, each a sentence, not a
 * tree. Add a move or wire a fact and the map (and these diagnostics) update themselves.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function study() { return OBOL.study; }
  function actions() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function fixtures() { return OBOL.STUDY_FIXTURES || {}; }
  function forks() { return OBOL.DECISION_FORKS || {}; }
  function sigs() { return OBOL.PARSER_SIGNATURES || {}; }
  function expected() { return OBOL.COVERAGE_EXPECTED || {}; }

  var _byId = null;
  function byId(id) {
    if (!_byId) { _byId = {}; actions().forEach(function (a) { _byId[a.id] = a; }); }
    return _byId[id] || null;
  }
  function reqSet(m) { return [].concat((m && m.requires_all) || [], (m && m.requires_any) || []); }
  function produces(m) { return (m && m.produces) || []; }

  // --- hand-off interchanges: a foothold/credential fact ends a port's own tree and links to the
  //     shared post-exploitation map (an access-tier Evidence card), instead of inlining the whole
  //     downstream under every port. fact -> { to: evidence key, label }.
  var HANDOFF = [
    { re: /^foothold\.linux$|^access\.shell$/, to: 'shell-linux', label: 'you have a shell on Linux' },
    { re: /^foothold\.windows$/, to: 'shell-windows', label: 'you have a shell on Windows' },
    { re: /^foothold\.webshell$/, to: 'shell-linux', label: 'you have a web shell (upgrade it)' },
    { re: /^hash\./, to: 'offline-hash', label: 'you have a hash to crack' },
    { re: /^credential\.available$/, to: 'domain-cred', label: 'you have a usable credential' },
    { re: /^loot\.ntds$/, to: 'domain-cred', label: 'you dumped the domain (NTDS)' },
    { re: /^access\.admin$|^access\.system$/, to: 'proof', label: 'you are admin / SYSTEM — capture proof' },
    { re: /^tunnel\./, to: 'pivot', label: 'you can reach a deeper network — pivot' },
  ];
  function handoffFor(fact) {
    for (var i = 0; i < HANDOFF.length; i++) if (HANDOFF[i].re.test(fact)) return HANDOFF[i];
    return null;
  }

  // --- the parser CAPABILITY SET: every fact obol can recognize from output, from PARSER_SIGNATURES.
  //     An emit ending in "." is a prefix wildcard (service. -> service.mysql). This is the source of
  //     truth for the parse-gap lens: a produced fact outside it is one nothing can read.
  var _cap = null;
  function capability() {
    if (_cap) return _cap;
    var exact = {}, pref = [];
    var S = sigs();
    Object.keys(S).forEach(function (k) { (S[k].emits || []).forEach(function (e) { if (e.charAt(e.length - 1) === '.') pref.push(e); else exact[e] = 1; }); });
    _cap = { exact: exact, pref: pref };
    return _cap;
  }
  function capable(fact) {
    var c = capability();
    if (c.exact[fact]) return true;
    for (var i = 0; i < c.pref.length; i++) if (fact.indexOf(c.pref[i]) === 0) return true;
    return false;
  }
  // environmental facts (the engagement/scan hands these over, no move or parse needed)
  function isEnv(f) { return /^(target\.|host\.up$|ports\.open$|port:|scan\.|service\.)/.test(f) || /\.reachable$/.test(f); }
  // "intent" facts that are legitimately not provable from pasted output (you did a thing, there is no
  // result to read): starting a listener, standing up a tunnel, planting persistence. Not a parse gap.
  function isActionIntent(f) { return /^(listener\.|tunnel\.|persistence\.|enum\.deep$)/.test(f); }
  // can obol ever obtain this fact? (a move produced it, a parser can read it, or it is environmental)
  function obtainable(fact, producedIndex) { return !!(producedIndex[fact]) || capable(fact) || isEnv(fact); }
  // is a produced fact readable back (so running the move advances the coach)? parseable, handed off,
  // environmental, or a legitimate action-intent fact.
  function readable(fact) { return capable(fact) || isEnv(fact) || isActionIntent(fact) || !!handoffFor(fact); }

  // ---------------------------------------------------------------------------------------------
  // Parser coverage: run each move's fixture output through the real parser dispatch and record
  // which fact kinds actually mint, vs what the move claims to `produce`. This is the parse-gap lens.
  // ---------------------------------------------------------------------------------------------
  function fixtureText(fx) {
    if (!fx) return '';
    if (fx.output) return fx.output;
    if (fx.steps && fx.steps.length) return fx.steps.map(function (s) { return s.output || ''; }).join('\n');
    return '';
  }
  var _parseCov = null;
  function parserCoverage() {
    if (_parseCov) return _parseCov;
    var out = {};
    var P = OBOL.parsers;
    actions().forEach(function (m) {
      var fx = fixtures()[m.id];
      var prod = produces(m);
      var entry = { id: m.id, produces: prod, minted: [], status: 'nofixture' };
      if (!fx || !fixtureText(fx)) { out[m.id] = entry; return; }
      if (!P || !P.parseActionOutput) { entry.status = 'noparser'; out[m.id] = entry; return; }
      var minted = [];
      try {
        var r = P.parseActionOutput({
          actionId: m.id, command: fx.cmd || '', stdout: fixtureText(fx), stderr: '',
          scope: 'host:10.10.10.10', domain: 'acme.internal',
        });
        minted = (r.facts || []).map(function (f) { return f.kind; });
      } catch (e) { entry.error = (e && e.message) || String(e); }
      entry.minted = minted;
      // the move's own sample output demonstrating one of its facts is a bonus "shown" signal, not the
      // grade (a teaching fixture often shows an earlier representative step than the fact's real run).
      entry.selfRead = prod.some(function (f) { return minted.indexOf(f) >= 0; });
      out[m.id] = entry;
    });
    // Grade each move on CAPABILITY, not on its one fixture: can any parser read each produced fact?
    actions().forEach(function (m) {
      var e = out[m.id] || (out[m.id] = { id: m.id, produces: produces(m), minted: [], selfRead: false });
      var prod = e.produces || [];
      var readq = prod.filter(readable);
      if (!prod.length) e.status = 'noproduce';                // enum/terminal move, declares no fact
      else if (readq.length === prod.length) e.status = 'verified';
      else if (readq.length) e.status = 'partial';
      else e.status = 'gap';                                   // runs, but obol can read NONE of its result
      e.unreadable = prod.filter(function (f) { return !readable(f); });
    });
    _parseCov = out;
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // The decision tree for one port: its moves, linked by fact flow (A.produces ∩ B.reqs), each move's
  // primary parent being the earliest in-set producer; entry moves hang off the port root; a produced
  // hand-off fact becomes a leaf that links to the post-exploitation map.
  // ---------------------------------------------------------------------------------------------
  function portTree(ev, pcov) {
    var S = study();
    var moveIds = (ev.moves || []).map(function (m) { return m.id; });
    var inSet = {}; moveIds.forEach(function (id) { inSet[id] = true; });
    // producer index within this port's move set
    var producerOf = {}; // fact -> [ids], order = topo (ev.moves already topo-ordered)
    moveIds.forEach(function (id) { produces(byId(id)).forEach(function (f) { (producerOf[f] = producerOf[f] || []).push(id); }); });

    var nodes = {}, order = [];
    function node(id) {
      if (nodes[id]) return nodes[id];
      var m = byId(id) || { id: id, title: id };
      var cell = (S.cellFor && S.cellFor(id)) || {};
      var tell = (S.signalTell && S.signalTell(id)) || {};
      var alts = (S.alternativesFor && S.alternativesFor(id)) || [];
      var pc = (pcov || {})[id] || {};
      var n = {
        id: id, title: m.title || id, cat: (S.categoryOf && S.categoryOf(id)) || '',
        laneKey: (S.laneEntry && (S.laneEntry(id) || {}).laneKey) || '',
        phase: cell.phase || '', scope: cell.scope || '', locus: (cell.commands && cell.commands[0] && cell.commands[0].locus) || '',
        produces: produces(m), reqs: reqSet(m),
        signal: tell.signal || '', teach: tell.teach || '', gist: tell.gist || '',
        fork: (forks()[id] && forks()[id].cond) || '', forkFail: (forks()[id] && forks()[id].onFail) || '',
        alternatives: alts.map(function (a) { return a.id; }).filter(function (aid) { return aid !== id; }),
        parse: pc.status || 'nofixture', parseHit: pc.hit || [], parseMinted: pc.minted || [],
        children: [], handoffs: [],
      };
      // hand-off leaves for any produced interchange fact
      produces(m).forEach(function (f) { var h = handoffFor(f); if (h) n.handoffs.push({ to: h.to, label: h.label, fact: f }); });
      nodes[id] = n; order.push(id);
      return n;
    }
    moveIds.forEach(node);

    // link each move to its earliest in-set producer of any requirement; else it is an entry move
    var roots = [];
    moveIds.forEach(function (id) {
      var m = byId(id), parent = null;
      reqSet(m).some(function (r) {
        var prods = (producerOf[r] || []).filter(function (pid) { return pid !== id; });
        if (prods.length) { parent = prods[0]; return true; }
        return false;
      });
      if (parent && nodes[parent]) nodes[parent].children.push(id);
      else roots.push(id);
    });
    return { key: ev.key, port: ev.port, proto: ev.proto, fam: ev.fam, label: ev.label, signal: ev.signal,
      roots: roots, nodes: nodes, order: order };
  }

  // The ranked "spine": from the port's entry facts, ask the coach for its #1 next move repeatedly,
  // staying within the port's move set, so the map lights the path the coach would actually walk.
  function spineFor(ev) {
    var PK = OBOL.pack, F = OBOL.facts;
    if (!PK || !PK.nextActionsV2 || !F) return [];
    var inSet = {}; (ev.moves || []).forEach(function (m) { inSet[m.id] = true; });
    var portNum = String(ev.port || '').split('/')[0];
    var have = ['target.configured', 'host.up', 'ports.open'];
    if (portNum) have.push('port:' + portNum);
    var spine = [], guard = 0, seen = {};
    while (guard++ < 24) {
      var fl = have.map(function (k, i) { return F.makeFact({ kind: k, scope: { target: '10.10.10.10' }, source: 'map', created_at: 1700000000000 + i * 1000 }); });
      var ranked = PK.nextActionsV2(new F.FactSet(fl), actions(), {}) || [];
      var pick = null;
      for (var i = 0; i < ranked.length; i++) { if (inSet[ranked[i].id] && !seen[ranked[i].id]) { pick = ranked[i]; break; } }
      if (!pick) break;
      seen[pick.id] = 1; spine.push(pick.id);
      produces(byId(pick.id)).forEach(function (f) { if (have.indexOf(f) < 0) have.push(f); });
    }
    return spine;
  }

  // The whole forest: scan root -> one subtree per port (filterable), each with its ranked spine.
  function decisionTree(opts) {
    opts = opts || {};
    var S = study();
    var evAll = (S.evidence && S.evidence()) || [];
    // the 'scan' card is the "before anything, scan" primer, not an open port — the forest root already
    // IS the port scan, so exclude it here (otherwise it renders a redundant subtree and a "first" chip).
    var portsOnly = evAll.filter(function (e) { return e.tier === 'ports' && e.key !== 'scan'; });
    var want = opts.ports && opts.ports.length ? opts.ports : null; // array of evidence keys
    var pcov = parserCoverage();
    var trees = portsOnly
      .filter(function (e) { return !want || want.indexOf(e.key) >= 0; })
      .map(function (e) { var t = portTree(e, pcov); t.spine = spineFor(e); return t; });
    return {
      scan: { label: 'Port scan', signal: 'Every engagement opens the same way: sweep the target, then let each open port tell you what to try.' },
      ports: trees,
      access: evAll.filter(function (e) { return e.tier === 'access'; }).map(function (e) { return { key: e.key, label: e.label, signal: e.signal }; }),
    };
  }

  // ---------------------------------------------------------------------------------------------
  // Gap report: structural (wiring) + parse + coverage. Pure data; tools/gap-report.js formats it.
  // ---------------------------------------------------------------------------------------------
  function gapReport() {
    var S = study();
    var acts = actions();
    var allProduced = {}, allRequired = {};
    acts.forEach(function (m) {
      produces(m).forEach(function (f) { allProduced[f] = (allProduced[f] || 0) + 1; });
      reqSet(m).forEach(function (f) { allRequired[f] = (allRequired[f] || 0) + 1; });
    });

    // wiring: a requires_all member (or an entire requires_any group) that is not obtainable — no move
    // produces it, no parser reads it, and it is not environmental, so the move can never become ready.
    var wiring = { unreachable: [], deadEnd: [], missingHandoff: [] };
    acts.forEach(function (m) {
      (m.requires_all || []).forEach(function (r) { if (!obtainable(r, allProduced)) wiring.unreachable.push({ id: m.id, fact: r, kind: 'all' }); });
      var any = m.requires_any || [];
      if (any.length && !any.some(function (r) { return obtainable(r, allProduced); })) wiring.unreachable.push({ id: m.id, fact: any.join(' / '), kind: 'any' });
      // dead-end: produces a fact nothing requires and that is not an interchange, objective, loot, or a
      // naturally-terminal enum/observation fact (a review list, not a hard gap).
      produces(m).forEach(function (f) {
        var consumed = allRequired[f] > 0, hand = !!handoffFor(f);
        // terminal/report facts: loot, proof, observations, and recorded credential MATERIAL whose
        // usable form (credential.available / .candidate) is emitted alongside — the material fact
        // itself feeds the report, not another move, so it is not a wiring dead-end.
        var term = /^(objective|flag|proof|loot\.|config\.review|defense\.|snmp\.info|host\.|web\.(server|tech|title|content_map|source)|dns\.|tls\.|persistence\.|credential\.plaintext$|db\.creds$)/.test(f);
        if (!consumed && !hand && !term) wiring.deadEnd.push({ id: m.id, fact: f });
      });
    });
    // a move that lands an interchange fact but whose target access card does not exist
    var accessKeys = {}; ((S.evidence && S.evidence()) || []).forEach(function (e) { if (e.tier === 'access') accessKeys[e.key] = 1; });
    acts.forEach(function (m) { produces(m).forEach(function (f) { var h = handoffFor(f); if (h && !accessKeys[h.to]) wiring.missingHandoff.push({ id: m.id, fact: f, to: h.to }); }); });

    // parse gaps: a move whose produced fact(s) no parser can read (nothing recognizes its result, so
    // running it never advances the coach) — graded from the capability set, not a single fixture.
    var pc = parserCoverage();
    var parse = { gap: [], partial: [] };
    Object.keys(pc).forEach(function (id) {
      var e = pc[id];
      if (e.status === 'gap') parse.gap.push({ id: id, produces: e.produces, unreadable: e.unreadable });
      else if (e.status === 'partial') parse.partial.push({ id: id, produces: e.produces, unreadable: e.unreadable });
    });

    // orphan parser facts: a fact a parser mints that NOTHING uses — no move produces it AND no move
    // requires it. A parser-only fact that some move requires (e.g. smb.ms17_010 → eternalblue) is
    // correct design, not an orphan, so those are excluded.
    var mintedAll = {};
    Object.keys(pc).forEach(function (id) { (pc[id].minted || []).forEach(function (k) { mintedAll[k] = 1; }); });
    var orphanParserFacts = Object.keys(mintedAll).filter(function (k) {
      return !allProduced[k] && !allRequired[k] && !/^(host\.|scan\.|ports\.open|port:|web\.|service\.|.*\.reachable$)/.test(k);
    });

    // coverage: expected techniques per port with no backing move
    var exp = expected(), coverage = [];
    Object.keys(exp).forEach(function (portKey) {
      var have = {};
      ((S.evidence && S.evidence()) || []).forEach(function (e) { if (e.key === portKey) (e.moves || []).forEach(function (mv) { have[mv.id] = 1; }); });
      (exp[portKey].expect || []).forEach(function (item) {
        var covered = (item.moves || []).some(function (mid) { return have[mid]; });
        if (!covered) coverage.push({ port: portKey, technique: item.name, note: item.note || '' });
      });
    });

    return { wiring: wiring, parse: parse, orphanParserFacts: orphanParserFacts, coverage: coverage,
      counts: {
        moves: acts.length,
        unreachable: wiring.unreachable.length, deadEnd: wiring.deadEnd.length, missingHandoff: wiring.missingHandoff.length,
        parseGap: parse.gap.length, parsePartial: parse.partial.length,
        orphanParserFacts: orphanParserFacts.length, coverageGap: coverage.length,
      } };
  }

  OBOL.decisionMap = {
    decisionTree: decisionTree,
    parserCoverage: parserCoverage,
    gapReport: gapReport,
    handoffFor: handoffFor,
    capability: capability,
    _reset: function () { _byId = null; _parseCov = null; _cap = null; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
