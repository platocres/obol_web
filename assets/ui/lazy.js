/*!
 * obol ui - lazy.js - route-lazy bundle loader. Injects <script> tags on demand (works over
 * file:// and http, unlike fetch). Keeps the critical boot path tiny: only the engine core +
 * coach/evidence/home/targets load up front; tools/domain/report/graph/checklist load on first
 * navigation. Missing files degrade gracefully (the route shows a "coming online" placeholder).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Files per group, in load order. Populated as bundles are built; tolerant of absent files.
  var GROUPS = {
    parsers: [
      'assets/engine/parsers/common.js?v=2f745338',
      'assets/engine/parsers/nmap.js?v=2262a57c', 'assets/engine/parsers/directory.js?v=c6b83d4f',
      'assets/engine/parsers/creds.js?v=18aadd03', 'assets/engine/parsers/host.js?v=f7778d94',
      'assets/engine/parsers/services.js?v=48375359', 'assets/engine/parsers/database.js?v=23c0b49c',
      'assets/engine/parsers/web.js?v=2b1ee17e', 'assets/engine/parsers/websource.js?v=22e3aa89',
      'assets/engine/parsers/findings.js?v=7e2431bf', 'assets/engine/parsers/edb.js?v=fd79d90f', 'assets/engine/parsers/shape.js?v=56fa03d2',
      'assets/engine/parsers/pivot.js?v=b11b57c1', 'assets/engine/parsers/dns.js?v=24395a65',
      'assets/engine/parsers/blockers.js?v=d690eda0',
      'assets/engine/parsers/nxc-catalog.js?v=7c423272', 'assets/engine/parsers/inference.js?v=8fa96c9d',
      'assets/engine/parsers/index.js?v=19d3187e',
    ],
    graph: ['assets/engine/graph.js?v=5f845ab4', 'assets/ui/routes/graph.js?v=42b74dc8'],
    domain: ['assets/jszip.min.js?v=c96375d5', 'assets/engine/bloodhound.js?v=9c4aaa25', 'assets/ui/bhgraph.js?v=b3d6a062', 'assets/ui/routes/domain.js?v=f86f8e9e'],
    report: ['assets/jszip.min.js?v=c96375d5', 'data/reportmeta.js?v=37f7e557', 'assets/engine/report.js?v=70acd4a7', 'assets/ui/routes/report.js?v=0e6a070b'],
    tools: ['assets/engine/toolbuilder.js?v=8e642c14', 'data/toolset.js?v=12c2716e',
      'data/tool-glossary.js?v=cf257324', 'data/tool-recipes.js?v=cafd6372', 'data/tool-stations.js?v=3f1621c8',
      'assets/engine/toolkit.js?v=cb14c479', 'assets/engine/shellkit.js?v=8289e51a', 'assets/engine/pivotkit.js?v=e59dbec6', 'assets/ui/pivotstation.js?v=697a8be7', 'assets/engine/workbench.js?v=23e5f918', 'assets/ui/bind.js?v=70d1fd1b', 'assets/ui/routes/tools.js?v=06c46c73'],
    loadout: ['assets/engine/arsenal.js?v=fb2f1de3', 'assets/ui/routes/loadout.js?v=7978f43b'],
    workbench: ['assets/engine/workbench.js?v=23e5f918', 'assets/ui/routes/workbench.js?v=1a1c1add'],
    stuck: ['data/stuck-catalog.js?v=0e28d317', 'assets/engine/stuck.js?v=9f3ec324', 'assets/ui/routes/stuck.js?v=1a559f6b'],
    // Library folds Stuck? in as a sub-lens, so it carries Stuck?'s data+engine+route plus the ATT&CK
    // catalog/map (for the ATT&CK lens) and the library engine itself.
    library: ['data/stuck-catalog.js?v=0e28d317', 'assets/engine/stuck.js?v=9f3ec324', 'assets/ui/routes/stuck.js?v=1a559f6b',
      'data/attack-catalog.js?v=f2aa133a', 'data/attack-move-map.js?v=754b3e0f',
      'data/tool-glossary.js?v=cf257324', 'data/tool-recipes.js?v=cafd6372', 'data/tool-stations.js?v=3f1621c8',
      'assets/engine/toolbuilder.js?v=8e642c14', 'data/toolset.js?v=12c2716e', 'assets/engine/toolkit.js?v=cb14c479', 'assets/ui/bind.js?v=70d1fd1b',
      'assets/engine/library.js?v=cc552212', 'assets/ui/routes/library.js?v=bfb32361'],
    study: ['data/tool-glossary.js?v=cf257324', 'data/study-fixtures.js?v=23029800', 'assets/engine/study.js?v=f8aac721', 'assets/ui/routes/study.js?v=10e4e326'],
    // data-only slice of the study group (the ~1MB sample-output fixtures + the replay engine, no Learn
    // route UI). The coach background-loads this after mount so "See It Run" can show real example output
    // in Next Steps without putting the fixtures on the critical boot path.
    studydata: ['data/tool-glossary.js?v=cf257324', 'data/study-fixtures.js?v=23029800', 'assets/engine/study.js?v=f8aac721'],
    decisionmap: ['data/decision-forks.js?v=3aaa2f1c', 'data/parser-signatures.js?v=a0c5afc4', 'data/coverage-expected.js?v=acc4df5e', 'data/flag-reach.js?v=f91ede7b', 'assets/engine/decisionmap.js?v=3a57f6be', 'assets/ui/decisiontree.js?v=0f23b0f7'],
    checklist: ['data/oscp-scope.js?v=47e64691', 'assets/ui/routes/checklist.js?v=7ea32b01'],
    target: ['assets/engine/graph.js?v=5f845ab4', 'assets/ui/routes/target.js?v=c343b25d'],
    creds: ['assets/ui/routes/creds.js?v=30d4cd96'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=54dcb2c2'],
    playbooks: ['data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=1361f6a3', 'assets/ui/routes/playbooks.js?v=73267e8c'],
    cruise: ['assets/engine/arsenal.js?v=fb2f1de3', 'data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=1361f6a3', 'assets/engine/cruise.js?v=cda9b13f', 'assets/engine/pivotkit.js?v=e59dbec6', 'assets/ui/pivotstation.js?v=697a8be7', 'assets/ui/routes/cruise.js?v=2858725e'],
    map: ['assets/engine/engmap.js?v=16d7647e', 'assets/ui/routes/map.js?v=1155be86'],
    findings: ['data/reportmeta.js?v=37f7e557', 'data/attack-catalog.js?v=f2aa133a', 'data/attack-move-map.js?v=754b3e0f', 'data/d3fend-map.js?v=ae2b6f53', 'data/frameworks-tables.js?v=428bffd8', 'data/kev-catalog.js?v=f91dccda', 'assets/engine/frameworks.js?v=341ed948', 'assets/ui/routes/findings.js?v=f313c036'],
    history: ['assets/ui/routes/history.js?v=cd540200'],
    help: ['data/help-content.js?v=48a12a15', 'assets/ui/routes/help.js?v=7528d7ed'],
    start: ['data/resources.js?v=662af84a', 'assets/ui/routes/start.js?v=58acd6ad'],
  };

  var _loaded = {};   // group -> Promise
  var _script = {};   // src -> Promise

  function loadScript(src) {
    if (_script[src]) return _script[src];
    _script[src] = new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = src; s.async = false;
      s.onload = function () { resolve(true); };
      // A failed load (404, or a content/ad blocker blocking a file by name) is not fatal, but we drop
      // its cached promise so a later attempt can retry it rather than being stuck half-loaded forever.
      s.onerror = function () { delete _script[src]; resolve(false); };
      document.head.appendChild(s);
    });
    return _script[src];
  }

  function loadGroup(name) {
    if (_loaded[name]) return _loaded[name];
    var files = GROUPS[name] || [];
    var p = files.reduce(function (acc, src) {
      return acc.then(function (allOk) { return loadScript(src).then(function (ok) { return allOk && ok; }); });
    }, Promise.resolve(true));
    // Don't cache a group that didn't fully load - a retry (e.g. the next paste) re-attempts the
    // missing file instead of running the engine with a helper permanently undefined.
    p.then(function (allOk) { if (!allOk) delete _loaded[name]; });
    _loaded[name] = p;
    return p;
  }

  // Register placeholder routes that lazy-load their group then delegate to the real route.
  function registerLazyRoutes(R) {
    ['start', 'loadout', 'workbench', 'library', 'stuck', 'study', 'tools', 'domain', 'report', 'checklist', 'graph', 'target', 'creds', 'scoreboard', 'playbooks', 'cruise', 'map', 'findings', 'history', 'help'].forEach(function (name) {
      R.register(name, {
        ensure: function () { return loadGroup(name); },
        render: function (ctx) {
          var real = OBOL.routes[name];
          if (real && real.render && real !== R._lazyStub) {
            var out = real.render(ctx);
            R._lastReal = name;
            return out;
          }
          return '<section class="route-stub"><h1 class="route-h1">' + name.charAt(0).toUpperCase() + name.slice(1) + '</h1>'
            + '<p class="route-sub">This surface is coming online in this build. If you just opened it, the bundle may still be loading, try again in a moment.</p></section>';
        },
        // forward the route's own unmount() (router.js calls it when navigating away): without this the
        // lazy wrapper swallowed it, so study's replay/bench cancel and re-entry reset never ran.
        unmount: function () {
          var real = OBOL.routes[name];
          if (real && typeof real.unmount === 'function') { try { real.unmount(); } catch (e) {} }
        },
        mounted: function (ctx) {
          var real = OBOL.routes[name];
          if (real && real.mounted) { try { real.mounted(ctx); } catch (e) {} }
        },
      });
    });
  }

  OBOL.lazy = { loadGroup: loadGroup, registerLazyRoutes: registerLazyRoutes, GROUPS: GROUPS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
