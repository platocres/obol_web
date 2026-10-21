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
      'assets/engine/parsers/common.js?v=ed477d98',
      'assets/engine/parsers/nmap.js?v=ea8f8417', 'assets/engine/parsers/directory.js?v=e6c936a1',
      'assets/engine/parsers/creds.js?v=9236f236', 'assets/engine/parsers/host.js?v=3ad360c7',
      'assets/engine/parsers/services.js?v=26176532', 'assets/engine/parsers/database.js?v=5a84b7bf',
      'assets/engine/parsers/web.js?v=b4644a29', 'assets/engine/parsers/websource.js?v=de442185',
      'assets/engine/parsers/findings.js?v=94c491fa', 'assets/engine/parsers/shape.js?v=2e96e9df',
      'assets/engine/parsers/pivot.js?v=49f6f5e1', 'assets/engine/parsers/dns.js?v=a0051018',
      'assets/engine/parsers/blockers.js?v=0c10aa87',
      'assets/engine/parsers/nxc-catalog.js?v=825542dd',
      'assets/engine/parsers/index.js?v=009524ee',
    ],
    graph: ['assets/engine/graph.js?v=5f9b7998', 'assets/ui/routes/graph.js?v=769e4702'],
    domain: ['assets/jszip.min.js?v=c96375d5', 'assets/engine/bloodhound.js?v=849eb1ff', 'assets/ui/bhgraph.js?v=4c229074', 'assets/ui/routes/domain.js?v=3bfee294'],
    report: ['assets/jszip.min.js?v=c96375d5', 'data/reportmeta.js?v=b4a40b19', 'assets/engine/report.js?v=d94d2eb9', 'assets/ui/routes/report.js?v=96fbfae9'],
    tools: ['assets/engine/toolbuilder.js?v=8e642c14', 'data/toolset.js?v=9b0f43f2',
      'data/tool-glossary.js?v=545023e5', 'data/tool-recipes.js?v=91e09076', 'data/tool-stations.js?v=1b822340',
      'assets/engine/toolkit.js?v=cb14c479', 'assets/engine/shellkit.js?v=8289e51a', 'assets/engine/pivotkit.js?v=e59dbec6', 'assets/ui/pivotstation.js?v=697a8be7', 'assets/engine/workbench.js?v=4690530a', 'assets/ui/bind.js?v=70d1fd1b', 'assets/ui/routes/tools.js?v=f02b12fe'],
    loadout: ['assets/engine/arsenal.js?v=d2a0f7eb', 'assets/ui/routes/loadout.js?v=6edd12d8'],
    workbench: ['assets/engine/workbench.js?v=4690530a', 'assets/ui/routes/workbench.js?v=8f861413'],
    stuck: ['data/stuck-catalog.js?v=7bee4a9a', 'assets/engine/stuck.js?v=9f3ec324', 'assets/ui/routes/stuck.js?v=1a559f6b'],
    // Library folds Stuck? in as a sub-lens, so it carries Stuck?'s data+engine+route plus the ATT&CK
    // catalog/map (for the ATT&CK lens) and the library engine itself.
    library: ['data/stuck-catalog.js?v=7bee4a9a', 'assets/engine/stuck.js?v=9f3ec324', 'assets/ui/routes/stuck.js?v=1a559f6b',
      'data/attack-catalog.js?v=0f7ea257', 'data/attack-move-map.js?v=4bf41fe7',
      'data/tool-glossary.js?v=545023e5', 'data/tool-recipes.js?v=91e09076', 'data/tool-stations.js?v=1b822340',
      'assets/engine/toolbuilder.js?v=8e642c14', 'data/toolset.js?v=9b0f43f2', 'assets/engine/toolkit.js?v=cb14c479', 'assets/ui/bind.js?v=70d1fd1b',
      'assets/engine/library.js?v=cc552212', 'assets/ui/routes/library.js?v=bfb32361'],
    study: ['data/study-fixtures.js?v=fe405b4e', 'assets/engine/study.js?v=2f89aecc', 'assets/ui/routes/study.js?v=d890cb45'],
    // data-only slice of the study group (the ~1MB sample-output fixtures + the replay engine, no Learn
    // route UI). The coach background-loads this after mount so "See It Run" can show real example output
    // in Next Steps without putting the fixtures on the critical boot path.
    studydata: ['data/study-fixtures.js?v=fe405b4e', 'assets/engine/study.js?v=2f89aecc'],
    decisionmap: ['data/decision-forks.js?v=abde552b', 'data/parser-signatures.js?v=29f0c9cc', 'data/coverage-expected.js?v=afdb39b5', 'data/flag-reach.js?v=e8d6c84a', 'assets/engine/decisionmap.js?v=dc3fb0c8', 'assets/ui/decisiontree.js?v=e112cbdb'],
    checklist: ['data/oscp-scope.js?v=b211d828', 'assets/ui/routes/checklist.js?v=ed34a17d'],
    target: ['assets/engine/graph.js?v=5f9b7998', 'assets/ui/routes/target.js?v=3d821a7c'],
    creds: ['assets/ui/routes/creds.js?v=8dbb827f'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=54dcb2c2'],
    playbooks: ['data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=1361f6a3', 'assets/ui/routes/playbooks.js?v=73267e8c'],
    cruise: ['assets/engine/arsenal.js?v=d2a0f7eb', 'data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=1361f6a3', 'assets/engine/cruise.js?v=78002ada', 'assets/engine/pivotkit.js?v=e59dbec6', 'assets/ui/pivotstation.js?v=697a8be7', 'assets/ui/routes/cruise.js?v=ac22d497'],
    map: ['assets/engine/engmap.js?v=eeaa1879', 'assets/ui/routes/map.js?v=d040288f'],
    findings: ['data/attack-catalog.js?v=0f7ea257', 'data/attack-move-map.js?v=4bf41fe7', 'data/d3fend-map.js?v=c8b35d9d', 'data/frameworks-tables.js?v=169ba840', 'data/kev-catalog.js?v=e8b4d122', 'assets/engine/frameworks.js?v=50ac05e2', 'assets/ui/routes/findings.js?v=06d5dd66'],
    history: ['assets/ui/routes/history.js?v=c53f1286'],
    help: ['data/help-content.js?v=58ca514f', 'assets/ui/routes/help.js?v=8dfce8ba'],
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
    ['loadout', 'workbench', 'library', 'stuck', 'study', 'tools', 'domain', 'report', 'checklist', 'graph', 'target', 'creds', 'scoreboard', 'playbooks', 'cruise', 'map', 'findings', 'history', 'help'].forEach(function (name) {
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
        mounted: function (ctx) {
          var real = OBOL.routes[name];
          if (real && real.mounted) { try { real.mounted(ctx); } catch (e) {} }
        },
      });
    });
  }

  OBOL.lazy = { loadGroup: loadGroup, registerLazyRoutes: registerLazyRoutes, GROUPS: GROUPS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
