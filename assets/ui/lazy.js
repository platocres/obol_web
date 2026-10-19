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
      'assets/engine/parsers/common.js?v=de99f48c',
      'assets/engine/parsers/nmap.js?v=666c66da', 'assets/engine/parsers/directory.js?v=b7c4100f',
      'assets/engine/parsers/creds.js?v=bb91cbb9', 'assets/engine/parsers/host.js?v=1f9af98c',
      'assets/engine/parsers/services.js?v=8886be39', 'assets/engine/parsers/database.js?v=46626db2',
      'assets/engine/parsers/web.js?v=130dc93d', 'assets/engine/parsers/websource.js?v=ebd07eff',
      'assets/engine/parsers/findings.js?v=a4a6a465', 'assets/engine/parsers/shape.js?v=98cd12a1',
      'assets/engine/parsers/pivot.js?v=2b6ce000', 'assets/engine/parsers/dns.js?v=61c20f89',
      'assets/engine/parsers/blockers.js?v=735aa9db',
      'assets/engine/parsers/nxc-catalog.js?v=39713d06',
      'assets/engine/parsers/index.js?v=fc760f4c',
    ],
    graph: ['assets/engine/graph.js?v=96741069', 'assets/ui/routes/graph.js?v=860cfd69'],
    domain: ['assets/jszip.min.js?v=42bf78a9', 'assets/engine/bloodhound.js?v=f47620d8', 'assets/ui/bhgraph.js?v=3c07276b', 'assets/ui/routes/domain.js?v=1df7dda3'],
    report: ['assets/jszip.min.js?v=42bf78a9', 'data/reportmeta.js?v=ef155083', 'assets/engine/report.js?v=05981acf', 'assets/ui/routes/report.js?v=0e56772b'],
    tools: ['assets/engine/toolbuilder.js?v=2b09578c', 'data/toolset.js?v=14dcf727',
      'data/tool-glossary.js?v=ecc13486', 'data/tool-recipes.js?v=19ed08c7', 'data/tool-stations.js?v=5a853a22',
      'assets/engine/toolkit.js?v=c296c726', 'assets/engine/shellkit.js?v=9c85f7b9', 'assets/engine/pivotkit.js?v=8f13edb9', 'assets/ui/pivotstation.js?v=db8de9e9', 'assets/engine/workbench.js?v=d7f910b9', 'assets/ui/bind.js?v=f7ce1151', 'assets/ui/routes/tools.js?v=b1e72bcc'],
    loadout: ['assets/engine/arsenal.js?v=c20665e7', 'assets/ui/routes/loadout.js?v=2b84d3a5'],
    workbench: ['assets/engine/workbench.js?v=d7f910b9', 'assets/ui/routes/workbench.js?v=3119bf5b'],
    stuck: ['data/stuck-catalog.js?v=e76b3e66', 'assets/engine/stuck.js?v=7bb9ce32', 'assets/ui/routes/stuck.js?v=26416b60'],
    // Library folds Stuck? in as a sub-lens, so it carries Stuck?'s data+engine+route plus the ATT&CK
    // catalog/map (for the ATT&CK lens) and the library engine itself.
    library: ['data/stuck-catalog.js?v=e76b3e66', 'assets/engine/stuck.js?v=7bb9ce32', 'assets/ui/routes/stuck.js?v=26416b60',
      'data/attack-catalog.js?v=1fca5f0a', 'data/attack-move-map.js?v=69b57161',
      'data/tool-glossary.js?v=ecc13486', 'data/tool-recipes.js?v=19ed08c7', 'data/tool-stations.js?v=5a853a22',
      'assets/engine/toolbuilder.js?v=2b09578c', 'data/toolset.js?v=14dcf727', 'assets/engine/toolkit.js?v=c296c726', 'assets/ui/bind.js?v=f7ce1151',
      'assets/engine/library.js?v=45dc2b64', 'assets/ui/routes/library.js?v=b765f5bb'],
    study: ['data/study-fixtures.js?v=67738f4a', 'assets/engine/study.js?v=b4f6b12b', 'assets/ui/routes/study.js?v=febc1728'],
    // data-only slice of the study group (the ~1MB sample-output fixtures + the replay engine, no Learn
    // route UI). The coach background-loads this after mount so "See It Run" can show real example output
    // in Next Steps without putting the fixtures on the critical boot path.
    studydata: ['data/study-fixtures.js?v=67738f4a', 'assets/engine/study.js?v=b4f6b12b'],
    decisionmap: ['data/decision-forks.js?v=c0723934', 'data/parser-signatures.js?v=3f503c12', 'data/coverage-expected.js?v=9a4bb92f', 'data/flag-reach.js?v=e8d6c84a', 'assets/engine/decisionmap.js?v=23cfa96f', 'assets/ui/decisiontree.js?v=b2010390'],
    checklist: ['data/oscp-scope.js?v=ebf0ff68', 'assets/ui/routes/checklist.js?v=2ceebfe3'],
    target: ['assets/engine/graph.js?v=96741069', 'assets/ui/routes/target.js?v=5bf5b977'],
    creds: ['assets/ui/routes/creds.js?v=f69235fa'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=5dff636a'],
    playbooks: ['data/playbooks-bundle.js?v=d8be47ce', 'assets/engine/playbooks.js?v=e8879ec8', 'assets/ui/routes/playbooks.js?v=47989518'],
    cruise: ['assets/engine/arsenal.js?v=c20665e7', 'data/playbooks-bundle.js?v=d8be47ce', 'assets/engine/playbooks.js?v=e8879ec8', 'assets/engine/cruise.js?v=f5dd14cf', 'assets/engine/pivotkit.js?v=8f13edb9', 'assets/ui/pivotstation.js?v=db8de9e9', 'assets/ui/routes/cruise.js?v=bfdf99e1'],
    map: ['assets/engine/engmap.js?v=39184f97', 'assets/ui/routes/map.js?v=8d44aa6c'],
    findings: ['data/attack-catalog.js?v=1fca5f0a', 'data/attack-move-map.js?v=69b57161', 'data/d3fend-map.js?v=24188198', 'data/frameworks-tables.js?v=5f75b2bc', 'data/kev-catalog.js?v=45ae87a9', 'assets/engine/frameworks.js?v=c304a986', 'assets/ui/routes/findings.js?v=ae41ead2'],
    history: ['assets/ui/routes/history.js?v=4b600b99'],
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
