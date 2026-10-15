/*!
 * obol ui — lazy.js — route-lazy bundle loader. Injects <script> tags on demand (works over
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
      'assets/engine/parsers/common.js?v=d779003b',
      'assets/engine/parsers/nmap.js?v=2b47ff03', 'assets/engine/parsers/directory.js?v=8504254b',
      'assets/engine/parsers/creds.js?v=b8cda7b4', 'assets/engine/parsers/host.js?v=a3d5205d',
      'assets/engine/parsers/services.js?v=d86e3aea', 'assets/engine/parsers/database.js?v=0e407c6a',
      'assets/engine/parsers/web.js?v=dff6fe62', 'assets/engine/parsers/websource.js?v=65a6766e',
      'assets/engine/parsers/findings.js?v=555ba048', 'assets/engine/parsers/shape.js?v=857b2f23',
      'assets/engine/parsers/pivot.js?v=f9381c5e', 'assets/engine/parsers/dns.js?v=7faf7efe',
      'assets/engine/parsers/blockers.js?v=ffe08979',
      'assets/engine/parsers/nxc-catalog.js?v=8060d8b1',
      'assets/engine/parsers/index.js?v=42093cb0',
    ],
    graph: ['assets/engine/graph.js?v=96741069', 'assets/ui/routes/graph.js?v=e45ae25b'],
    domain: ['assets/jszip.min.js?v=c96375d5', 'assets/engine/bloodhound.js?v=b9cd70b7', 'assets/ui/bhgraph.js?v=18204e6c', 'assets/ui/routes/domain.js?v=dcac952d'],
    report: ['assets/jszip.min.js?v=c96375d5', 'data/reportmeta.js?v=ef155083', 'assets/engine/report.js?v=0a3837f6', 'assets/ui/routes/report.js?v=a4e9c6ee'],
    tools: ['assets/engine/toolbuilder.js?v=e3ee7f1f', 'data/toolset.js?v=73192b48',
      'data/tool-glossary.js?v=a7190533', 'data/tool-recipes.js?v=4b5b815c', 'data/tool-stations.js?v=fb120866',
      'assets/engine/toolkit.js?v=77414ef4', 'assets/engine/shellkit.js?v=aa4a8af5', 'assets/engine/pivotkit.js?v=94634d8e', 'assets/ui/pivotstation.js?v=0173cdd2', 'assets/ui/bind.js?v=4319ea2f', 'assets/ui/routes/tools.js?v=e44991e0'],
    loadout: ['assets/engine/arsenal.js?v=bf5ae024', 'assets/ui/routes/loadout.js?v=fd258957'],
    workbench: ['assets/engine/workbench.js?v=1acf899d', 'assets/ui/routes/workbench.js?v=42462153'],
    stuck: ['data/stuck-catalog.js?v=e76b3e66', 'assets/engine/stuck.js?v=7bb9ce32', 'assets/ui/routes/stuck.js?v=bf310a35'],
    // Library folds Stuck? in as a sub-lens, so it carries Stuck?'s data+engine+route plus the ATT&CK
    // catalog/map (for the ATT&CK lens) and the library engine itself.
    library: ['data/stuck-catalog.js?v=e76b3e66', 'assets/engine/stuck.js?v=7bb9ce32', 'assets/ui/routes/stuck.js?v=bf310a35',
      'data/attack-catalog.js?v=1fca5f0a', 'data/attack-move-map.js?v=69b57161',
      'data/tool-glossary.js?v=a7190533', 'data/tool-recipes.js?v=4b5b815c', 'data/tool-stations.js?v=fb120866',
      'assets/engine/toolbuilder.js?v=e3ee7f1f', 'data/toolset.js?v=73192b48', 'assets/engine/toolkit.js?v=77414ef4', 'assets/ui/bind.js?v=4319ea2f',
      'assets/engine/library.js?v=cc552212', 'assets/ui/routes/library.js?v=4f8e4bd2'],
    study: ['data/study-fixtures.js?v=74aaac1e', 'assets/engine/study.js?v=b4f6b12b', 'assets/ui/routes/study.js?v=277d4c77'],
    decisionmap: ['data/decision-forks.js?v=c0723934', 'data/parser-signatures.js?v=24469b5c', 'data/coverage-expected.js?v=9a4bb92f', 'data/flag-reach.js?v=2317deac', 'assets/engine/decisionmap.js?v=72d3dcb7', 'assets/ui/decisiontree.js?v=910ea8b0'],
    checklist: ['data/oscp-scope.js?v=ebf0ff68', 'assets/ui/routes/checklist.js?v=ff1f5ef9'],
    target: ['assets/engine/graph.js?v=96741069', 'assets/ui/routes/target.js?v=3e9e5e4a'],
    creds: ['assets/ui/routes/creds.js?v=867f1379'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=2dfeb512'],
    playbooks: ['data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=e8879ec8', 'assets/ui/routes/playbooks.js?v=6222dd34'],
    cruise: ['data/playbooks-bundle.js?v=e845bbbe', 'assets/engine/playbooks.js?v=e8879ec8', 'assets/engine/cruise.js?v=d32b13c9', 'assets/engine/pivotkit.js?v=94634d8e', 'assets/ui/pivotstation.js?v=0173cdd2', 'assets/ui/routes/cruise.js?v=3c990314'],
    map: ['assets/engine/engmap.js?v=49eca2a8', 'assets/ui/routes/map.js?v=3a19112a'],
    findings: ['data/attack-catalog.js?v=1fca5f0a', 'data/attack-move-map.js?v=69b57161', 'data/d3fend-map.js?v=24188198', 'data/frameworks-tables.js?v=5f75b2bc', 'data/kev-catalog.js?v=45ae87a9', 'assets/engine/frameworks.js?v=c304a986', 'assets/ui/routes/findings.js?v=55f3e567'],
    history: ['assets/ui/routes/history.js?v=5fb9bd10'],
    help: ['data/help-content.js?v=fb1c88a1', 'assets/ui/routes/help.js?v=d864ef28'],
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
    // Don't cache a group that didn't fully load — a retry (e.g. the next paste) re-attempts the
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
