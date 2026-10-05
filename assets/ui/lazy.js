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
      'assets/engine/parsers/common.js?v=b5952184',
      'assets/engine/parsers/nmap.js?v=c3b834f5', 'assets/engine/parsers/directory.js?v=ad2672df',
      'assets/engine/parsers/creds.js?v=22662bce', 'assets/engine/parsers/host.js?v=dc42c8bf',
      'assets/engine/parsers/services.js?v=6808bcc2', 'assets/engine/parsers/database.js?v=87aa6b26',
      'assets/engine/parsers/web.js?v=cc567928', 'assets/engine/parsers/websource.js?v=2c736bdb',
      'assets/engine/parsers/findings.js?v=0c7eb0d6', 'assets/engine/parsers/shape.js?v=aba67dd4',
      'assets/engine/parsers/index.js?v=44baef5a',
    ],
    graph: ['assets/engine/graph.js?v=0434f272', 'assets/ui/routes/graph.js?v=f509cf3e'],
    domain: ['assets/jszip.min.js?v=c96375d5', 'assets/engine/bloodhound.js?v=d8710496', 'assets/ui/bhgraph.js?v=80a0f124', 'assets/ui/routes/domain.js?v=78af2103'],
    report: ['assets/jszip.min.js?v=c96375d5', 'data/reportmeta.js?v=b4a40b19', 'assets/engine/report.js?v=885cb4fb', 'assets/ui/routes/report.js?v=217e6ca7'],
    tools: ['assets/engine/toolbuilder.js?v=b3586e67', 'data/toolset.js?v=70b2d005', 'assets/ui/routes/tools.js?v=aff6dc97'],
    loadout: ['assets/engine/arsenal.js?v=9a46d3b8', 'assets/ui/routes/loadout.js?v=f6d299e1'],
    study: ['data/study-fixtures.js?v=7af7d7ca', 'assets/engine/study.js?v=2f2551b4', 'assets/ui/routes/study.js?v=41cd329c'],
    decisionmap: ['data/decision-forks.js?v=9785225d', 'data/parser-signatures.js?v=62e74cbf', 'data/coverage-expected.js?v=afdb39b5', 'assets/engine/decisionmap.js?v=940f1173', 'assets/ui/decisiontree.js?v=4d77a423'],
    checklist: ['assets/ui/routes/checklist.js?v=68b05ed8'],
    target: ['assets/engine/graph.js?v=0434f272', 'assets/ui/routes/target.js?v=f44f77f5'],
    creds: ['assets/ui/routes/creds.js?v=c8322951'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=b9b21413'],
    playbooks: ['data/playbooks-bundle.js?v=31b337d6', 'assets/engine/playbooks.js?v=be235b11', 'assets/ui/routes/playbooks.js?v=db570cba'],
    map: ['assets/engine/engmap.js?v=488914b1', 'assets/ui/routes/map.js?v=b415a554'],
    findings: ['assets/ui/routes/findings.js?v=629fbcf9'],
    history: ['assets/ui/routes/history.js?v=f2888760'],
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
    ['loadout', 'study', 'tools', 'domain', 'report', 'checklist', 'graph', 'target', 'creds', 'scoreboard', 'playbooks', 'map', 'findings', 'history'].forEach(function (name) {
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
