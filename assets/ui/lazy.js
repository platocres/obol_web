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
      'assets/engine/parsers/_common.js',
      'assets/engine/parsers/nmap.js', 'assets/engine/parsers/directory.js',
      'assets/engine/parsers/creds.js', 'assets/engine/parsers/host.js',
      'assets/engine/parsers/services.js', 'assets/engine/parsers/database.js',
      'assets/engine/parsers/web.js', 'assets/engine/parsers/websource.js',
      'assets/engine/parsers/index.js',
    ],
    graph: ['assets/engine/graph.js', 'assets/ui/routes/graph.js'],
    domain: ['assets/jszip.min.js', 'assets/engine/bloodhound.js', 'assets/ui/bhgraph.js', 'assets/ui/routes/domain.js'],
    report: ['assets/jszip.min.js', 'data/reportmeta.js', 'assets/engine/report.js', 'assets/ui/routes/report.js'],
    tools: ['assets/engine/toolbuilder.js', 'data/toolset.js', 'assets/ui/routes/tools.js'],
    checklist: ['assets/ui/routes/checklist.js'],
    target: ['assets/engine/graph.js', 'assets/ui/routes/target.js'],
    creds: ['assets/ui/routes/creds.js'],
    scoreboard: ['assets/ui/routes/scoreboard.js'],
    playbooks: ['data/playbooks-bundle.js', 'assets/engine/playbooks.js', 'assets/ui/routes/playbooks.js'],
    map: ['assets/engine/engmap.js', 'assets/ui/routes/map.js'],
    findings: ['assets/ui/routes/findings.js'],
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
    ['tools', 'domain', 'report', 'checklist', 'graph', 'target', 'creds', 'scoreboard', 'playbooks', 'map', 'findings'].forEach(function (name) {
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
            + '<p class="route-sub">This surface is coming online in this build. If you just opened it, the bundle may still be loading — try again in a moment.</p></section>';
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
