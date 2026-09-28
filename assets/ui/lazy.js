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
      'assets/engine/parsers/common.js?v=6bea7893',
      'assets/engine/parsers/nmap.js?v=6c9b4446', 'assets/engine/parsers/directory.js?v=281e37f5',
      'assets/engine/parsers/creds.js?v=1dcddfb3', 'assets/engine/parsers/host.js?v=b359f078',
      'assets/engine/parsers/services.js?v=3fc42098', 'assets/engine/parsers/database.js?v=3dfc40c5',
      'assets/engine/parsers/web.js?v=e7538a8d', 'assets/engine/parsers/websource.js?v=a70edcb6',
      'assets/engine/parsers/index.js?v=5bd56991',
    ],
    graph: ['assets/engine/graph.js?v=e17600a0', 'assets/ui/routes/graph.js?v=bb95d124'],
    domain: ['assets/jszip.min.js?v=c96375d5', 'assets/engine/bloodhound.js?v=57e37dff', 'assets/ui/bhgraph.js?v=715f8264', 'assets/ui/routes/domain.js?v=6b1a39e5'],
    report: ['assets/jszip.min.js?v=c96375d5', 'data/reportmeta.js?v=9ad71876', 'assets/engine/report.js?v=e84e0e9e', 'assets/ui/routes/report.js?v=b8700738'],
    tools: ['assets/engine/toolbuilder.js?v=b3586e67', 'data/toolset.js?v=f27f51ef', 'assets/ui/routes/tools.js?v=7d043fd0'],
    checklist: ['assets/ui/routes/checklist.js?v=4d68a1b2'],
    target: ['assets/engine/graph.js?v=e17600a0', 'assets/ui/routes/target.js?v=b43b71b8'],
    creds: ['assets/ui/routes/creds.js?v=6935aeca'],
    scoreboard: ['assets/ui/routes/scoreboard.js?v=1d235ab7'],
    playbooks: ['data/playbooks-bundle.js?v=4294252f', 'assets/engine/playbooks.js?v=be235b11', 'assets/ui/routes/playbooks.js?v=0d08af7e'],
    map: ['assets/engine/engmap.js?v=274fcc29', 'assets/ui/routes/map.js?v=c92643bb'],
    findings: ['assets/ui/routes/findings.js?v=58a2feb2'],
    history: ['assets/ui/routes/history.js?v=65925c29'],
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
    ['tools', 'domain', 'report', 'checklist', 'graph', 'target', 'creds', 'scoreboard', 'playbooks', 'map', 'findings', 'history'].forEach(function (name) {
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
