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
    parsers: ['assets/engine/parsers/index.js'],
    graph: ['assets/engine/graph.js', 'assets/ui/routes/graph.js'],
    domain: ['assets/jszip.min.js', 'assets/engine/bloodhound.js', 'assets/ui/routes/domain.js'],
    report: ['data/reportmeta.js', 'assets/engine/report.js', 'assets/ui/routes/report.js'],
    tools: ['assets/engine/toolbuilder.js', 'data/toolset.js', 'assets/ui/routes/tools.js'],
    checklist: ['assets/ui/routes/checklist.js'],
  };

  var _loaded = {};   // group -> Promise
  var _script = {};   // src -> Promise

  function loadScript(src) {
    if (_script[src]) return _script[src];
    _script[src] = new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = src; s.async = false;
      s.onload = function () { resolve(true); };
      s.onerror = function () { resolve(false); }; // degrade: missing bundle is not fatal
      document.head.appendChild(s);
    });
    return _script[src];
  }

  function loadGroup(name) {
    if (_loaded[name]) return _loaded[name];
    var files = GROUPS[name] || [];
    _loaded[name] = files.reduce(function (p, src) {
      return p.then(function () { return loadScript(src); });
    }, Promise.resolve());
    return _loaded[name];
  }

  // Register placeholder routes that lazy-load their group then delegate to the real route.
  function registerLazyRoutes(R) {
    ['tools', 'domain', 'report', 'checklist', 'graph'].forEach(function (name) {
      R.register(name, {
        ensure: function () { return loadGroup(name === 'graph' ? 'graph' : name); },
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
