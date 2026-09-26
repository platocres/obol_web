/*!
 * obol ui — router.js
 * A tiny deterministic hash router. Each navigation renders the target route into #view
 * EXACTLY ONCE (no setTimeout double-paint, no historical wrapper chain — the old
 * #/path-rendered-twice bug is the anti-pattern this avoids). Routes may be lazy: a route
 * can declare an async `ensure()` that loads its bundle once before first render.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var _routes = {};        // name -> {render(ctx), ensure?()}
  var _default = 'path';
  var _mount = null;       // the #view element
  var _rendering = false;
  var _pending = null;
  var _lastRoute = null;   // to scroll to top only on a real route change, not in-place re-renders

  function parseHash() {
    var h = (location.hash || '').replace(/^#\/?/, '');
    var parts = h.split('/').filter(Boolean);
    return { name: parts[0] || _default, args: parts.slice(1), raw: h };
  }

  function register(name, def) { _routes[name] = def; }
  function setDefault(name) { _default = name; }
  function mountEl(el) { _mount = el; }

  function current() { return parseHash(); }

  async function render() {
    if (_rendering) { _pending = true; return; }
    _rendering = true;
    try {
      var route = parseHash();
      var def = _routes[route.name] || _routes[_default];
      if (!def) return;
      if (def.ensure && !def._ensured) {
        try { await def.ensure(); def._ensured = true; }
        catch (e) { /* surfaced by the route's own render */ }
      }
      // Single write into #view.
      if (_mount && def.render) {
        var out = def.render({ name: route.name, args: route.args, mount: _mount });
        // render() may return an HTML string (we set it) or manage the DOM itself (returns undefined).
        if (typeof out === 'string') _mount.innerHTML = out;
        if (def.mounted) { try { def.mounted({ name: route.name, args: route.args, mount: _mount }); } catch (e) {} }
      }
      // reflect active nav
      reflectNav(route.name);
      // On a real route change (e.g. launch → coach), land at the top; leave scroll alone on the
      // in-place re-renders that happen after minting a fact or marking a move done.
      if (route.name !== _lastRoute) {
        _lastRoute = route.name;
        try { if (_mount) _mount.scrollTop = 0; if (root.scrollTo) root.scrollTo(0, 0); } catch (e) {}
      }
    } finally {
      _rendering = false;
      if (_pending) { _pending = false; render(); }
    }
  }

  function reflectNav(name) {
    var links = document.querySelectorAll('[data-nav]');
    for (var i = 0; i < links.length; i++) {
      var el = links[i];
      var target = (el.getAttribute('href') || '').replace(/^#\/?/, '').split('/')[0];
      var on = target === name;
      el.classList.toggle('active', on);
      if (on) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current');
    }
  }

  function go(hash) { location.hash = hash.charAt(0) === '#' ? hash : ('#/' + hash.replace(/^#?\/?/, '')); }

  function start() {
    window.addEventListener('hashchange', render);
    if (!location.hash) location.replace('#/' + _default);
    render();
  }

  OBOL.router = {
    register: register, setDefault: setDefault, mount: mountEl,
    render: render, start: start, go: go, current: current,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
