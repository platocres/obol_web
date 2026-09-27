/*!
 * obol ui — routes/map.js — the ENGAGEMENT MAP surface.
 * The engagement-wide picture: scope ranges + domains up top, targets (colored by access level,
 * DC flagged) hanging from the evidence that ties them, their services + credentials + BloodHound
 * findings below. One inline SVG projected by OBOL.engmap from the engagement's browser state.
 * Clicking a target jumps to #/target/<ip>. Reached at #/map.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  var LEGEND = [
    { cls: 'em-acc-discovered', label: 'Discovered' },
    { cls: 'em-acc-enumerated', label: 'Enumerated' },
    { cls: 'em-acc-credentialed', label: 'Credentialed' },
    { cls: 'em-acc-foothold', label: 'Foothold' },
    { cls: 'em-acc-privileged', label: 'Privileged' },
  ];
  var TYPES = [
    { cls: 'em-scope', label: 'Scope' },
    { cls: 'em-domain', label: 'Domain' },
    { cls: 'em-service', label: 'Service' },
    { cls: 'em-credential', label: 'Credential' },
    { cls: 'em-dc', label: 'Domain controller' },
  ];

  // Legend items double as filters: each is a checkbox that toggles nodes of that class on the map.
  function item(l) {
    return '<button type="button" class="em-legend-item" role="checkbox" aria-checked="true" data-filter="' + esc(l.cls) + '" title="Toggle ' + esc(l.label) + '">'
      + '<span class="em-swatch ' + l.cls + '"></span>' + esc(l.label) + '</button>';
  }
  function legend() {
    return '<div class="em-legend"><span class="em-legend-group">access</span>' + LEGEND.map(item).join('')
      + '<span class="em-legend-group">nodes</span>' + TYPES.map(item).join('')
      + '<span class="em-legend-hint">click a swatch to filter</span></div>';
  }

  function render() {
    var eng = OBOL.store.active();
    var targets = (eng && eng.targets) || [];
    if (!targets.length) {
      return '<section class="engmap-route">'
        + '<h1 class="route-h1">Engagement map</h1>'
        + '<p class="route-sub">The engagement-wide picture — scope, domains, targets, services, credentials and BloodHound findings, all from proven evidence.</p>'
        + '<div class="coach-empty">No targets yet — add one from <a href="#/targets">Targets</a> or paste a scan on the <a href="#/">engagement</a> screen.</div>'
        + '</section>';
    }
    var svg = OBOL.engmap.buildEngagementSvg(eng);
    return '<section class="engmap-route">'
      + '<h1 class="route-h1">Engagement map</h1>'
      + '<p class="route-sub">Targets hang from the scope range or domain the evidence ties them to (never a shared subnet). Colored by access level; click a target to open it.</p>'
      + legend()
      + '<div class="graph-scroll" id="em-scroll">' + svg + '</div>'
      + '</section>';
  }

  function mounted(ctx) {
    // Bind on the route's own section (recreated each render), not the persistent #view — a lazy
    // route renders twice (stub, then real), so binding on #view would stack the handlers and a
    // click would toggle an even number of times, netting to a no-op.
    var mount = ctx.mount.querySelector('.engmap-route') || ctx.mount;
    U.on(mount, 'click', '.em-target', function (e, g) {
      var ip = g.getAttribute('data-ip');
      if (ip) OBOL.router.go('target/' + ip);
    });
    // Legend = filter: toggle a swatch to hide/show that class of node (and edges touching it).
    function applyFilters() {
      var svg = mount.querySelector('svg.obol-engmap'); if (!svg) return;
      var hidden = {};
      Array.prototype.forEach.call(mount.querySelectorAll('.em-legend-item[aria-checked="false"]'), function (b) {
        hidden[b.getAttribute('data-filter')] = true;
      });
      var hiddenIds = {};
      Array.prototype.forEach.call(svg.querySelectorAll('.em-node'), function (n) {
        var off = Array.prototype.some.call(n.classList, function (c) { return hidden[c]; });
        n.style.display = off ? 'none' : '';
        if (off) hiddenIds[n.getAttribute('data-node-id')] = true;
      });
      Array.prototype.forEach.call(svg.querySelectorAll('.em-edge'), function (ed) {
        var off = hiddenIds[ed.getAttribute('data-from')] || hiddenIds[ed.getAttribute('data-to')];
        ed.style.display = off ? 'none' : '';
      });
    }
    U.on(mount, 'click', '.em-legend-item', function (e, b) {
      b.setAttribute('aria-checked', b.getAttribute('aria-checked') === 'false' ? 'true' : 'false');
      applyFilters();
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.map = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
