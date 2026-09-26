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

  function legend() {
    var acc = LEGEND.map(function (l) {
      return '<span class="em-legend-item"><span class="em-swatch ' + l.cls + '"></span>' + esc(l.label) + '</span>';
    }).join('');
    var types = TYPES.map(function (l) {
      return '<span class="em-legend-item"><span class="em-swatch ' + l.cls + '"></span>' + esc(l.label) + '</span>';
    }).join('');
    return '<div class="em-legend"><span class="em-legend-group">access</span>' + acc
      + '<span class="em-legend-group">nodes</span>' + types + '</div>';
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
    U.on(ctx.mount, 'click', '.em-target', function (e, g) {
      var ip = g.getAttribute('data-ip');
      if (ip) OBOL.router.go('target/' + ip);
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.map = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
