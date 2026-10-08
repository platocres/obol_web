/*!
 * obol ui — mobile.js — the phone/tablet app chrome.
 * Narrow screens get a native-style shell: a bottom tab bar for the primary sections (+ a More
 * sheet for the rest), an appbar hamburger that opens the engagement drawer (switcher, params,
 * facts), and an appbar search button that opens the command palette. A single scrim backs both
 * the drawer and the sheet; either closes on scrim tap, Escape, route change, or when the viewport
 * grows back to desktop. Presentation-only + self-contained; no effect on desktop.
 */
(function (root) {
  'use strict';
  var doc = root.document;
  if (!doc) return;
  var html = doc.documentElement;

  function el(id) { return doc.getElementById(id); }
  function hasCls(c) { return html.classList.contains(c); }

  function scrimOn(on) { var s = el('nav-scrim'); if (s) s.hidden = !on; }
  function refreshScrim() { scrimOn(hasCls('drawer-open') || hasCls('sheet-open')); }

  function setDrawer(open) {
    html.classList.toggle('drawer-open', !!open);
    var t = el('nav-toggle'); if (t) t.setAttribute('aria-expanded', open ? 'true' : 'false');
    refreshScrim();
  }
  function setSheet(open) {
    html.classList.toggle('sheet-open', !!open);
    var b = el('tab-more'); if (b) b.setAttribute('aria-expanded', open ? 'true' : 'false');
    var s = el('more-sheet'); if (s) s.setAttribute('aria-hidden', open ? 'false' : 'true');
    refreshScrim();
  }
  function closeAll() { if (hasCls('drawer-open')) setDrawer(false); if (hasCls('sheet-open')) setSheet(false); }

  // Light up the tab whose route is active; a route that lives in the More sheet lights More.
  function syncTabs() {
    var hash = (root.location.hash || '#/home').split('?')[0];
    var tabs = doc.querySelectorAll('#tabbar .tab[href]');
    var matched = false;
    tabs.forEach(function (a) {
      var on = a.getAttribute('href') === hash;
      a.classList.toggle('active', on);
      if (on) matched = true;
    });
    var more = el('tab-more');
    if (more) more.classList.toggle('active', !matched);
  }

  // Map the current route to the Help section that explains it. Every engagement surface lives under
  // the one "engagements" section; the global surfaces map to their own section id.
  var ENG_HELP = { home: 1, targets: 1, path: 1, evidence: 1, map: 1, domain: 1, creds: 1, checklist: 1, findings: 1, history: 1, scoreboard: 1, report: 1, graph: 1, target: 1 };
  var GLOBAL_HELP = { study: 1, loadout: 1, tools: 1, workbench: 1, stuck: 1, playbooks: 1 };
  function helpTargetForRoute() {
    var r = ((root.location.hash || '').replace(/^#\/?/, '').split('/')[0] || '').toLowerCase();
    if (!r || r === 'help') return '#/help';
    if (ENG_HELP[r]) return '#/help/engagements';
    if (GLOBAL_HELP[r]) return '#/help/' + r;
    return '#/help';
  }

  function wire() {
    var toggleBtn = el('nav-toggle');
    if (toggleBtn) toggleBtn.addEventListener('click', function (e) { e.preventDefault(); var open = !hasCls('drawer-open'); setSheet(false); setDrawer(open); });
    var moreBtn = el('tab-more');
    if (moreBtn) moreBtn.addEventListener('click', function (e) { e.preventDefault(); var open = !hasCls('sheet-open'); setDrawer(false); setSheet(open); });
    var scrim = el('nav-scrim');
    if (scrim) scrim.addEventListener('click', closeAll);
    var search = el('nav-search');
    if (search) search.addEventListener('click', function (e) { e.preventDefault(); closeAll(); try { if (root.OBOL && root.OBOL.palette) root.OBOL.palette.open(); } catch (x) {} });
    // Context-aware "?" on-ramp: open Help at the section covering the current screen ("what is this?").
    var help = el('nav-help');
    if (help) help.addEventListener('click', function (e) { e.preventDefault(); closeAll(); location.hash = helpTargetForRoute(); });

    // Any link tap inside the drawer or the sheet navigates → close everything.
    ['sidebar', 'more-sheet'].forEach(function (id) {
      var host = el(id);
      if (host) host.addEventListener('click', function (e) { var a = e.target && e.target.closest && e.target.closest('a[href]'); if (a) closeAll(); });
    });

    root.addEventListener('hashchange', function () { closeAll(); syncTabs(); });
    doc.addEventListener('keydown', function (e) { if ((e.key === 'Escape' || e.key === 'Esc') && (hasCls('drawer-open') || hasCls('sheet-open'))) closeAll(); });
    if (root.matchMedia) {
      var mq = root.matchMedia('(min-width: 861px)');
      var onChange = function () { if (mq.matches) closeAll(); };
      if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
    }
    syncTabs();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', wire); else wire();
  root.OBOL = root.OBOL || {};
  root.OBOL.drawer = { open: function () { setDrawer(true); }, close: closeAll, toggle: function () { setDrawer(!hasCls('drawer-open')); } };
})(typeof globalThis !== 'undefined' ? globalThis : this);
