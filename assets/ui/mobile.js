/*!
 * obol ui — mobile.js — the phone/tablet engagement drawer.
 * On narrow screens the sidebar (engagement switcher, parameters, facts) is an off-canvas drawer
 * toggled by the appbar hamburger; a scrim dims the page behind it. The drawer closes on scrim
 * click, Escape, route change (hashchange), and when the viewport grows back to desktop width.
 * Presentation-only + self-contained. No effect on desktop, where the sidebar is always in-flow.
 */
(function (root) {
  'use strict';
  var doc = root.document;
  if (!doc) return;
  var OPEN = 'drawer-open';

  function el(id) { return doc.getElementById(id); }
  function isOpen() { return doc.documentElement.classList.contains(OPEN); }

  function setOpen(open) {
    var html = doc.documentElement;
    var toggle = el('nav-toggle');
    var scrim = el('nav-scrim');
    html.classList.toggle(OPEN, !!open);
    if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (scrim) { if (open) scrim.hidden = false; else scrim.hidden = true; }
  }
  function open() { setOpen(true); }
  function close() { if (isOpen()) setOpen(false); }
  function toggle() { setOpen(!isOpen()); }

  function wire() {
    var toggleBtn = el('nav-toggle');
    var scrim = el('nav-scrim');
    if (toggleBtn) toggleBtn.addEventListener('click', function (e) { e.preventDefault(); toggle(); });
    if (scrim) scrim.addEventListener('click', close);
    // Close the drawer whenever the route changes (a nav tap inside it, or anywhere else).
    root.addEventListener('hashchange', close);
    // Close on Escape.
    doc.addEventListener('keydown', function (e) { if ((e.key === 'Escape' || e.key === 'Esc') && isOpen()) close(); });
    // Tapping any link inside the sidebar navigates → close.
    var side = el('sidebar');
    if (side) side.addEventListener('click', function (e) {
      var a = e.target && e.target.closest && e.target.closest('a[href]');
      if (a) close();
    });
    // If the viewport grows past the drawer breakpoint, make sure we're not left in a stuck state.
    if (root.matchMedia) {
      var mq = root.matchMedia('(min-width: 861px)');
      var onChange = function () { if (mq.matches) close(); };
      if (mq.addEventListener) mq.addEventListener('change', onChange); else if (mq.addListener) mq.addListener(onChange);
    }
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', wire); else wire();
  root.OBOL = root.OBOL || {};
  root.OBOL.drawer = { open: open, close: close, toggle: toggle };
})(typeof globalThis !== 'undefined' ? globalThis : this);
