/*!
 * obol ui — graphview.js — pan / zoom / fit for an inline OBOL.graph SVG. Wraps the SVG in a fixed-height
 * viewport with a zoom toolbar; the SVG is moved with a CSS transform (translate + scale). Drag to pan,
 * scroll to zoom toward the cursor, +/−/fit buttons, double-click to fit. No dependencies.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // The five node states, in reading order (act → reached → not-yet). Each swatch class mirrors the
  // node fill/stroke in obol.css so the legend and the graph can never drift apart.
  var LEGEND = [
    ['next', 'Do next', 'A move that is ready to run now'],
    ['proven', 'Proven', 'A milestone you have already reached'],
    ['done', 'Done', 'A move you have already run'],
    ['goal', 'Goal', 'A milestone the next move is meant to prove'],
    ['locked', 'Blocked', 'A move whose prerequisites are not proven yet'],
  ];
  // Legend doubles as a filter: every category on by default; clicking a chip dims it and drops that
  // category's nodes (and any edge touching them) from the graph. aria-pressed carries the on/off state.
  function legend() {
    return '<div class="gv-legend" role="group" aria-label="Filter path graph by node type">'
      + '<span class="gv-legend-h">Legend · click to filter</span>'
      + LEGEND.map(function (it) {
        return '<button type="button" class="gv-lg gv-lg-' + it[0] + '" data-gvfilter="' + it[0] + '" aria-pressed="true" title="' + it[2] + ' — click to hide">'
          + '<i aria-hidden="true"></i>' + it[1] + '</button>';
      }).join('')
      + '</div>';
  }

  // Wrap an SVG string in the pan/zoom viewport markup (with a state legend above it). attach() wires it.
  function html(svg) {
    return '<div class="gv-wrap">'
      + legend()
      + '<div class="graphview" data-graphview>'
      + svg
      + '<div class="gv-toolbar" role="group" aria-label="Graph zoom">'
      + '<button type="button" class="gv-btn" data-gv="out" title="Zoom out" aria-label="Zoom out">−</button>'
      + '<button type="button" class="gv-btn" data-gv="fit" title="Fit to view" aria-label="Fit to view">⤢</button>'
      + '<button type="button" class="gv-btn" data-gv="in" title="Zoom in" aria-label="Zoom in">+</button>'
      + '</div>'
      + '<div class="gv-hint">drag to pan · scroll to zoom</div>'
      + '</div>'
      + '</div>';
  }

  function attach(scope) {
    scope = scope || document;
    var views = scope.querySelectorAll ? scope.querySelectorAll('[data-graphview]') : [];
    Array.prototype.forEach.call(views, function (v) { if (!v._gvWired) wire(v); });
  }

  // Wire the legend chips (sibling of the viewport) to filter node categories: toggling a chip flips
  // aria-pressed and a `gv-off-<cat>` class on the viewport, which CSS uses to hide that category.
  function wireLegend(view) {
    var wrap = view.closest ? view.closest('.gv-wrap') : null;
    var legendEl = wrap && wrap.querySelector('.gv-legend');
    if (!legendEl || legendEl._gvWired) return;
    legendEl._gvWired = true;
    legendEl.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-gvfilter]'); if (!btn) return;
      var cat = btn.getAttribute('data-gvfilter');
      var on = btn.getAttribute('aria-pressed') !== 'false';
      btn.setAttribute('aria-pressed', on ? 'false' : 'true');
      btn.classList.toggle('off', on);
      view.classList.toggle('gv-off-' + cat, on);
    });
  }

  function wire(view) {
    view._gvWired = true;
    wireLegend(view);
    var svg = view.querySelector('svg');
    if (!svg) return;

    // Intrinsic size from the viewBox (falls back to width/height attrs).
    var vb = (svg.getAttribute('viewBox') || '').split(/[\s,]+/).map(Number);
    var iw = (vb.length === 4 && vb[2]) || parseFloat(svg.getAttribute('width')) || 320;
    var ih = (vb.length === 4 && vb[3]) || parseFloat(svg.getAttribute('height')) || 60;
    // Give the SVG a fixed pixel box so the transform is predictable; it sits at the viewport origin.
    svg.setAttribute('width', iw); svg.setAttribute('height', ih);
    svg.style.transformOrigin = '0 0';
    svg.style.willChange = 'transform';

    var st = { s: 1, x: 0, y: 0, min: 0.15, max: 5 };
    function clamp(s) { return Math.max(st.min, Math.min(st.max, s)); }
    function apply() { svg.style.transform = 'translate(' + st.x + 'px,' + st.y + 'px) scale(' + st.s + ')'; }
    function fit() {
      var vw = view.clientWidth, vh = view.clientHeight, pad = 20;
      if (!vw || !vh) { requestAnimationFrame(fit); return; }
      var s = clamp(Math.min((vw - pad) / iw, (vh - pad) / ih) || 1);
      st.s = s; st.x = Math.max(pad / 2, (vw - iw * s) / 2); st.y = Math.max(pad / 2, (vh - ih * s) / 2); apply();
    }
    function zoomAt(cx, cy, factor) {
      var ns = clamp(st.s * factor); if (ns === st.s) return;
      st.x = cx - (cx - st.x) * (ns / st.s);
      st.y = cy - (cy - st.y) * (ns / st.s);
      st.s = ns; apply();
    }
    function centerZoom(f) { zoomAt(view.clientWidth / 2, view.clientHeight / 2, f); }

    view.addEventListener('wheel', function (e) {
      e.preventDefault();
      var r = view.getBoundingClientRect();
      zoomAt(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 1 / 1.12);
    }, { passive: false });

    var drag = null;
    view.addEventListener('pointerdown', function (e) {
      if (e.target.closest('.gv-toolbar')) return;
      drag = { x: e.clientX, y: e.clientY, tx: st.x, ty: st.y };
      view.classList.add('gv-grabbing');
      try { view.setPointerCapture(e.pointerId); } catch (_) {}
    });
    view.addEventListener('pointermove', function (e) {
      if (!drag) return;
      st.x = drag.tx + (e.clientX - drag.x); st.y = drag.ty + (e.clientY - drag.y); apply();
    });
    function endDrag() { drag = null; view.classList.remove('gv-grabbing'); }
    view.addEventListener('pointerup', endDrag);
    view.addEventListener('pointercancel', endDrag);

    view.addEventListener('click', function (e) {
      var b = e.target.closest('[data-gv]'); if (!b) return;
      var a = b.getAttribute('data-gv');
      if (a === 'in') centerZoom(1.25); else if (a === 'out') centerZoom(1 / 1.25); else fit();
    });
    view.addEventListener('dblclick', function (e) { if (!e.target.closest('.gv-toolbar')) fit(); });

    fit();
  }

  OBOL.graphview = { html: html, attach: attach };
})(typeof globalThis !== 'undefined' ? globalThis : this);
