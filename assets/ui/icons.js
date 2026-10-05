/*!
 * obol ui — icons.js
 * A small, consistent inline-SVG icon set that replaces decorative emoji across the app.
 * Every icon is monochrome and draws in `currentColor`, so it inherits the surrounding text
 * colour and therefore passes contrast on every skin automatically, and never reads as an
 * AI-tell emoji. Usage: OBOL.ic('host')  ->  '<svg class="ic ic-host" ...>…</svg>'
 * Optional second arg is an extra class string. Icons are decorative (aria-hidden); the
 * surrounding text always carries the meaning, so no label is needed on the glyph itself.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  // 16x16 viewBox paths. Stroke-style icons share a common wrapper; a few are filled.
  var P = {
    // where a command runs
    box:   '<rect x="2" y="3" width="12" height="8" rx="1"/><path d="M1 13h14M6 13l-.4 1.5M10 13l.4 1.5"/>',        // your box (laptop)
    host:  '<rect x="2.5" y="2.5" width="11" height="4" rx="1"/><rect x="2.5" y="9" width="11" height="4" rx="1"/><path d="M5 4.5h.01M5 11h.01"/>', // the target host (stacked server)
    disk:  '<path d="M3 2.5h8.5L13.5 4.5V13a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1z"/><rect x="5" y="2.5" width="5" height="3.5"/><rect x="4.5" y="9" width="7" height="4"/>', // offline (disk)
    // objects / status
    flag:  '<path d="M4 14V2M4 2.5h8l-2 3 2 3H4"/>',
    lock:  '<rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/>',
    shield:'<path d="M8 1.5l5 2v4c0 3.2-2.1 5.6-5 7-2.9-1.4-5-3.8-5-7v-4z"/>',
    skull: '<path d="M8 1.5c3.3 0 5.5 2.3 5.5 5.3 0 1.8-.8 3-1.8 3.7V13H4.3v-2.5C3.3 9.8 2.5 8.6 2.5 6.8 2.5 3.8 4.7 1.5 8 1.5z"/><circle cx="5.7" cy="7" r="1.1" fill="currentColor" stroke="none"/><circle cx="10.3" cy="7" r="1.1" fill="currentColor" stroke="none"/><path d="M6.3 13v1.3M8 13v1.3M9.7 13v1.3"/>',
    folder:'<path d="M2 4a1 1 0 0 1 1-1h3l1.5 1.5H13a1 1 0 0 1 1 1V12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/>',
    pin:   '<path d="M8 1.8c2.5 0 4.2 1.9 4.2 4.1 0 2.9-4.2 8.3-4.2 8.3S3.8 8.8 3.8 5.9C3.8 3.7 5.5 1.8 8 1.8z"/><circle cx="8" cy="5.9" r="1.5" fill="currentColor" stroke="none"/>',
    clip:  '<path d="M12.5 7.2 7.6 12a2.8 2.8 0 0 1-4-4l5-5a1.8 1.8 0 0 1 2.6 2.6l-5 5a.9.9 0 0 1-1.3-1.3L9.4 5"/>',
    gear:  '<circle cx="8" cy="8" r="2.3"/><path d="M8 1.5v1.8M8 12.7v1.8M14.5 8h-1.8M3.3 8H1.5M12.6 3.4l-1.3 1.3M4.7 11.3l-1.3 1.3M12.6 12.6l-1.3-1.3M4.7 4.7 3.4 3.4"/>',
    coin:  '<circle cx="8" cy="8" r="6"/><path d="M8 4.5v7M6.2 6.2h2.4a1.4 1.4 0 0 1 0 2.8H6.6"/>',
    spark: '<path d="M8 1.8l1.4 4.3 4.3 1.4-4.3 1.4L8 13.2 6.6 8.9 2.3 7.5l4.3-1.4z"/>',
    bolt:  '<path d="M9 1.5 3.5 9H7l-.8 5.5L12.5 7H9z"/>',
    stop:  '<path d="M5.4 2.2h5.2L13.8 5.4v5.2l-3.2 3.2H5.4L2.2 10.6V5.4z"/>',
    sound: '<path d="M3 6v4h2.3L9 13V3L5.3 6z"/><path d="M11 5.5a3.5 3.5 0 0 1 0 5M12.8 3.8a6 6 0 0 1 0 8.4"/>',
    crosshair: '<circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="1.4" fill="currentColor" stroke="none"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2"/>',
    // a decision fork: one node branching into two (the decision tree)
    branch: '<circle cx="3" cy="8" r="1.7" fill="currentColor" stroke="none"/><path d="M4.7 8H8M8 8V4.8a1.2 1.2 0 0 1 1.2-1.2h1.1M8 8v3.2a1.2 1.2 0 0 0 1.2 1.2h1.1"/><circle cx="12.3" cy="3.6" r="1.7" fill="currentColor" stroke="none"/><circle cx="12.3" cy="12.4" r="1.7" fill="currentColor" stroke="none"/>',
    // play triangle (run a cold box)
    play: '<path d="M4.8 3.2 12.8 8 4.8 12.8Z"/>',
    // a small node-and-edge graph (the attack graph / atlas)
    graph: '<path d="M5 4.6 10.7 5.3M5.2 5.6 6.7 10.4M8.7 11.1 10.9 6.4"/><circle cx="4" cy="4.2" r="1.7" fill="currentColor" stroke="none"/><circle cx="12" cy="5.4" r="1.7" fill="currentColor" stroke="none"/><circle cx="7.4" cy="11.6" r="1.7" fill="currentColor" stroke="none"/>',
    // a list of open ports (browse by open port)
    ports: '<circle cx="3.4" cy="4" r="1.1" fill="currentColor" stroke="none"/><circle cx="3.4" cy="8" r="1.1" fill="currentColor" stroke="none"/><circle cx="3.4" cy="12" r="1.1" fill="currentColor" stroke="none"/><path d="M6.2 4h6.4M6.2 8h6.4M6.2 12h4"/>'
  };
  // icons that look best filled rather than stroked
  var FILLED = { shield: 1, skull: 1, pin: 1, spark: 1, bolt: 1, stop: 1, flagfill: 1, play: 1 };
  function ic(name, cls) {
    var body = P[name]; if (!body) return '';
    var fill = FILLED[name] ? 'fill="currentColor" stroke="none"' : 'fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"';
    return '<svg class="ic ic-' + name + (cls ? ' ' + cls : '') + '" viewBox="0 0 16 16" width="1em" height="1em" ' + fill + ' aria-hidden="true" focusable="false">' + body + '</svg>';
  }
  OBOL.ic = ic;
})(typeof window !== 'undefined' ? window : this);
