/*!
 * obol ui - icons.js
 * A small, consistent inline-SVG icon set that replaces decorative emoji across the app.
 * Every icon is monochrome and draws in `currentColor`, so it inherits the surrounding text
 * colour and therefore passes contrast on every skin automatically, and never reads as an
 * AI-tell emoji. Usage: OBOL.ic('host')  ->  '<svg class="ic ic-host" ...>...</svg>'
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
    copy:  '<rect x="5.5" y="5.5" width="8" height="8" rx="1.2"/><path d="M3.5 10.5h-.8a1.2 1.2 0 0 1-1.2-1.2V3.5a1.2 1.2 0 0 1 1.2-1.2h5.8a1.2 1.2 0 0 1 1.2 1.2v.8"/>',
    unlock:'<rect x="3" y="7" width="10" height="7" rx="1"/><path d="M5 7V4.8a3 3 0 0 1 5.6-1.4"/>',
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
    ports: '<circle cx="3.4" cy="4" r="1.1" fill="currentColor" stroke="none"/><circle cx="3.4" cy="8" r="1.1" fill="currentColor" stroke="none"/><circle cx="3.4" cy="12" r="1.1" fill="currentColor" stroke="none"/><path d="M6.2 4h6.4M6.2 8h6.4M6.2 12h4"/>',
    // download / export (arrow into a tray)
    download: '<path d="M8 2v7M5 6.3 8 9.3l3-3M3 11.5v1.5a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1.5"/>',
    // chain link (add to playbook)
    chain: '<path d="M6.5 9.5 9.5 6.5M6 4.5l1-1a2.6 2.6 0 0 1 3.7 3.7l-1 1M10 11.5l-1 1a2.6 2.6 0 0 1-3.7-3.7l1-1"/>',
    // open book (courses, references)
    book: '<path d="M2.5 3.5c1.8-.7 3.7-.7 5.5.5 1.8-1.2 3.7-1.2 5.5-.5v9.5c-1.8-.7-3.7-.7-5.5.5-1.8-1.2-3.7-1.2-5.5-.5zM8 4v9.5"/>',
    // right arrow (forward CTA)
    arrow: '<path d="M3 8h10M9.5 4.5 13 8l-3.5 3.5"/>',
    // lightning bolt / zap (simulator, privesc, quick action)
    zap: '<path d="M9 1.5 3.5 9H7l-.8 5.5L12.5 7H9z"/>',
    // compass (navigation, beginner orientation)
    compass: '<circle cx="8" cy="8" r="6"/><polygon points="6.5,6.5 11.2,4.8 9.5,9.5 4.8,11.2"/>',
    // terminal prompt (>_)
    terminal: '<rect x="1.8" y="2.5" width="12.4" height="11" rx="1.5"/><path d="M4.5 6l2.5 2-2.5 2M8 10h3.5"/>',
    // award / certification medal
    award: '<circle cx="8" cy="6" r="4"/><path d="M5.8 9.3 4.5 14.2 8 12.5l3.5 1.7-1.3-4.9"/>',
    // radar / recon sweep
    radar: '<circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.8"/><path d="M8 8 12.2 3.8"/>',
    // search magnifier (enumeration)
    search: '<circle cx="7" cy="7" r="4.5"/><path d="m10.3 10.3 3.5 3.5"/>',
    // stacked layers (hypervisor, deep reference)
    layers: '<polygon points="8,2 14,5.5 8,9 2,5.5"/><path d="m2 8.5 6 3.5 6-3.5M2 11.5 8 15l6-3.5"/>',
    // package cube (Kali loadout)
    package: '<path d="M8 1.8 13.5 4.8v6.4L8 14.2 2.5 11.2V4.8z"/><path d="M2.5 4.8 8 7.8l5.5-3M8 7.8v6.4"/>',
    // external link arrow
    ext: '<path d="M9.5 2.5h4v4M13.5 2.5 7.5 8.5M6.5 3.5H3.5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-3"/>',
    // checkmark
    check: '<path d="M3 8.5 6.5 12 13 4.5"/>',
    // globe / network
    globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12"/>',
    // key (hash id / credentials)
    key: '<circle cx="5.2" cy="8.5" r="2.8"/><path d="M8 8.5h6M11.5 8.5v2.2M13.8 8.5v2.2"/>',
    // users (password spray / accounts)
    users: '<circle cx="6" cy="5.5" r="2.3"/><path d="M2 13c0-2.2 1.8-3.8 4-3.8s4 1.6 4 3.8"/><circle cx="11.2" cy="5.8" r="1.8"/><path d="M11.5 9.4c1.6.2 2.8 1.4 2.8 3.2"/>',
    // code brackets (codec / evasion)
    code: '<path d="M5.2 4.5 1.8 8l3.4 3.5M10.8 4.5 14.2 8l-3.4 3.5M9.2 3.2 6.8 12.8"/>',
    // database cylinder (SQLi)
    database: '<ellipse cx="8" cy="3.8" rx="5.2" ry="1.8"/><path d="M2.8 3.8v8.4c0 1 2.3 1.8 5.2 1.8s5.2-.8 5.2-1.8V3.8M2.8 8c0 1 2.3 1.8 5.2 1.8s5.2-.8 5.2-1.8"/>',
    // list (wordlists)
    list: '<path d="M5.5 4.2h8M5.5 8h8M5.5 11.8h8"/><circle cx="2.8" cy="4.2" r="1" fill="currentColor" stroke="none"/><circle cx="2.8" cy="8" r="1" fill="currentColor" stroke="none"/><circle cx="2.8" cy="11.8" r="1" fill="currentColor" stroke="none"/>',
    // activity pulse (Output & Error Doctor)
    activity: '<path d="M1.5 8h2.8l1.8-4.5 3.2 9 2.1-4.5h3.1"/>',
    // git-branch alias for pivot / tunnels
    'git-branch': '<circle cx="4" cy="4" r="1.8"/><circle cx="4" cy="12" r="1.8"/><circle cx="12" cy="6" r="1.8"/><path d="M4 5.8v4.4M12 7.8c0 2.5-2 3.2-6.2 3.2"/>'
  };
  // icons that look best filled rather than stroked
  var FILLED = { shield: 1, skull: 1, pin: 1, spark: 1, bolt: 1, zap: 1, stop: 1, flagfill: 1, play: 1 };
  function ic(name, cls) {
    var body = P[name]; if (!body) return '';
    var fill = FILLED[name] ? 'fill="currentColor" stroke="none"' : 'fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"';
    return '<svg class="ic ic-' + name + (cls ? ' ' + cls : '') + '" viewBox="0 0 16 16" width="1em" height="1em" ' + fill + ' aria-hidden="true" focusable="false">' + body + '</svg>';
  }
  OBOL.ic = ic;
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this));
