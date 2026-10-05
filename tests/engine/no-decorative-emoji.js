/*!
 * no-decorative-emoji.js — guard against AI-tell emoji creeping back into the UI.
 *
 * The app renders meaning through text plus a small monochrome inline-SVG icon set
 * (assets/ui/icons.js, OBOL.ic). Decorative/pictographic emoji (🎯 🚩 📁 …) are banned
 * from shipped source: they read as machine-generated and they do not inherit the skin
 * colour, so they cannot be held to the per-skin contrast floor the rest of the UI meets.
 *
 * A short allow-list of monochrome typographic/geometric glyphs is kept: these are
 * single-colour marks that render consistently and already clear contrast as text.
 */
'use strict';
var fs = require('fs');
var path = require('path');
var ROOT = path.join(__dirname, '..', '..');

// Monochrome glyphs we deliberately keep (status ticks, arrows, geometric shapes,
// box-drawing, smart punctuation, and the cut-here scissors used in paste fences).
var KEEP = new Set(Array.from('✓✗✕⚠★◉◐○⌘⭱⭳↗↳↩↴⏭⏹↺▶●◆◇☆✂✎•·«»→←↑↓≤≥≈×÷°±§¶†‡—–‘’“”…│─┌┐└┘├┤┬┴┼░▒▓█▀▄■□▪▫'));

function isDecorativeEmoji(ch) {
  var o = ch.codePointAt(0);
  if (KEEP.has(ch)) return false;
  if (o < 0x2190) return false;
  if (o >= 0x1F000 && o <= 0x1FAFF) return true;   // pictographs, symbols & emoji
  if (o >= 0x2600 && o <= 0x27BF) return true;      // misc symbols + dingbats
  if (o >= 0x2B00 && o <= 0x2BFF) return true;      // misc symbols & arrows
  if (o === 0xFE0F || o === 0x20E3) return true;    // variation selector / keycap
  if (o >= 0x1F1E6 && o <= 0x1F1FF) return true;    // regional indicators
  return false;
}

// Ship-facing source. Tests themselves are allowed to mention banned glyphs in prose,
// so tests/ is intentionally excluded (except nothing here needs it).
var DIRS = ['assets', 'data'];
var EXT = /\.(js|css|json|html)$/;

function walk(dir, out) {
  var ents = fs.readdirSync(dir, { withFileTypes: true });
  for (var i = 0; i < ents.length; i++) {
    var e = ents[i];
    if (e.name === 'node_modules') continue;
    var fp = path.join(dir, e.name);
    if (e.isDirectory()) walk(fp, out);
    else if (EXT.test(e.name) && e.name !== 'icons.js') out.push(fp);
  }
}

var files = [];
DIRS.forEach(function (d) { var p = path.join(ROOT, d); if (fs.existsSync(p)) walk(p, files); });
['index.html'].forEach(function (f) { var p = path.join(ROOT, f); if (fs.existsSync(p)) files.push(p); });

var offenders = [];
files.forEach(function (fp) {
  var lines = fs.readFileSync(fp, 'utf8').split('\n');
  lines.forEach(function (ln, i) {
    var bad = Array.from(ln).filter(isDecorativeEmoji);
    if (bad.length) offenders.push(path.relative(ROOT, fp) + ':' + (i + 1) + '  [' + Array.from(new Set(bad)).join('') + ']  ' + ln.trim().slice(0, 80));
  });
});

if (offenders.length) {
  console.error('DECORATIVE EMOJI FOUND (use OBOL.ic() from assets/ui/icons.js instead):');
  offenders.forEach(function (o) { console.error('  ' + o); });
  process.exit(1);
}
console.log('NO-DECORATIVE-EMOJI: clean (' + files.length + ' shipped files scanned)');
