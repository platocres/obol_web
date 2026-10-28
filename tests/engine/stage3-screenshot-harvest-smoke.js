/* Stage 3 screenshot-harvest smoke (the Tier 1 vision tier). Locks the asset classification and format-pair
 * dedup in tools/corpus/harvest-screenshots.js: a content capture (the 0xdf image-<timestamp>-<hash> naming)
 * vs a decoration (CDN/stock art, avatars, placeholder shapes), and the captureKey that collapses the png and
 * webp of ONE capture (and the many decorations sharing a CDN id) to a single asset identity, so the worklist
 * counts unique assets, not files. If this drift went unnoticed the vision tier would either miss real captures
 * or double-count format pairs. Hand-built filenames, no verbatim corpus output (docs/CORPUS-MINING.md
 * Principle 7). The corpus-optional tail runs the real classifier over one box dir when the private snapshot is
 * present. qa-only; nothing ships. House style: no em or en dashes. */
'use strict';
var fs = require('fs');
var path = require('path');

var ROOT = path.join(__dirname, '..', '..');
var H = require(path.join(ROOT, 'tools', 'corpus', 'harvest-screenshots.js'));

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// ---- classifyAsset ----
ok(H.classifyAsset('image-20210122093135169-0f5d7defe26d.png') === 'content_capture', 'image-<timestamp> png is a content capture');
ok(H.classifyAsset('image-20240508161546921-ffa4610ebaec.webp') === 'content_capture', 'image-<timestamp> webp is a content capture');
ok(H.classifyAsset('1567581600067-dab850f5c17e.png') === 'decoration', 'CDN unix-ms name is a decoration');
ok(H.classifyAsset('103958-02d387a4a2d4.png') === 'decoration', 'short-numeric CDN name is a decoration');
ok(H.classifyAsset('box-sink-83e65d7640cf.webp') === 'decoration', 'box-slug stock name is a decoration');
ok(H.classifyAsset('README.md') === 'non_image', 'a non-image file is neither capture nor decoration');
ok(H.classifyAsset('image-20210122093135169-0f5d7defe26d.svg') === 'non_image', 'an unsupported extension is a non-image even with the capture name');

// ---- captureKey: collapse the png/webp pair of one asset, keep distinct assets distinct ----
ok(H.captureKey('image-20210122093135169-0f5d7defe26d.webp') === H.captureKey('image-20210122093135169-dfc3fa40eac9.png'),
  'the png and webp of one capture share a captureKey (format pair collapses)');
ok(H.captureKey('1567581600067-2a0ebf5da45b.webp') === H.captureKey('1567581600067-dab850f5c17e.png'),
  'the png and webp of one decoration share a captureKey');
ok(H.captureKey('image-20210122093135169-0f5d7defe26d.png') !== H.captureKey('image-20210122093243599-181755eb08c7.png'),
  'two different captures have different captureKeys');
ok(H.captureKey('image-20210122093135169-0f5d7defe26d.png') === 'image-20210122093135169',
  'captureKey strips the per-file hash and extension to the capture identity');

// ---- groupAssets: unique assets, formats collapsed, non-images dropped ----
var g = H.groupAssets([
  'image-20210122093135169-0f5d7defe26d.webp',
  'image-20210122093135169-dfc3fa40eac9.png',   // same capture, other format
  'image-20210122093243599-181755eb08c7.png',   // a second capture
  '1567581600067-2a0ebf5da45b.webp',
  '1567581600067-dab850f5c17e.png',             // same decoration, other format
  'notes.txt'                                    // dropped
]);
var keys = Object.keys(g);
ok(keys.length === 3, 'six files with two format pairs collapse to three unique assets (got ' + keys.length + ')');
var caps = keys.filter(function (k) { return g[k].kind === 'content_capture'; });
var decs = keys.filter(function (k) { return g[k].kind === 'decoration'; });
ok(caps.length === 2 && decs.length === 1, 'two content captures and one decoration grouped');
var paired = g['image-20210122093135169'];
ok(paired && paired.files.length === 2 && paired.formats.indexOf('png') >= 0 && paired.formats.indexOf('webp') >= 0,
  'the collapsed capture records both files and both formats');

// ---- validate 0xdf-screenshots-ocr.json against Stage 1 contract ----
var S = require(path.join(ROOT, 'tools', 'corpus', 'extraction-schema.js'));
var vm = require('vm');
var ctx = { globalThis: {} }; ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'data', 'parser-signatures.js'), 'utf8'), ctx, { filename: 'parser-signatures.js' });
var V = S.buildKindVocabulary(ctx.OBOL.PARSER_SIGNATURES);
var ocrFile = path.join(ROOT, 'tools', 'corpus', 'labels', '0xdf-screenshots-ocr.json');
ok(fs.existsSync(ocrFile), '0xdf-screenshots-ocr.json exists');
if (fs.existsSync(ocrFile)) {
  var ocrRecs = JSON.parse(fs.readFileSync(ocrFile, 'utf8'));
  ok(Array.isArray(ocrRecs) && ocrRecs.length >= 15, '0xdf-screenshots-ocr.json has at least 15 OCR records (got ' + (ocrRecs && ocrRecs.length) + ')');
  var allValid = ocrRecs.every(function (rec) {
    var r = S.validateRecord(rec, { isKnownKind: V.isKnownKind });
    return r.ok && rec.asset && rec.asset.type === 'screenshot' && rec.asset.fidelity === 'ocr';
  });
  ok(allValid, 'every record in 0xdf-screenshots-ocr.json passes Stage 1 schema + ocr fidelity validation');
}

// ---- corpus-optional: the real classifier over one box dir ----
var sink = path.join(ROOT, '..', '0xdf-offsec-complete-2026-08-20', 'assets', 'sink');
if (fs.existsSync(sink)) {
  var real = H.groupAssets(fs.readdirSync(sink));
  var rk = Object.keys(real);
  var rcaps = rk.filter(function (k) { return real[k].kind === 'content_capture'; });
  ok(rcaps.length > 0, 'real box dir yields content captures (' + rcaps.length + ' unique)');
  var cleanKeys = rcaps.every(function (k) { return /^image-\d{14,17}$/.test(k); });
  ok(cleanKeys, 'every content-capture key reduces to image-<timestamp> (per-file hash and extension stripped)');
  var collapsed = rk.filter(function (k) { return real[k].files.length > 1; });
  ok(collapsed.length > 0, 'at least one real asset had its png/webp pair collapsed (' + collapsed.length + ' collapsed)');
} else {
  console.log('  skip: 0xdf assets/sink absent (corpus-optional)');
}

console.log('\nSTAGE 3 SCREENSHOT-HARVEST SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
