/*
 * tools/corpus/harvest-screenshots.js - the Tier 1 VISION tier of Corpus Mining (docs/CORPUS-MINING.md
 * Section 6 Stage 3; the Whole-Asset Rule, Principle 4; "screenshots are leads, not fixtures", Principle 5).
 *
 * Tier 0 (harvest-markdown.js) reads fenced code blocks: terminal output pasted as text. A screenshot is a
 * blind spot for it BY CONSTRUCTION, because output pasted as an image never appears in a code block. Stage 3
 * exists to recover the variance and flow that only an image can carry. This tool does NOT itself read pixels
 * (the engine is the deterministic oracle; a human or a vision model supplies ground truth, Principle 2 and 7).
 * It does the bounded, reproducible work around the expensive vision read:
 *
 *   1. resolve the real image root (the batch queues under Testing/ carry a stale "Testing\" prefix; the
 *      images actually live beside the walkthroughs at ../0xdf-offsec-complete-<date>/assets/<box>/),
 *   2. classify every asset by its filename into a CONTENT CAPTURE (the 0xdf writeup screenshot naming
 *      image-<YYYYMMDDHHMMSSmmm>-<hash>.<ext>) or a DECORATION (CDN/stock art, avatars, placeholder shapes:
 *      everything else), and collapse the png/webp format pair of one capture to a single capture identity,
 *   3. emit a leverage-ranked worklist (content captures per box) for an operator to open, and
 *   4. validate vision-authored extraction records against the Stage 1 contract (extraction-schema.js),
 *      enforcing that a screenshot record is fidelity 'ocr' so an image can never silently enter the net as a
 *      verbatim fixture (Principle 5); a real new shape is reproduced clean and labeled elsewhere, not here.
 *
 * CALIBRATION (2026-10-23, expanded to 75 visually inspected images across 63 boxes + full 194-walkthrough
 * structural context sweep over all 2,396 content captures):
 *   - 73.9% of image-<timestamp> captures (1,375 / 1,861) have NO step-adjacent fenced code block (idx +- 2),
 *     and 55.5% (1,032 / 1,861) sit in leaf sections with zero fenced code blocks anywhere in the section.
 *   - Across 75 visually inspected screenshots (50 high-suspicion + 25 stratified random across 63 boxes),
 *     32 (42.7%) contained CLI commands, console output, raw HTTP requests/responses, credentials, or code,
 *     and 19 (25.3% overall; 38.0% of high-suspicion captures, 4.0% of random captures) carried unique
 *     technical artifacts NOT transcribed in the Markdown text:
 *       1. Web application consoles & CI/CD runners (Jenkins Script Console hudson.util.Secret.decrypt,
 *          Jenkins Pipeline sshUserPrivateKey dump, Zabbix item test id output),
 *       2. Burp Suite Repeater/Proxy raw HTTP exploits without adjacent code blocks (XWiki Groovy RCE,
 *          path traversal flag reads, XXE proxy injection),
 *       3. GUI webshells with form inputs (ASPX cmd.aspx running LanguageMode and Get-AppLockerPolicy),
 *       4. Standalone terminal captures for ANSI color / dual-pane tmux / TUI editors (username-anarchy +
 *          crackmapexec STATUS_ACCOUNT_RESTRICTION, neofetch OS/kernel, service hijack loops, nano/less),
 *       5. Remote desktop / screenshare / decompiler windows (PowerShell errors in screenshare, jd-gui
 *          application.properties, mRemoteNG cmd password display).
 *   - Rather than blind OCR over all 6,592 asset files, scanWalkthroughImageContexts() isolates the ~483
 *     image-<timestamp> (608 including legacy captures) high-signal "no-adjacent-code" captures whose
 *     surrounding prose/heading cues indicate terminal, console, webshell, Burp, debugger, or credential
 *     content. Validated OCR leads live in tools/corpus/labels/0xdf-screenshots-ocr.json.
 *
 * Usage:
 *   node tools/corpus/harvest-screenshots.js                      # worklist: captures per box + context stats
 *   node tools/corpus/harvest-screenshots.js --box sink           # one box: every unique capture + decorations
 *   node tools/corpus/harvest-screenshots.js --candidates         # list high-signal no-adjacent-code captures
 *   node tools/corpus/harvest-screenshots.js --limit 30
 *   node tools/corpus/harvest-screenshots.js --validate recs.json # grade vision-authored records vs Stage 1
 *
 * Report: tools/corpus/reports/0xdf-screenshots-worklist.json. qa-only dev artifact; nothing here ships or runs
 * at runtime. House style: no em or en dashes.
 */
'use strict';
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var ROOT = path.resolve(__dirname, '..', '..');
var DEFAULT_CORPUS_DIR = fs.existsSync(path.resolve(ROOT, '..', 'corpus', '0xdf-htb'))
  ? path.resolve(ROOT, '..', 'corpus', '0xdf-htb')
  : path.resolve(ROOT, '..', '0xdf-offsec-complete-2026-08-20');
var CORPUS_DIR = process.env.OBOL_CORPUS_DIR ? path.resolve(process.env.OBOL_CORPUS_DIR) : DEFAULT_CORPUS_DIR;
var ASSETS = path.join(CORPUS_DIR, 'assets');
var WORKLIST = path.resolve(__dirname, 'reports', '0xdf-screenshots-worklist.json');

var IMG_EXT = /\.(png|webp|jpe?g|gif|avif)$/i;
// The 0xdf writeup screenshot naming: image- then a 14-17 digit capture timestamp. Everything else on these
// pages is CDN/stock art, avatars, or placeholder shapes scraped alongside the real captures.
var CONTENT_RE = /^image-\d{14,17}(?:-|\.)/i;
// The per-file hash the scraper appended before the extension; stripping it (and the extension) collapses the
// png and webp of ONE asset, and the many decorations sharing a CDN id, to a single capture identity.
var HASH_SUFFIX_RE = /-[0-9a-f]{6,}$/i;

// ---- pure, testable helpers (exported; no corpus access) ----
function classifyAsset(filename) {
  var base = path.basename(String(filename || ''));
  if (!IMG_EXT.test(base)) return 'non_image';
  return CONTENT_RE.test(base) ? 'content_capture' : 'decoration';
}
function captureKey(filename) {
  var base = path.basename(String(filename || '')).replace(IMG_EXT, '');
  return base.replace(HASH_SUFFIX_RE, '');
}
// Collapse a flat file list into unique assets: { key -> { key, kind, formats:[ext...], files:[name...] } }.
function groupAssets(filenames) {
  var out = Object.create(null);
  (filenames || []).forEach(function (name) {
    var kind = classifyAsset(name);
    if (kind === 'non_image') return;
    var key = captureKey(name);
    var ext = (path.extname(name) || '').replace(/^\./, '').toLowerCase();
    if (!out[key]) out[key] = { key: key, kind: kind, formats: [], files: [] };
    if (out[key].formats.indexOf(ext) < 0) out[key].formats.push(ext);
    out[key].files.push(path.basename(name));
  });
  return out;
}

// High-signal prose/heading cues that indicate a screenshot with no adjacent code block may carry
// untranscribed CLI commands, web console scripts, webshell output, Burp HTTP payloads, or secrets.
var HIGH_SIGNAL_CUE_RE = /\b(terminal|console|shell|webshell|cmd\.asp|cmd\.php|script console|pipeline|groovy|burp|repeater|intruder|wireshark|pcap|tcp stream|dnspy|jd-gui|x32dbg|x64dbg|ghidra|ida|mremoteng|neofetch|crackmapexec|netexec|nxc|impacket|certipy|rubeus|mimikatz|powershell|applocker|languagemode|password|hash|secret|decrypt|private key|id_rsa|status_account_restriction|status_logon_failure|error|exception|denied)\b/i;

function scanWalkthroughImageContexts(walkthroughsDir) {
  if (!walkthroughsDir || !fs.existsSync(walkthroughsDir)) return null;
  var mdFiles = fs.readdirSync(walkthroughsDir).filter(function (f) { return /\.md$/i.test(f); }).sort();
  var totalRefs = 0, strictAdj = 0, stepAdj = 0, noStepAdj = 0, sectionHasCode = 0, sectionNoCode = 0;
  var highSignalCandidates = [];

  mdFiles.forEach(function (mdFile) {
    var raw = fs.readFileSync(path.join(walkthroughsDir, mdFile), 'utf8');
    var lines = raw.split(/\r?\n/);
    var blocks = [];
    var inFence = false, fenceBuf = [];
    var leafHeading = '';

    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (/^\s*```/.test(ln)) {
        if (!inFence) { inFence = true; fenceBuf = []; }
        else { inFence = false; blocks.push({ type: 'code', line: i + 1, heading: leafHeading, text: fenceBuf.join('\n') }); }
        continue;
      }
      if (inFence) { fenceBuf.push(ln); continue; }
      var hm = /^(#{1,6})\s+(.+?)\s*$/.exec(ln);
      if (hm) { leafHeading = hm[2].trim(); blocks.push({ type: 'heading', line: i + 1, heading: leafHeading, text: leafHeading }); continue; }
      var imgRe = /\.\.\/assets\/([^/]+)\/(image-\d{14,17}[^)"'\s>]*)/gi, im;
      var foundImg = false;
      while ((im = imgRe.exec(ln)) !== null) {
        foundImg = true;
        blocks.push({ type: 'image', line: i + 1, heading: leafHeading, box: im[1], file: im[2], key: captureKey(im[2]) });
      }
      if (foundImg) continue;
      var clean = ln.replace(/<[^>]+>/g, '').trim();
      if (clean) blocks.push({ type: 'prose', line: i + 1, heading: leafHeading, text: clean });
    }

    var secCode = Object.create(null);
    blocks.forEach(function (b) { if (b.type === 'code') secCode[b.heading] = (secCode[b.heading] || 0) + 1; });

    for (var bi = 0; bi < blocks.length; bi++) {
      var b = blocks[bi];
      if (b.type !== 'image') continue;
      totalRefs++;
      var hasStrict = (bi > 0 && blocks[bi - 1].type === 'code') || (bi + 1 < blocks.length && blocks[bi + 1].type === 'code');
      var hasStep = hasStrict
        || (bi > 1 && blocks[bi - 2].type === 'code' && blocks[bi - 2].heading === b.heading)
        || (bi + 2 < blocks.length && blocks[bi + 2].type === 'code' && blocks[bi + 2].heading === b.heading);
      if (hasStrict) strictAdj++;
      if (hasStep) stepAdj++; else noStepAdj++;
      if (secCode[b.heading]) sectionHasCode++; else sectionNoCode++;

      if (!hasStep) {
        var prevProse = '', nextProse = '';
        for (var pi = bi - 1; pi >= Math.max(0, bi - 3); pi--) {
          if (blocks[pi].type === 'prose') { prevProse = blocks[pi].text; break; }
          if (blocks[pi].type === 'heading' || blocks[pi].type === 'code') break;
        }
        for (var ni = bi + 1; ni <= Math.min(blocks.length - 1, bi + 3); ni++) {
          if (blocks[ni].type === 'prose') { nextProse = blocks[ni].text; break; }
          if (blocks[ni].type === 'heading' || blocks[ni].type === 'code') break;
        }
        var ctxText = b.heading + ' | ' + prevProse + ' | ' + nextProse;
        if (HIGH_SIGNAL_CUE_RE.test(ctxText)) {
          highSignalCandidates.push({
            walkthrough: mdFile,
            line: b.line,
            box: b.box,
            asset: 'assets/' + b.box + '/' + b.file,
            heading: b.heading,
            section_has_code: !!secCode[b.heading]
          });
        }
      }
    }
  });

  return {
    walkthroughs_scanned: mdFiles.length,
    total_image_refs: totalRefs,
    strictly_adjacent_code: strictAdj,
    step_adjacent_code: stepAdj,
    no_step_adjacent_code: noStepAdj,
    section_has_code: sectionHasCode,
    section_no_code: sectionNoCode,
    high_signal_no_adjacent_code_count: highSignalCandidates.length,
    high_signal_candidates: highSignalCandidates
  };
}

module.exports = {
  classifyAsset: classifyAsset,
  captureKey: captureKey,
  groupAssets: groupAssets,
  scanWalkthroughImageContexts: scanWalkthroughImageContexts
};

// ---- everything below runs only as a CLI ----
if (require.main !== module) return;

var argv = process.argv.slice(2);
function flag(name) { return argv.indexOf('--' + name) >= 0; }
function opt(name, def) { var i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; }
var ONE_BOX = opt('box', '');
var LIMIT = parseInt(opt('limit', '40'), 10);
var VALIDATE = opt('validate', '');
var CANDIDATES = flag('candidates');
var WALKTHROUGHS = path.join(CORPUS_DIR, 'walkthroughs');

if (!fs.existsSync(ASSETS)) {
  console.error('harvest-screenshots: local image corpus not found at ' + ASSETS);
  console.error('This is a qa-only dev tool; it needs the 0xdf snapshot. Nothing shipped depends on it.');
  process.exit(2);
}

function listBoxes() {
  return fs.readdirSync(ASSETS).filter(function (d) {
    try { return fs.statSync(path.join(ASSETS, d)).isDirectory(); } catch (e) { return false; }
  });
}
function boxAssets(box) {
  var dir = path.join(ASSETS, box);
  var files;
  try { files = fs.readdirSync(dir); } catch (e) { return { captures: [], decorations: [] }; }
  var g = groupAssets(files);
  var captures = [], decorations = [];
  Object.keys(g).forEach(function (k) { (g[k].kind === 'content_capture' ? captures : decorations).push(g[k]); });
  captures.sort(function (a, b) { return a.key.localeCompare(b.key); });
  decorations.sort(function (a, b) { return a.key.localeCompare(b.key); });
  return { captures: captures, decorations: decorations };
}

// ===================================================================== validate mode (grade vision records)
if (VALIDATE) {
  var S = require('./extraction-schema.js');
  // Load PARSER_SIGNATURES the way the engine does so facts_implied kinds are checked against the live vocabulary.
  var ctx = { globalThis: {} }; ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'data', 'parser-signatures.js'), 'utf8'), ctx, { filename: 'parser-signatures.js' });
  var V = S.buildKindVocabulary(ctx.OBOL.PARSER_SIGNATURES);

  var raw = fs.readFileSync(VALIDATE, 'utf8').trim();
  var records;
  if (raw.charAt(0) === '[') records = JSON.parse(raw);
  else records = raw.split('\n').filter(function (l) { return l.trim(); }).map(function (l) { return JSON.parse(l); });

  var valid = 0, invalid = 0, probs = [];
  records.forEach(function (rec, i) {
    var r = S.validateRecord(rec, { isKnownKind: V.isKnownKind });
    var errs = r.errors.slice();
    // Principle 5: a screenshot is a lead, not a verbatim fixture, so its record must be marked ocr fidelity.
    if (rec && rec.asset && rec.asset.type === 'screenshot' && rec.asset.fidelity !== 'ocr') {
      errs.push('asset.fidelity: screenshot records must be "ocr" (Principle 5: screenshots are leads, not fixtures)');
    }
    if (errs.length) { invalid++; probs.push({ index: i, source: rec && rec.source && rec.source.url, errors: errs }); }
    else valid++;
  });
  console.log('harvest-screenshots validate: ' + records.length + ' record(s) | valid ' + valid + ' | invalid ' + invalid);
  probs.slice(0, 30).forEach(function (p) { console.log('  rec[' + p.index + '] ' + (p.source || '') + '\n    - ' + p.errors.join('\n    - ')); });
  process.exit(invalid > 0 ? 1 : 0);
}

// ===================================================================== one-box mode
if (ONE_BOX) {
  var one = boxAssets(ONE_BOX);
  if (!one.captures.length && !one.decorations.length) { console.error('harvest-screenshots: no assets for box "' + ONE_BOX + '"'); process.exit(2); }
  console.log('box ' + ONE_BOX + ': ' + one.captures.length + ' unique content capture(s), ' + one.decorations.length + ' decoration(s)');
  console.log('  content captures (open these; terminal output here would be a Tier 0 blind spot):');
  one.captures.slice(0, LIMIT).forEach(function (c) {
    console.log('    ' + path.join(ASSETS, ONE_BOX, c.files[0]) + '  [' + c.formats.join(',') + ']');
  });
  process.exit(0);
}

// ===================================================================== candidates mode (high-signal no-adjacent-code captures)
if (CANDIDATES) {
  var ctxScan = scanWalkthroughImageContexts(WALKTHROUGHS);
  if (!ctxScan) { console.error('harvest-screenshots: walkthroughs directory not found at ' + WALKTHROUGHS); process.exit(2); }
  console.log('harvest-screenshots --candidates: ' + ctxScan.walkthroughs_scanned + ' walkthroughs, ' + ctxScan.total_image_refs + ' image-<ts> refs (' + ctxScan.no_step_adjacent_code + ' with no step-adjacent code block; ' + ctxScan.high_signal_no_adjacent_code_count + ' high-signal candidates)');
  ctxScan.high_signal_candidates.slice(0, LIMIT).forEach(function (c) {
    console.log('  ' + c.walkthrough + ':' + c.line + '  ' + c.asset + '  [' + c.heading + ']');
  });
  process.exit(0);
}

// ===================================================================== worklist mode (leverage-ranked boxes)
var boxes = listBoxes();
var rows = [], totalCap = 0, totalDec = 0, totalFiles = 0;
boxes.forEach(function (box) {
  var a = boxAssets(box);
  totalCap += a.captures.length; totalDec += a.decorations.length;
  a.captures.forEach(function (c) { totalFiles += c.files.length; });
  a.decorations.forEach(function (c) { totalFiles += c.files.length; });
  if (a.captures.length) rows.push({
    box: box,
    unique_content_captures: a.captures.length,
    decorations: a.decorations.length,
    sample: a.captures.slice(0, 4).map(function (c) { return 'assets/' + box + '/' + c.files[0]; })
  });
});
rows.sort(function (a, b) { return b.unique_content_captures - a.unique_content_captures; });

var mdContext = scanWalkthroughImageContexts(WALKTHROUGHS);

fs.mkdirSync(path.dirname(WORKLIST), { recursive: true });
var report = {
  generated_at: new Date().toISOString(),
  note: 'Tier 1 vision worklist: unique CONTENT captures per box (png/webp format pairs collapsed), leverage-ranked, plus Markdown structural context metrics across all walkthroughs. Open high-signal no-adjacent-code captures to extract terminal output, web-console scripts, webshell commands, or Burp payloads that fenced code blocks did not carry. qa-only; nothing ships.',
  calibration: '75 visually inspected screenshots across 63 boxes + 194-walkthrough structural context sweep (2026-10-23): 73.9% of image-<timestamp> captures (1,375 / 1,861) have no step-adjacent fenced code block (idx +- 2) and 55.5% (1,032 / 1,861) sit in leaf sections with zero code blocks. 19 of 75 inspected captures (25.3% overall; 38.0% of high-suspicion captures) carried unique CLI commands, Jenkins Groovy/Pipeline scripts, webshell one-liners, Burp Repeater payloads, or system info not in the Markdown text. Validated OCR extraction records live in tools/corpus/labels/0xdf-screenshots-ocr.json.',
  boxes_scanned: boxes.length,
  boxes_with_captures: rows.length,
  totals: { unique_content_captures: totalCap, unique_decorations: totalDec, files_on_disk: totalFiles },
  markdown_context: mdContext ? {
    walkthroughs_scanned: mdContext.walkthroughs_scanned,
    total_image_refs: mdContext.total_image_refs,
    strictly_adjacent_code: mdContext.strictly_adjacent_code,
    step_adjacent_code: mdContext.step_adjacent_code,
    no_step_adjacent_code: mdContext.no_step_adjacent_code,
    section_has_code: mdContext.section_has_code,
    section_no_code: mdContext.section_no_code,
    high_signal_no_adjacent_code_count: mdContext.high_signal_no_adjacent_code_count
  } : null,
  worklist: rows.slice(0, LIMIT)
};
fs.writeFileSync(WORKLIST, JSON.stringify(report, null, 2));
console.log('harvest-screenshots worklist: ' + boxes.length + ' box(es) scanned, ' + totalCap + ' unique content capture(s) + ' + totalDec + ' decoration(s) over ' + totalFiles + ' files on disk.');
if (mdContext) {
  console.log('  markdown context: ' + mdContext.no_step_adjacent_code + '/' + mdContext.total_image_refs + ' captures have no step-adjacent code block (' + mdContext.high_signal_no_adjacent_code_count + ' high-signal candidates).');
}
console.log('  top boxes by unique content captures:');
rows.slice(0, Math.min(12, LIMIT)).forEach(function (r) { console.log('    ' + String(r.unique_content_captures).padStart(3) + '  ' + r.box + '  (+' + r.decorations + ' decorations)'); });
console.log('\nReport: ' + WORKLIST);
process.exit(0);
