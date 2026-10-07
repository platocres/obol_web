#!/usr/bin/env node
/* build-gtfobins.js - distill GTFOBins into a compact bundle for the Workbench + the Next Steps resolver.
 *
 * GTFOBins (https://gtfobins.github.io/) publishes each binary's escapes on its own Pages URL. The GitHub
 * API / raw / codeload are not reachable from this environment, but the Pages site is, so this parser reads
 * the rendered per-binary HTML pages (fetched into a local directory) and extracts, per binary, each
 * function's code variants (the sudo / suid / capabilities forms appear as sibling code blocks under one
 * function heading, so grabbing every <pre><code> under a function captures them).
 *
 *   usage: node tools/build-gtfobins.js <pages-dir> [out-file]
 *   pages-dir holds <binary>.html files saved from https://gtfobins.github.io/gtfobins/<binary>/
 *   out-file defaults to data/gtfobins.js
 *
 * Source data is GTFOBins, (C) its contributors, GPL-3.0 (compatible with obol's AGPL-3.0). Attributed in
 * the generated file. Do not hand-edit the output; regenerate from this tool.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const KEEP = new Set(['shell', 'command', 'reverse-shell', 'non-interactive-reverse-shell', 'bind-shell',
  'file-read', 'file-write', 'library-load', 'download', 'upload', 'sudo']);

function unescapeHtml(s) {
  return String(s)
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&#x27;/gi, "'").replace(/&#x2F;/gi, '/')
    .replace(/&#(\d+);/g, function (m, n) { return String.fromCharCode(+n); })
    .replace(/&#x([0-9a-f]+);/gi, function (m, n) { return String.fromCharCode(parseInt(n, 16)); });
}

function parsePage(html) {
  var secRe = /<h2 id="([^"]+)" class="function-name">/g, secs = [], m;
  while ((m = secRe.exec(html))) secs.push({ func: m[1], at: m.index });
  var funcs = {};
  for (var i = 0; i < secs.length; i++) {
    if (!KEEP.has(secs[i].func)) continue;
    var seg = html.slice(secs[i].at, i + 1 < secs.length ? secs[i + 1].at : html.length);
    var codeRe = /<pre><code>([\s\S]*?)<\/code><\/pre>/g, c, codes = [];
    while ((c = codeRe.exec(seg))) {
      var code = unescapeHtml(c[1]).trim();
      if (code && code.length < 400 && codes.indexOf(code) < 0) codes.push(code);
    }
    if (codes.length) funcs[secs[i].func] = codes;
  }
  return funcs;
}

var dir = process.argv[2];
var out = process.argv[3] || path.join(__dirname, '..', 'data', 'gtfobins.js');
if (!dir) { console.error('usage: node tools/build-gtfobins.js <pages-dir> [out-file]'); process.exit(1); }

var data = {}, all = [], n = 0;
fs.readdirSync(dir).filter(function (f) { return f.endsWith('.html'); }).sort().forEach(function (f) {
  var bin = f.replace(/\.html$/, '');
  all.push(bin);
  var funcs = parsePage(fs.readFileSync(path.join(dir, f), 'utf8'));
  if (Object.keys(funcs).length) { data[bin] = funcs; n++; }
});
// The full binary name list (including the ~76 that use GTFOBins' `inherit` directive, whose commands wrap
// a base binary and cannot be inlined faithfully). The resolver links these to the authoritative page rather
// than guessing a command.
all = all.sort();

var banner = '/*!\n'
  + ' * obol data - gtfobins.js - OBOL.GTFOBINS (generated; do not hand-edit)\n'
  + ' * Distilled from GTFOBins (https://gtfobins.github.io/), (C) its contributors, licensed GPL-3.0,\n'
  + ' * which is compatible with obol\'s AGPL-3.0. Regenerate with tools/build-gtfobins.js.\n'
  + ' * Shape: OBOL.GTFOBINS[binary][function] = [code, ...] (sudo/suid/capabilities variants included).\n'
  + ' */\n';
var body = '(function (root) {\n  \'use strict\';\n  var OBOL = root.OBOL = root.OBOL || {};\n'
  + '  OBOL.GTFOBINS = ' + JSON.stringify(data) + ';\n'
  + '  OBOL.GTFOBINS_ALL = ' + JSON.stringify(all) + ';\n'
  + '})(typeof globalThis !== \'undefined\' ? globalThis : this);\n';
fs.writeFileSync(out, banner + body);
console.log('gtfobins: ' + n + ' with inline escapes, ' + all.length + ' names total, '
  + (banner + body).length + ' bytes -> ' + out);
