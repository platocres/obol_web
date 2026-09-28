#!/usr/bin/env node
/*! obol — tools/stamp-assets.js
 * Cache-bust every local asset in index.html with a content hash: `assets/…/x.js` → `assets/…/x.js?v=<hash8>`.
 * GitHub Pages serves main verbatim with a 10-minute cache and updates files independently, so without this a
 * fresh deploy can leave the browser running a stale packs-bundle.js against a new parser (half-updated app).
 * A content hash changes a URL only when that file's bytes change, so unchanged assets stay cached and a
 * changed one is refetched the moment the new index.html loads. Re-run after editing any asset (CI checks
 * index.html is in sync):  node tools/stamp-assets.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');

// Files that reference local assets, each with the regex that matches those references. index.html uses
// src="…"/href="…" attributes; lazy.js loads its route bundles (parsers, report, domain, …) by bare quoted
// path, so those must be stamped too — and because lazy.js is itself stamped in index.html, changing a
// lazy-loaded module bumps its hash in lazy.js, which bumps lazy.js's own hash in index.html. The chain
// means a single `node tools/stamp-assets.js` cache-busts every asset, eagerly loaded or lazy.
const TARGETS = [
  // index.html: (prefix)(url)(?v=…?)(suffix) — attribute form.
  { file: 'index.html', re: /(\b(?:src|href)=")([^"?]+?\.(?:js|css))(?:\?v=[0-9a-f]+)?(")/gi },
  // lazy.js: quoted local module paths under assets/ or data/.
  { file: 'assets/ui/lazy.js', re: /(['"])((?:assets|data)\/[^'"?]+?\.(?:js|css))(?:\?v=[0-9a-f]+)?(\1)/g },
];

function isLocal(url) {
  return !/^(?:[a-z]+:)?\/\//i.test(url) && !url.startsWith('data:') && !url.startsWith('#');
}
function hashOf(url, missing) {
  const file = path.join(ROOT, url.split('?')[0]);
  if (!fs.existsSync(file)) { missing.push(url); return null; }
  return crypto.createHash('sha1').update(fs.readFileSync(file)).digest('hex').slice(0, 8);
}

function main() {
  let changed = 0, total = 0;
  const missing = [];
  // Stamp lazy.js FIRST so its new content hash is what index.html then stamps.
  for (const t of TARGETS.slice().reverse()) {
    const abs = path.join(ROOT, t.file);
    const src = fs.readFileSync(abs, 'utf8');
    let n = 0;
    const out = src.replace(t.re, function (m, pre, url, post) {
      if (!isLocal(url)) return m;
      const h = hashOf(url, missing);
      if (!h) return m;
      n++;
      return pre + url + '?v=' + h + post;
    });
    total += n;
    if (out !== src) { fs.writeFileSync(abs, out); changed++; console.log('stamp-assets: updated ' + t.file + ' (' + n + ' refs).'); }
  }
  if (missing.length) {
    console.error('stamp-assets: referenced files not found:\n  ' + missing.join('\n  '));
    process.exit(2);
  }
  if (!changed) console.log('stamp-assets: all in sync (' + total + ' refs).');
}

main();
