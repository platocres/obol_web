/* Real IndexedDB migration/deletion, Cruise UI, and redacted report export checks. */
'use strict';
const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = process.env.OBOL_AUDIT_OUTPUT || path.join(os.tmpdir(), 'obol-audit-browser');
fs.mkdirSync(OUTPUT, { recursive: true });
const mime = { '.js': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };
let checks = 0;
function check(value, label) { assert.ok(value, label); checks++; }
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/blank') { res.end('<!doctype html><title>Audit Test</title>'); return; }
  const file = path.resolve(ROOT, '.' + (url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname)));
  if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const executablePath = process.env.OBOL_BROWSER_EXECUTABLE;
  const browser = await chromium.launch(executablePath ? { executablePath } : {});
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', err => errors.push(err.message));
    await page.goto(origin + '/blank');
    await page.evaluate(async () => {
      const db = await new Promise((resolve, reject) => {
        const r = indexedDB.open('obol-db', 1);
        r.onupgradeneeded = () => { for (const name of ['engagements', 'blobs', 'settings']) r.result.createObjectStore(name, { keyPath: name === 'settings' ? 'key' : 'id' }); };
        r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
      });
      const tx = db.transaction(['engagements', 'blobs', 'settings'], 'readwrite');
      tx.objectStore('engagements').put({ id: 'legacy-eng', name: 'Legacy Evidence Test', params: {}, facts: [], targets: [], screenshots: [{ blobId: 'legacy-blob' }] });
      tx.objectStore('blobs').put({ id: 'legacy-blob', blob: new Blob(['legacy evidence']) });
      tx.objectStore('blobs').put({ id: 'orphan-blob', blob: new Blob(['orphan evidence']) });
      tx.objectStore('settings').put({ key: 'activeEngagement', value: 'legacy-eng' });
      await new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); }); db.close();
    });
    await page.goto(origin + '/index.html');
    await page.waitForFunction(() => window.OBOL && OBOL.store && OBOL.store.active() && document.documentElement.dataset.obolBoot === 'ready');
    const migration = await page.evaluate(async () => {
      const r = indexedDB.open('obol-db');
      const db = await new Promise(resolve => { r.onsuccess = () => resolve(r.result); });
      const tx = db.transaction('blobs'), store = tx.objectStore('blobs');
      const indexed = store.indexNames.contains('engagementId');
      const all = await new Promise(resolve => { const q = store.getAll(); q.onsuccess = () => resolve(q.result); }); db.close();
      return { version: db.version, indexed, rows: all.map(b => ({ id: b.id, engagementId: b.engagementId })) };
    });
    check(migration.version === 2 && migration.indexed, 'Database upgrades the blob engagement index');
    check(migration.rows.length === 1 && migration.rows[0].engagementId === 'legacy-eng', 'Legacy referenced blobs are adopted and orphaned blobs are removed');

    await page.goto(origin + '/index.html#/cruise');
    await page.waitForFunction(() => document.body.textContent.includes('Target Required'));
    check(await page.locator('.cr-dl-stage').count() === 0, 'Missing-target Cruise UI offers no executable download');
    await page.screenshot({ path: path.join(OUTPUT, 'cruise-missing-target.png'), fullPage: true });

    await page.evaluate(() => {
      OBOL.store.update(e => { e.params.target = '10.0.0.10'; e.targets = [{ ip: '10.0.0.10' }, { ip: '10.0.0.20' }]; });
      OBOL.store.addFacts(['10.0.0.10', '10.0.0.20'].map(ip => OBOL.facts.makeFact({ kind: 'blocker.clock_skew', scope: 'host:' + ip })));
      location.hash = '#/evidence';
    });
    const dismissA = page.locator('[data-dismiss-blocker="blocker.clock_skew"][data-fact-scope="host:10.0.0.10"]');
    await dismissA.waitFor();
    await dismissA.click();
    check(await page.evaluate(() => !OBOL.store.factSetForTarget('10.0.0.10').has('blocker.clock_skew') && OBOL.store.factSetForTarget('10.0.0.20').has('blocker.clock_skew')), 'Manual diagnostic dismissal preserves other hosts blockers');

    await page.evaluate(() => {
      OBOL.store.setActiveTarget('10.0.0.10');
      OBOL.store.addFacts([OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:10.0.0.10' })]);
      location.hash = '#/path';
    });
    const doneButton = page.locator('.btn-done').first();
    await doneButton.waitFor();
    const actionId = await doneButton.getAttribute('data-action');
    await doneButton.click();
    check(await page.evaluate(id => OBOL.store.doneIdsForTarget('10.0.0.10')[id] && !OBOL.store.doneIdsForTarget('10.0.0.20')[id], actionId), 'Manual Mark Done UI writes target-scoped completion');

    const deletion = await page.evaluate(async () => {
      const S = OBOL.store;
      const a = await S.createEngagement('Blob Owner A');
      S.update(e => { e.params.target = '10.0.0.10'; });
      const aBlob = await S.putBlob(new Blob(['A']));
      const b = await S.createEngagement('Blob Owner B');
      const bBlob = await S.putBlob(new Blob(['B']));
      S.update(e => { e.params.target = '10.0.0.20'; });
      await S.deleteEngagement(a.id);
      await S.deleteEngagement('legacy-eng');
      const deleted = await S.getBlob(aBlob), kept = await S.getBlob(bBlob), legacy = await S.getBlob('legacy-blob');
      await S.clearEngagements();
      const removedOnClear = await S.getBlob(bBlob);
      const request = indexedDB.open('obol-db');
      const db = await new Promise(resolve => { request.onsuccess = () => resolve(request.result); });
      const tx = db.transaction(['blobs', 'engagements']);
      const counts = await Promise.all(['blobs', 'engagements'].map(name => new Promise(resolve => { const q = tx.objectStore(name).count(); q.onsuccess = () => resolve(q.result); }))); db.close();
      return { deleted: !deleted, kept: !!kept, legacyDeleted: !legacy, removedOnClear: !removedOnClear, counts };
    });
    check(deletion.deleted && deletion.kept && deletion.legacyDeleted, 'Engagement deletion removes only its binary evidence, including migrated records');
    check(deletion.removedOnClear && deletion.counts.every(n => n === 0), 'Clear Engagements clears both persistent stores and pending saves');

    const FLAG = '0123456789abcdef0123456789abcdef';
    const exports = await page.evaluate(async flag => {
      await OBOL.store.createEngagement('Redaction Browser Test');
      await OBOL.lazy.loadGroup('report');
      const F = OBOL.facts, R = OBOL.report;
      const facts = new F.FactSet([F.makeFact({ kind: 'objective.local_flag', scope: 'host:10.0.0.10', value: { slot: 'local', flag, path: '/home/alice/local.txt' } })]);
      const ctx = R.buildContext({ facts, params: { target: '10.0.0.10' }, targets: [{ host: '10.0.0.10' }],
        activities: [{ target: '10.0.0.10', command: 'cat local.txt', stdout: flag, produced: ['objective.local_flag'] }] });
      const blocks = R.document('oscp', ctx), markdown = R.toMarkdown(blocks), html = R.htmlDocument(R.toHtml(blocks), 'Redacted Audit Report');
      const zip = new JSZip();
      R.docxFiles(blocks).forEach(file => zip.file(file.path, file.data, { base64: !!file.base64 }));
      return { markdown, html, docx: await zip.generateAsync({ type: 'base64' }), xml: R.docxFiles(blocks).filter(f => !f.base64).map(f => f.data).join('\n') };
    }, FLAG);
    check(!exports.markdown.includes(FLAG) && !exports.html.includes(FLAG) && !exports.xml.includes(FLAG), 'Browser Markdown, HTML, and DOCX exports contain no test flag');
    fs.writeFileSync(path.join(OUTPUT, 'redacted.md'), exports.markdown);
    fs.writeFileSync(path.join(OUTPUT, 'redacted.html'), exports.html);
    fs.writeFileSync(path.join(OUTPUT, 'redacted.docx'), Buffer.from(exports.docx, 'base64'));
    const reportPage = await browser.newPage();
    await reportPage.setContent(exports.html);
    await reportPage.pdf({ path: path.join(OUTPUT, 'redacted.pdf'), format: 'Letter' });
    await reportPage.screenshot({ path: path.join(OUTPUT, 'redacted-report.png'), fullPage: true });
    check((await reportPage.textContent('body')).includes('redacted') && !(await reportPage.textContent('body')).includes(FLAG), 'Print/PDF document displays redaction rather than raw flags');
    const reset = await page.evaluate(async () => {
      sessionStorage.setItem('unrelated-session', 'keep'); sessionStorage.setItem('obol-ui-test', 'erase');
      await OBOL.store.resetAll();
      return { kept: sessionStorage.getItem('unrelated-session'), removed: sessionStorage.getItem('obol-ui-test') };
    });
    check(reset.kept === 'keep' && reset.removed === null, 'Browser factory reset preserves unrelated session keys');
    check(!errors.length, 'Changed routes produce no browser exceptions: ' + errors.join('; '));
    console.log('BROWSER AUDIT: ' + checks + ' checks passed. Artifacts: ' + OUTPUT);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => server.close());
