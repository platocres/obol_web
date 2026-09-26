/* Headless Chromium smoke for the new obol_web shell + coach.
 * Serves the repo statically and drives the app: boot commits, coach renders proof-gated
 * moves, adding a target updates the coach, evidence route loads. Fails on console errors.
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const PORT = 8791;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };

function serve() {
  return http.createServer((req, res) => {
    let p = decodeURIComponent(req.url.split('?')[0]);
    if (p === '/') p = '/index.html';
    const fp = path.join(ROOT, p);
    if (!fp.startsWith(ROOT) || !fs.existsSync(fp) || fs.statSync(fp).isDirectory()) { res.writeHead(404); res.end('nf'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp)] || 'application/octet-stream' });
    fs.createReadStream(fp).pipe(res);
  }).listen(PORT);
}

(async () => {
  const server = serve();
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));

  let fail = 0;
  const ok = (c, m) => { console.log((c ? '  ok  : ' : '  FAIL: ') + m); if (!c) fail++; };

  await page.goto(`http://localhost:${PORT}/index.html`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.documentElement.getAttribute('data-obol-boot') === 'ready', { timeout: 8000 }).catch(() => {});

  ok(await page.getAttribute('html', 'data-obol-boot') === 'ready', 'boot committed (data-obol-boot=ready)');
  ok(await page.locator('nav.mainnav a').count() >= 5, 'nav rendered');

  // engine present + packs loaded
  const actionCount = await page.evaluate(() => window.OBOL && window.OBOL.packs ? window.OBOL.packs.actions().length : 0);
  ok(actionCount === 157, 'packs loaded in browser (157 actions, got ' + actionCount + ')');

  // Add a target -> coach should surface an nmap-first move
  await page.goto(`http://localhost:${PORT}/index.html#/targets`, { waitUntil: 'networkidle' });
  await page.fill('#t-ip', '10.10.10.161');
  await page.click('#t-add');
  await page.waitForTimeout(300);
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  const moveCount = await page.locator('.move').count();
  ok(moveCount >= 1, 'coach renders at least one move after adding a target (' + moveCount + ')');
  const firstMove = (await page.locator('.move-title').first().textContent()) || '';
  ok(/nmap/i.test(firstMove), 'top coach move is nmap recon ("' + firstMove.trim() + '")');
  ok(await page.locator('.move .cmd-run code').count() >= 1, 'move shows a copy-ready command (no toggles)');
  ok(await page.locator('.move input, .move select').count() === 0, 'coach move has NO form toggles/switches');

  // Blocked list present
  ok(await page.locator('.coach-blocked').count() >= 1, 'blocked-with-reasons section present');

  // Evidence route loads + lazy-loads parsers (if built)
  await page.goto(`http://localhost:${PORT}/index.html#/evidence`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(await page.locator('#ev-text').count() === 1, 'evidence paste box present');

  // End-to-end paste-back: parse real nmap output -> facts minted -> coach recomputes.
  await page.waitForFunction(() => window.OBOL && window.OBOL.parsers && window.OBOL.parsers.parseActionOutput, { timeout: 8000 }).catch(() => {});
  const factsBefore = await page.evaluate(() => Object.keys(window.OBOL.store.factSet().kinds()).length);
  const nmapOut = [
    'Nmap scan report for 10.10.10.161',
    'Host is up (0.021s latency).',
    'PORT     STATE SERVICE',
    '53/tcp   open  domain',
    '88/tcp   open  kerberos-sec',
    '389/tcp  open  ldap',
    '445/tcp  open  microsoft-ds',
  ].join('\n');
  await page.fill('#ev-text', nmapOut);
  await page.fill('#ev-cmd', 'nmap -Pn -sC -sV 10.10.10.161');
  await page.click('#ev-parse');
  await page.waitForTimeout(400);
  const factsAfter = await page.evaluate(() => Object.keys(window.OBOL.store.factSet().kinds()).length);
  ok(factsAfter > factsBefore, 'parsing nmap output minted new facts (' + factsBefore + ' -> ' + factsAfter + ')');
  const kinds = await page.evaluate(() => Object.keys(window.OBOL.store.factSet().kinds()));
  ok(kinds.indexOf('ldap.reachable') >= 0 || kinds.indexOf('port:389') >= 0, 'nmap parse produced AD-service facts (ldap.reachable/port:389)');

  // The coach should now surface more moves than before parsing.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  ok(await page.locator('.move').count() >= 2, 'coach recomputed: more moves unlocked after evidence (' + (await page.locator('.move').count()) + ')');

  ok(errors.length === 0, 'no console errors (' + errors.length + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : '') + ')');

  await browser.close();
  server.close();
  console.log(fail ? ('\nBROWSER SMOKE: ' + fail + ' FAILURES') : '\nBROWSER SMOKE: all passed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
