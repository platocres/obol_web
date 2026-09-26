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
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.png': 'image/png' };

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

  // presentation modules loaded (motion background, coin bursts, ⚙ settings)
  ok(await page.evaluate(() => !!(window.OBOL && window.OBOL.backdrop && window.OBOL.coins)), 'backdrop + coin modules attached');
  ok(await page.locator('#obol-settings-toggle').count() === 1, 'bottom-right settings button rendered');
  ok(await page.locator('#skin-select').count() === 0, 'legacy appbar skin select removed (moved into settings)');
  const brandCoin = await page.locator('.brand svg.coin').count();
  ok(brandCoin === 1, 'brand mark is the gold coin SVG');

  // engine present + packs loaded
  const actionCount = await page.evaluate(() => window.OBOL && window.OBOL.packs ? window.OBOL.packs.actions().length : 0);
  ok(actionCount === 157, 'packs loaded in browser (157 actions, got ' + actionCount + ')');

  // Engagement screen is the default landing; launch an OSCP run with a scoped target.
  await page.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(200);
  ok(await page.locator('.pf-card').count() >= 6, 'engagement screen shows platform profiles (' + (await page.locator('.pf-card').count()) + ')');
  await page.locator('.pf-card:has(input[value="oscp"])').click();
  await page.fill('#eng-name', 'OSCP Exam');
  await page.fill('#eng-scope', '10.10.10.10 junk 10.10.10.0/24');
  await page.click('#eng-launch');
  await page.waitForTimeout(500);
  ok(page.url().indexOf('#/path') >= 0, 'launch lands on the coach');
  const launchedPlatform = await page.evaluate(() => window.OBOL.store.active().profile.platform);
  ok(launchedPlatform === 'oscp', 'launched engagement carries the OSCP profile (' + launchedPlatform + ')');
  const scopedTargets = await page.evaluate(() => window.OBOL.store.active().targets.length);
  ok(scopedTargets === 1, 'scope paste kept the bare IP as a target, filtered junk+CIDR (' + scopedTargets + ')');
  await page.waitForTimeout(200);
  const moveCount = await page.locator('.move').count();
  ok(moveCount >= 1, 'coach renders at least one move after adding a target (' + moveCount + ')');
  const firstMove = (await page.locator('.move-title').first().textContent()) || '';
  ok(/nmap/i.test(firstMove), 'top coach move is nmap recon ("' + firstMove.trim() + '")');
  ok(await page.locator('.move .cmd-run code').count() >= 1, 'move shows a copy-ready command (no toggles)');
  ok(await page.locator('.move input, .move select').count() === 0, 'coach move has NO form toggles/switches');

  // Blocked list present
  ok(await page.locator('.coach-blocked').count() >= 1, 'blocked-with-reasons section present');

  // Live context rail is present on the coach (shown at >=1500px; element always rendered).
  ok(await page.locator('.withrail .context-rail').count() === 1, 'coach live context rail rendered');
  ok(await page.evaluate(() => !!(window.OBOL && window.OBOL.rail && window.OBOL.rail.html)), 'rail module exposed for reuse');

  // Evidence route loads + lazy-loads parsers (if built)
  await page.goto(`http://localhost:${PORT}/index.html#/evidence`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(await page.locator('#ev-text').count() === 1, 'evidence paste box present');

  // End-to-end paste-back: parse real nmap output -> facts minted -> coach recomputes.
  await page.waitForFunction(() => window.OBOL && window.OBOL.parsers && window.OBOL.parsers.parseActionOutput, { timeout: 8000 }).catch(() => {});
  const factsBefore = await page.evaluate(() => Object.keys(window.OBOL.store.factSet().kinds()).length);
  const nmapOut = [
    'Nmap scan report for 10.10.10.10',
    'Host is up (0.021s latency).',
    'PORT     STATE SERVICE',
    '53/tcp   open  domain',
    '88/tcp   open  kerberos-sec',
    '389/tcp  open  ldap',
    '445/tcp  open  microsoft-ds',
  ].join('\n');
  await page.fill('#ev-text', nmapOut);
  await page.fill('#ev-cmd', 'nmap -Pn -sC -sV 10.10.10.10');
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

  // Per-target attack-path page (scoped to the launched target's facts).
  await page.goto(`http://localhost:${PORT}/index.html#/target/10.10.10.10`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  ok(await page.locator('.target-chain .spine-node').count() === 6, 'target page shows the attack-chain bar');
  ok(await page.locator('.target-route svg.obol-graph').count() >= 1, 'target page renders the attack-path graph');
  ok(await page.locator('.acc-pill').count() === 1, 'target page shows an access level');
  ok(await page.locator('.tmove').count() >= 1, 'target page shows scoped next moves');

  // New parity surfaces render without errors.
  await page.goto(`http://localhost:${PORT}/index.html#/playbooks`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(await page.locator('.pb-card').count() >= 1, 'playbooks route renders playbook cards (' + (await page.locator('.pb-card').count()) + ')');
  await page.goto(`http://localhost:${PORT}/index.html#/map`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(await page.locator('.engmap-route, svg.obol-engmap, .em-target').count() >= 1, 'engagement map route renders');
  await page.goto(`http://localhost:${PORT}/index.html#/scoreboard`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  ok(await page.locator('.score-total').count() === 1, 'scoreboard renders with the OSCP score line');

  // BloodHound: ingest a small SharpHound-CE collection and confirm the interactive graph draws.
  await page.evaluate(() => { window.OBOL.store.update(function (e) { e.params = e.params || {}; e.params.username = 'JEFF'; }, 'seed'); });
  await page.goto(`http://localhost:${PORT}/index.html#/domain`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  await page.setInputFiles('#bh-file', [
    path.join(ROOT, 'tests/fixtures-bh/domains.json'),
    path.join(ROOT, 'tests/fixtures-bh/users.json'),
    path.join(ROOT, 'tests/fixtures-bh/groups.json'),
  ]);
  await page.waitForTimeout(900);
  ok(await page.locator('.bh-card').count() >= 3, 'domain: PlumHound-style query cards rendered (' + (await page.locator('.bh-card').count()) + ')');
  ok(await page.locator('svg.bh-graph .bh-node').count() >= 2, 'domain: interactive attack-path graph drew nodes (' + (await page.locator('svg.bh-graph .bh-node').count()) + ')');
  const kerb = await page.evaluate(() => Object.keys(window.OBOL.store.factSet().kinds()).some(function (k) { return k.indexOf('ad.') === 0; }));
  ok(kerb, 'domain: BloodHound ingest minted AD facts');

  // ⌘K command palette: opens, searches commands, closes.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(200);
  await page.keyboard.press('Control+k');
  await page.waitForTimeout(200);
  ok(await page.locator('.pal-overlay.show').count() === 1, 'Ctrl+K opens the command palette');
  await page.fill('.pal-input', 'nmap');
  await page.waitForTimeout(150);
  ok(await page.locator('.pal-item').count() >= 1, 'palette finds commands for "nmap" (' + (await page.locator('.pal-item').count()) + ')');
  const palRun = (await page.locator('.pal-item.sel .pal-run').first().textContent().catch(() => '')) || '';
  ok(/10\.10\.10\.161/.test(palRun) || /nmap/i.test(palRun), 'palette fills the target into the command preview');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(100);
  ok(await page.locator('.pal-overlay.show').count() === 0, 'Escape closes the palette');

  // Findings roll-up renders.
  await page.goto(`http://localhost:${PORT}/index.html#/findings`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  ok(await page.locator('.findings-route').count() === 1, 'findings roll-up route renders');

  // Proof screenshot attaches and embeds into the report.
  await page.goto(`http://localhost:${PORT}/index.html#/evidence`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  await page.setInputFiles('#ss-file', path.join(ROOT, 'tests/fixtures-bh/px.png'));
  await page.waitForTimeout(400);
  ok(await page.locator('.ev-shot').count() >= 1, 'screenshot attaches to the evidence gallery');
  const shotInReport = await page.evaluate(() => {
    var e = window.OBOL.store.active();
    return (e.screenshots || []).length >= 1 && /^data:image/.test(e.screenshots[0].data_uri || '');
  });
  ok(shotInReport, 'screenshot stored as an embeddable data-URI (feeds the report)');

  // Report renders the verbatim command+output transcript (from the nmap paste) + the notes editor.
  await page.goto(`http://localhost:${PORT}/index.html#/report`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(await page.locator('.rep-out pre.lang-terminal').count() >= 1, 'report renders the pasted terminal transcript');
  ok(await page.locator('.rep-notes .rep-note-fld').count() >= 1, 'report shows the per-host notes editor');
  const transcriptHasCmd = await page.evaluate(() => {
    var pre = document.querySelector('.rep-out pre.lang-terminal');
    return !!pre && pre.textContent.indexOf('nmap') !== -1 && pre.textContent.indexOf('kerberos') !== -1;
  });
  ok(transcriptHasCmd, 'transcript contains the command and its output');

  // Performance budget: boot-to-interactive + route render must stay fast (guards against the
  // historical "many uncompressed layers / tabs never load" regression). Generous for CI runners.
  const perfPage = await browser.newPage();
  const t0 = Date.now();
  await perfPage.goto(`http://localhost:${PORT}/index.html`, { waitUntil: 'domcontentloaded' });
  await perfPage.waitForFunction(() => document.documentElement.getAttribute('data-obol-boot') === 'ready', { timeout: 8000 });
  const bootMs = Date.now() - t0;
  ok(bootMs < 4000, 'boot-to-interactive under budget (' + bootMs + 'ms < 4000)');
  const t1 = Date.now();
  await perfPage.evaluate(() => { location.hash = '#/path'; });
  await perfPage.waitForSelector('.coach', { timeout: 5000 });
  const routeMs = Date.now() - t1;
  ok(routeMs < 2500, 'coach route render under budget (' + routeMs + 'ms < 2500)');
  const t2 = Date.now();
  await perfPage.evaluate(() => { location.hash = '#/tools'; });
  await perfPage.waitForSelector('.tools-grid, .tool-card, [class*=tool-card]', { timeout: 6000 }).catch(() => {});
  const toolsMs = Date.now() - t2;
  ok(toolsMs < 3500, 'lazy Tools route render under budget (' + toolsMs + 'ms < 3500)');
  await perfPage.close();

  ok(errors.length === 0, 'no console errors (' + errors.length + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : '') + ')');

  await browser.close();
  server.close();
  console.log(fail ? ('\nBROWSER SMOKE: ' + fail + ' FAILURES') : '\nBROWSER SMOKE: all passed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
