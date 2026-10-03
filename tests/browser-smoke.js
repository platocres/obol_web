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
  // a first-time visitor lands on the plain Obol skin, in a clean untitled run — never an
  // "Imported engagement" with a stale seed target. (Neon and the rest stay selectable in ⚙.)
  ok(await page.getAttribute('html', 'data-skin') === 'obol', 'default skin is obol for a fresh visitor');
  const firstEng = await page.evaluate(() => { var e = window.OBOL.store.active(); return { name: e && e.name, target: (e && e.params && e.params.target) || '' }; });
  ok(firstEng.name !== 'Imported engagement' && firstEng.target !== '10.129.85.48', 'fresh engagement is not the legacy import (' + JSON.stringify(firstEng) + ')');

  // presentation modules loaded (motion background, coin bursts, ⚙ settings)
  ok(await page.evaluate(() => !!(window.OBOL && window.OBOL.backdrop && window.OBOL.coins)), 'backdrop + coin modules attached');
  ok(await page.locator('#obol-settings-toggle').count() === 1, 'bottom-right settings button rendered');
  ok(await page.locator('#skin-select').count() === 0, 'legacy appbar skin select removed (moved into settings)');
  const brandCoin = await page.locator('.brand svg.coin').count();
  ok(brandCoin === 1, 'brand mark is the gold coin SVG');

  // engine present + packs loaded
  const actionCount = await page.evaluate(() => window.OBOL && window.OBOL.packs ? window.OBOL.packs.actions().length : 0);
  ok(actionCount === 166, 'packs loaded in browser (166 actions, got ' + actionCount + ')');

  // Engagement screen is the default landing; launch an OSCP run with a scoped target.
  await page.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(200);
  ok(await page.locator('.pf-card').count() >= 6, 'engagement screen shows platform profiles (' + (await page.locator('.pf-card').count()) + ')');
  // A fresh visitor gets the getting-started guide, not a confusing "Untitled Run" phase bar.
  ok(await page.locator('.eng-welcome').count() === 1 && await page.locator('.home-spine').count() === 0,
    'fresh engagement shows the getting-started guide, no phase bar');
  ok(await page.locator('#eng-workdir').count() === 1, 'setup form has a working-directory field');
  // The working-dir placeholder is a GENERIC example — a remembered machine-specific base must not leak in.
  await page.evaluate(() => { try { window.OBOL.store.setPref('workspaceBase', '~/CTF/HTB/boxes/Windows/forest'); } catch (e) {} window.OBOL.router.render(); });
  await page.waitForTimeout(80);
  const wdPh = (await page.getAttribute('#eng-workdir', 'placeholder')) || '';
  ok(wdPh.indexOf('forest') === -1 && wdPh.indexOf('engagements') !== -1, 'the working-dir placeholder stays a generic example, ignoring a remembered machine-specific base (got "' + wdPh + '")');
  await page.locator('.pf-card:has(input[value="oscp"])').click();
  await page.fill('#eng-name', 'OSCP Exam');
  await page.fill('#eng-scope', '10.10.10.10 junk 10.10.10.0/24');
  await page.fill('#eng-workdir', '/home/kali/lab/box');
  // the attacker-box IP + interface field
  ok(await page.locator('#eng-lhost').count() === 1 && await page.locator('#eng-iface').count() === 1, 'setup form has a VM IP + interface field');
  await page.fill('#eng-lhost', '10.10.14.9');
  await page.selectOption('#eng-iface', 'tun0');
  await page.click('#eng-launch');
  await page.waitForTimeout(500);
  ok(page.url().indexOf('#/path') >= 0, 'launch lands on the coach');
  const savedLhost = await page.evaluate(() => (window.OBOL.store.active().params || {}).lhost);
  ok(savedLhost === '10.10.14.9', 'launch saved the attacker VM IP as {{lhost}} (' + savedLhost + ')');
  const launchedPlatform = await page.evaluate(() => window.OBOL.store.active().profile.platform);
  ok(launchedPlatform === 'oscp', 'launched engagement carries the OSCP profile (' + launchedPlatform + ')');
  // workspace: saved on the engagement, drives command output paths, and shows the scaffold banner
  const wsRoot = await page.evaluate(() => (window.OBOL.store.active().workspace || {}).root);
  ok(wsRoot === '/home/kali/lab/box', 'launch saved the working directory (' + wsRoot + ')');
  ok(await page.locator('.ws-banner').count() === 1 && (await page.locator('.ws-banner .cmd-run code').first().textContent() || '').indexOf('mkdir -p /home/kali/lab/box/{') === 0,
    'coach shows the one-time workspace scaffold command');
  const cmdHasScandir = await page.evaluate(() => Array.prototype.some.call(document.querySelectorAll('.move .cmd-run code'), function (c) { return c.textContent.indexOf('/home/kali/lab/box/scans/') !== -1; }));
  ok(cmdHasScandir, 'coach commands write into the workspace scans/ directory');
  // launching configured the default in place (no stray second run) and the home panel now shows it
  const engCount = await page.evaluate(() => window.OBOL.store.listEngagements().length);
  ok(engCount === 1, 'launch configured the default run in place, no stray empty engagement (' + engCount + ')');
  const scopedTargets = await page.evaluate(() => window.OBOL.store.active().targets.length);
  ok(scopedTargets === 1, 'scope paste kept the bare IP as a target, filtered junk+CIDR (' + scopedTargets + ')');
  await page.waitForTimeout(200);
  const moveCount = await page.locator('.move').count();
  ok(moveCount >= 1, 'coach renders at least one move after adding a target (' + moveCount + ')');
  const firstMove = (await page.locator('.move-title').first().textContent()) || '';
  ok(/nmap/i.test(firstMove), 'top coach move is nmap recon ("' + firstMove.trim() + '")');
  ok(await page.locator('.move .cmd-run code').count() >= 1, 'move shows a copy-ready command (no toggles)');
  ok(await page.locator('.move input, .move select').count() === 0, 'coach move has NO form toggles/switches');
  // now that the run is configured, the home panel shows the active run + phase bar (not the guide)
  await page.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(200);
  ok(await page.locator('.eng-active').count() === 1 && await page.locator('.home-spine').count() === 1 && await page.locator('.eng-welcome').count() === 0,
    'a configured engagement shows the active panel with the phase bar (not the getting-started guide)');
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(200);

  // Blocked list present
  ok(await page.locator('.coach-blocked').count() >= 1, 'blocked-with-reasons section present');

  // Scope lens: the newcomer-safe syllabus filter renders with its three levels and a default selection.
  ok(await page.locator('.coach-lens .lens-opt').count() === 3, 'scope lens renders OSCP / OSCP+ / All');
  ok(await page.locator('.coach-lens .lens-opt.on').count() === 1, 'scope lens has exactly one active level');

  // Live context rail is present on the coach (shown at >=1500px; element always rendered).
  ok(await page.locator('.withrail .context-rail').count() === 1, 'coach live context rail rendered');
  ok(await page.evaluate(() => !!(window.OBOL && window.OBOL.rail && window.OBOL.rail.html)), 'rail module exposed for reuse');

  // Guided fact picker (sidebar): a friendly labelled option adds the underlying fact kind.
  ok(await page.locator('#fact-pick .fp-sel').count() === 1, 'sidebar guided fact picker rendered');
  const beforePick = await page.evaluate(() => window.OBOL.store.factSet().has('smb.reachable'));
  await page.selectOption('#fact-pick .fp-sel', 'smb.reachable');
  await page.click('#fact-pick .fp-add');
  await page.waitForTimeout(150);
  const afterPick = await page.evaluate(() => window.OBOL.store.factSet().has('smb.reachable'));
  ok(!beforePick && afterPick, 'picker added the smb.reachable fact');

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

  // File-ingest: a firehose output (too big to paste — e.g. bloodyAD / full ldapsearch) is attached
  // as a file, parsed through the same pipeline, and stored CAPPED (never the whole 200k chars).
  const bigDump = ['# firehose output, attached as a file instead of pasted', 'PORT     STATE SERVICE', '5985/tcp open  wsman']
    .concat(Array.from({ length: 5000 }, (_, i) => 'noise line ' + i + ' :: nothing the parser recognizes here')).join('\n');
  await page.fill('#ev-cmd', 'nmap -p- 10.10.10.10');
  await page.setInputFiles('#ev-file', { name: 'nmap-full.txt', mimeType: 'text/plain', buffer: Buffer.from(bigDump) });
  await page.waitForTimeout(400);
  const fileIngest = await page.evaluate(() => {
    var a = window.OBOL.store.active().activities[0] || {};
    var res = (document.getElementById('ev-result') || {}).textContent || '';
    return { source: a.source, file: a.file, capped: (a.stdout || '').indexOf('truncated') !== -1, resHasName: res.indexOf('nmap-full.txt') !== -1 };
  });
  ok(fileIngest.source === 'file' && fileIngest.file === 'nmap-full.txt', 'attached output file ingested through the evidence pipeline');
  ok(fileIngest.capped, 'a huge attached dump is stored capped, not whole');

  // The coach should now surface more moves than before parsing.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  ok(await page.locator('.move').count() >= 2, 'coach recomputed: more moves unlocked after evidence (' + (await page.locator('.move').count()) + ')');

  // Per-target attack-path page (scoped to the launched target's facts).
  await page.goto(`http://localhost:${PORT}/index.html#/target/10.10.10.10`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.target-chain .spine-node', { timeout: 6000 }).catch(() => {});
  ok(await page.locator('.target-chain .spine-node').count() === 6, 'target page shows the attack-chain bar');
  ok(await page.locator('.target-route svg.obol-graph').count() >= 1, 'target page renders the attack-path graph');
  // graph node labels are Title Cased (no lowercase-article fact labels like "a live host")
  const lowerNode = await page.evaluate(() => Array.from(document.querySelectorAll('.target-route svg.obol-graph text'))
    .map((t) => (t.textContent || '').trim()).some((s) => /^(a|an|the|open|port) /.test(s)));
  ok(!lowerNode, 'graph node labels are Title Cased (no lowercase-article labels)');
  ok(await page.locator('.acc-pill').count() === 1, 'target page shows an access level');
  ok(await page.locator('.tmove').count() >= 1, 'target page shows scoped next moves');
  // attack path: dense horizontal block ribbon (this target has recon facts from the earlier nmap paste)
  ok(await page.locator('.apath-flow .apath-block').count() >= 1, 'target page shows the attack-path ribbon (' + (await page.locator('.apath-flow .apath-block').count()) + ' blocks)');
  ok(await page.locator('.apath-block .ph-chip').count() >= 1, 'attack-path blocks carry a phase category chip');
  ok((await page.locator('.target-route .coach-sec-h').allTextContents()).some(function (h) { return h.indexOf('Attack Path — What Led to What') !== -1; }), 'attack-path heading is Title Case');
  // A proven hostname is reflected onto the target record and shown alongside the IP in the header.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([
      F.makeFact({ kind: 'host.hostname', scope: 'host:10.10.10.10', value: { name: 'BOXY' }, state: F.ProofState.SUPPORTED, source: 'test' }),
      F.makeFact({ kind: 'host.domain', scope: 'host:10.10.10.10', value: { domain: 'corp.local' }, state: F.ProofState.SUPPORTED, source: 'test' }),
    ], 'test');
  });
  // re-render the target route in-app (no full reload → engagement already loaded)
  await page.evaluate(() => window.OBOL.router.go('home'));
  await page.waitForTimeout(60);
  await page.evaluate(() => window.OBOL.router.go('target/10.10.10.10'));
  await page.waitForSelector('.target-ident .ident-host', { timeout: 6000 }).catch(() => {});
  ok((await page.locator('.target-ident .ident-host').textContent().catch(() => '') || '').indexOf('BOXY') !== -1, 'the target identity block shows the proven hostname in its labelled Hostname row');
  ok((await page.locator('.target-ident .ident-ip').textContent().catch(() => '') || '').indexOf('10.10.10.10') !== -1, 'the identity block shows the IP in its labelled IP row');
  ok((await page.locator('.target-ident .ident-dom').textContent().catch(() => '') || '').indexOf('corp.local') !== -1, 'the identity block fills the Domain row once the domain is proven');
  ok(await page.evaluate(() => ((window.OBOL.store.active().targets.find((t) => t.ip === '10.10.10.10') || {}).hostname)) === 'BOXY', 'the proven hostname is synced onto the target record');

  // Credential switcher: collected creds appear in the sidebar; clicking one fills the params.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([
      F.makeFact({ kind: 'credential.available', scope: 'host:10.10.10.9', value: { user: 'alice', domain: 'corp.local', password: 'S3cret!' }, state: F.ProofState.SUPPORTED, source: 'test' }),
      F.makeFact({ kind: 'credential.available', scope: 'host:10.10.10.9', value: { user: 'bob', domain: 'corp.local', nthash: 'aabbccddeeff00112233445566778899' }, state: F.ProofState.SUPPORTED, source: 'test' }),
    ], 'test');
    window.OBOL.app.renderSidebar();
  });
  ok(await page.locator('#cred-switch .cred-row').count() >= 2, 'credential switcher lists collected creds (' + (await page.locator('#cred-switch .cred-row').count()) + ')');
  // Redaction is opt-in: a recovered password shows in cleartext by default (not dots).
  const aliceSecret = (await page.locator('#cred-switch .cred-row', { hasText: 'alice' }).locator('.cred-secret').textContent()) || '';
  ok(aliceSecret.indexOf('S3cret!') !== -1 && aliceSecret.indexOf('•') === -1, 'the credential switcher shows the real password by default (redaction is opt-in), got "' + aliceSecret + '"');
  // the live context RAIL's Credentials card also shows the recovered secret (not just user@domain).
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(150);
  const railSecret = (await page.locator('.context-rail .rail-secret').first().textContent().catch(() => '')) || '';
  ok(railSecret.indexOf('S3cret!') !== -1, 'the coach rail Credentials card shows the recovered password, got "' + railSecret + '"');
  // …and the report's Redact Secrets toggle masks it here too.
  await page.evaluate(() => { window.OBOL.store.update((e) => { e.ui = e.ui || {}; e.ui.reportRedact = true; }, 'ui'); window.OBOL.app.renderSidebar(); });
  await page.waitForTimeout(80);
  const aliceRedacted = (await page.locator('#cred-switch .cred-row', { hasText: 'alice' }).locator('.cred-secret').textContent()) || '';
  ok(aliceRedacted.indexOf('•') !== -1 && aliceRedacted.indexOf('S3cret!') === -1, 'turning Redact Secrets ON masks the password in the switcher');
  await page.evaluate(() => { window.OBOL.store.update((e) => { e.ui = e.ui || {}; e.ui.reportRedact = false; }, 'ui'); window.OBOL.app.renderSidebar(); });
  await page.waitForTimeout(80);
  const bobRow = page.locator('#cred-switch .cred-row', { hasText: 'bob' });
  await bobRow.click();
  const swapped = await page.evaluate(() => { const p = window.OBOL.store.active().params; return p.username === 'bob' && p.nthash === 'aabbccddeeff00112233445566778899'; });
  ok(swapped, 'clicking a credential fills the engagement params (bob + NT hash)');
  ok(await page.locator('#cred-switch .cred-row.active', { hasText: 'bob' }).count() === 1, 'the chosen credential is marked active');
  // The right-rail Credentials card dedupes: one credential proven on two scopes must show ONCE, not twice.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([F.makeFact({ kind: 'credential.available', scope: 'host:10.10.10.7', value: { user: 'alice', domain: 'corp.local', password: 'S3cret!' }, state: F.ProofState.SUPPORTED, source: 'test2' })], 'test');
  });
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(150);
  ok((await page.locator('.context-rail .rail-list li', { hasText: 'alice@corp.local' }).count()) === 1, 'the coach rail lists a credential proven on two scopes only once (deduped)');

  // Retire/un-retire is judged PER MOVE (its own runs), not per fact-kind.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.update((e) => { e.checklist = e.checklist || {}; e.checklist['bloodyad-acl'] = 'empty'; }, 'done');
    S.addFacts([F.makeFact({ kind: 'host.os_hint', scope: 'host:10.10.10.9', value: { os: 'windows' }, state: F.ProofState.SUPPORTED, source: 'test' })], 'test');
    window.OBOL.router.render();
  });
  await page.waitForTimeout(120);
  ok((await page.locator('.move[data-action="bloodyad-acl"]').count()) === 0, 'a move retired empty (none of its own runs produced a fact) stays out of the coach');
  // The sccm bug: a fact-KIND this move produces (credential.candidate) exists from an UNRELATED source —
  // that must NOT un-retire it.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([F.makeFact({ kind: 'credential.candidate', scope: 'domain:corp.local', value: { kind: 'asrep_hash', count: 1 }, state: F.ProofState.SUPPORTED, source: 'asrep-crack' })], 'test');
    window.OBOL.router.render();
  });
  await page.waitForTimeout(120);
  ok((await page.locator('.move[data-action="bloodyad-acl"]').count()) === 0, 'a produced fact-kind from an UNRELATED move does not un-retire (the sccm regression)');
  // New evidence: a run attributed to THIS move produces a fact → un-retire (the chain is recoverable).
  await page.evaluate(() => {
    window.OBOL.store.update((e) => { e.activities = e.activities || []; e.activities.unshift({ at: Date.now(), action_id: 'bloodyad-acl', produced: ['ad.acl_lead'], command: "bloodyAD -d corp.local --host 10.10.10.9 -u alice -p x get writable" }); }, 'activity');
    window.OBOL.router.render();
  });
  await page.waitForTimeout(120);
  ok((await page.locator('.move[data-action="bloodyad-acl"]').count()) >= 1, 'the move RE-APPEARS once one of ITS OWN runs produced a fact (un-retired)');

  // Run Log: every command run is recorded and reviewable (with a filter), not just the attack-path moves.
  await page.evaluate(() => {
    window.OBOL.store.update((e) => {
      e.activities = e.activities || [];
      e.activities.unshift({ at: Date.now(), command: "nxc smb 10.10.10.9 -u alice -p S3cret!", produced: ['smb.authenticated'], stdout: 'SMB 10.10.10.9 445 BOXY [+] corp.local\\alice:S3cret! (Pwn3d!)', target: '10.10.10.9', scope: 'host:10.10.10.9', action_id: 'nxc-arsenal' });
    }, 'activity');
  });
  await page.goto(`http://localhost:${PORT}/index.html#/history`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.history-route .hl-row', { timeout: 6000 }).catch(() => {});
  ok((await page.locator('.history-route .hl-row').count()) >= 1, 'the Run Log lists commands run on the engagement');
  ok(((await page.locator('.history-route .hl-cmd').first().textContent().catch(() => '')) || '').indexOf('nxc smb') !== -1, 'the Run Log shows the command text');
  await page.locator('.hl-filter').fill('zzz-no-such-command');
  await page.waitForTimeout(80);
  ok((await page.locator('.history-route .hl-row:not([hidden])').count()) === 0, 'the Run Log filter hides non-matching rows');
  // selecting a credential fills the matching parameter FIELDS (secret lands in the right field)
  await page.locator('#cred-switch .cred-row', { hasText: 'alice' }).click();
  ok(await page.evaluate(() => { const p = window.OBOL.store.active().params; return p.username === 'alice' && p.password === 'S3cret!' && !p.nthash; }), 'selecting a password credential fills USER + PASSWORD and clears NT hash');
  ok((await page.evaluate(() => document.querySelector('#params [data-param=password]').value)) === 'S3cret!', 'the PASSWORD parameter field is populated on select');
  ok((await page.evaluate(() => document.querySelector('#params [data-param=password]').type)) === 'text', 'the PASSWORD field shows cleartext by default (redaction is opt-in) — not masked dots');
  // turning Redact Secrets on masks the param field too
  await page.evaluate(() => { window.OBOL.store.update((e) => { e.ui = e.ui || {}; e.ui.reportRedact = true; }, 'ui'); window.OBOL.app.renderSidebar(); });
  await page.waitForTimeout(60);
  ok((await page.evaluate(() => document.querySelector('#params [data-param=password]').type)) === 'password', 'turning Redact Secrets ON masks the PASSWORD field');
  await page.evaluate(() => { window.OBOL.store.update((e) => { e.ui = e.ui || {}; e.ui.reportRedact = false; }, 'ui'); window.OBOL.app.renderSidebar(); });
  await page.waitForTimeout(60);
  // each value has its own copy control (username vs secret)
  ok(await page.locator('#cred-switch .cred-row', { hasText: 'alice' }).locator('.cred-copy-user').count() === 1, 'the credential row has a copy-username button');
  ok(await page.locator('#cred-switch .cred-row', { hasText: 'alice' }).locator('.cred-copy-secret').count() === 1, 'the credential row has a separate copy-secret button');
  // manually add any kind of credential (an NT hash) and use it
  const credsBefore = await page.locator('#cred-switch .cred-row').count();
  await page.locator('.cred-add-btn').click();
  await page.locator('.cf-user').fill('carol');
  await page.locator('.cf-type').selectOption('NT');
  await page.locator('.cf-secret').fill('ffeeddccbbaa99887766554433221100');
  await page.locator('.cf-save').click();
  await page.waitForTimeout(120);
  ok(await page.locator('#cred-switch .cred-row').count() === credsBefore + 1, 'a manually-added credential joins the switcher');
  await page.locator('#cred-switch .cred-row', { hasText: 'carol' }).click();
  const usedAdded = await page.evaluate(() => { const p = window.OBOL.store.active().params; return p.username === 'carol' && p.nthash === 'ffeeddccbbaa99887766554433221100'; });
  ok(usedAdded, 'the manually-added credential fills commands when selected');
  // and it can be removed
  await page.locator('#cred-switch .cred-row', { hasText: 'carol' }).locator('.cred-del').click();
  await page.waitForTimeout(120);
  ok(await page.locator('#cred-switch .cred-row', { hasText: 'carol' }).count() === 0, 'a manually-added credential can be removed');

  // Engagement-wide Attack Path on the home screen (single target → identical ribbon, no host header).
  await page.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.eng-apath .apath-flow', { timeout: 5000 }).catch(() => {});
  ok(await page.locator('.eng-apath .apath-flow .apath-block').count() >= 1, 'engagement screen shows the engagement-wide Attack Path (' + (await page.locator('.eng-apath .apath-block').count()) + ' blocks)');
  ok(await page.locator('.eng-apath .apath-host').count() === 1, 'the engagement Attack Path carries a per-host IP·hostname header (shown even for one target)');

  // Loot glue: proving a user list resolves {{userlist}}/{{hashfile}} to workspace paths and offers
  // a "set up first" heredoc that writes the exact proven names to loot/users.txt.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([
      F.makeFact({ kind: 'ad.user_list', scope: 'domain:corp.local', value: { users: ['Administrator', 'Guest', 'svc-web'], count: 3 }, state: F.ProofState.SUPPORTED, source: 'test' }),
      F.makeFact({ kind: 'port:88', scope: 'host:10.10.10.9', value: {}, state: F.ProofState.SUPPORTED, source: 'test' }),
      F.makeFact({ kind: 'kerberos.reachable', scope: 'host:10.10.10.9', value: {}, state: F.ProofState.SUPPORTED, source: 'test' }),
    ], 'test');
  });
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(250);
  const roast = page.locator('.move[data-action="asrep-roast"]');
  ok(await roast.count() === 1, 'proving a user list surfaces the AS-REP Roasting move on the coach');
  const roastCmd = (await roast.locator('.cmd-run code').allTextContents()).join('\n');
  ok(roastCmd.indexOf('/home/kali/lab/box/loot/users.txt') !== -1, '{{userlist}} now resolves to the workspace loot/users.txt path (not a bare placeholder)');
  ok(roastCmd.indexOf('/home/kali/lab/box/loot/asrep.hashes') !== -1, '{{hashfile}} resolves to loot/asrep.hashes so roast + crack agree on one file');
  const prep = roast.locator('.move-prep');
  ok(await prep.count() === 1, 'the roast move offers a "set up first" materialize block');
  const prepCmd = (await prep.locator('.cmd-run code').first().textContent()) || '';
  ok(prepCmd.indexOf("cat > /home/kali/lab/box/loot/users.txt <<'EOF'") === 0, 'the materialize command is a heredoc writing the canonical users.txt');
  ok(prepCmd.indexOf('Administrator') !== -1 && prepCmd.indexOf('svc-web') !== -1, 'the heredoc body carries the exact proven usernames');
  const prepBeforeCmds = await roast.evaluate((el) => {
    const prep = el.querySelector('.move-prep'), cmd = el.querySelector('.cmd:not(.cmd-prep)');
    return !!(prep && cmd && (prep.compareDocumentPosition(cmd) & Node.DOCUMENT_POSITION_FOLLOWING));
  });
  ok(prepBeforeCmds, 'the "set up first" block renders ABOVE the roast commands it must precede');

  // Inline per-command ingestion on the coach: open a move's paste box, ingest its output in place.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.coach .move .btn-pasteback', { timeout: 6000 });
  const actsBefore = await page.evaluate(() => (window.OBOL.store.active().activities || []).length);
  ok(await page.locator('.coach .move .move-ingest[hidden]').count() >= 1, 'each move carries an inline ingestion box (collapsed by default)');
  await page.locator('.coach .move .btn-pasteback').first().click();
  await page.waitForSelector('.coach .move .move-ingest:not([hidden]) .mi-text', { timeout: 3000 });
  ok(true, 'the Paste Output button expands the inline ingestion box in place (no route jump)');
  await page.locator('.coach .move .move-ingest:not([hidden]) .mi-text').fill('PORT      STATE SERVICE\n5985/tcp  open  wsman\n');
  await page.locator('.coach .move .move-ingest:not([hidden]) .mi-go').click();
  await page.waitForTimeout(500);
  const actsAfter = await page.evaluate(() => (window.OBOL.store.active().activities || []).length);
  ok(actsAfter === actsBefore + 1, 'inline ingestion records exactly ONE activity — no duplicate from re-bound listeners (' + actsBefore + '→' + actsAfter + ')');
  // Paste Output must still TOGGLE OPEN after the ingest (guards the stacked-delegated-listener
  // regression where a click nets to a no-op). Force a known-closed state first — the ingest may or
  // may not have re-rendered depending on whether the pasted output minted facts for the top move.
  await page.evaluate(() => { document.querySelectorAll('.coach .move .move-ingest:not([hidden])').forEach(function (b) { b.setAttribute('hidden', ''); }); });
  await page.locator('.coach .move .btn-pasteback').first().click();
  await page.waitForTimeout(120);
  ok(await page.locator('.coach .move .move-ingest:not([hidden])').count() >= 1, 'Paste Output still opens the box after a re-render (no listener stacking)');

  // nmap XML output (-oX -) must parse in-browser (DOMParser path). nmap always emits
  // `<!DOCTYPE nmaprun>`, which the XXE guard used to reject — so real nmap XML never parsed.
  const xmlFacts = await page.evaluate(async () => {
    await window.OBOL.ingest.ensureParsers();
    const xml = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap" args="nmap -sV -oX -" version="7.95">\n'
      + '<host><status state="up"/><address addr="10.129.95.210" addrtype="ipv4"/><ports>'
      + '<port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" extrainfo="Domain: htb.local"/></port>'
      + '<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>'
      + '</ports></host><runstats><finished summary="Nmap done"/></runstats></nmaprun>';
    const r = window.OBOL.parsers.parseActionOutput({ actionId: 'nmap-version-scripts', command: 'nmap -sC -sV -oX - 10.129.95.210', stdout: xml, source: 'nmap', scope: 'host:10.129.95.210', domain: '' });
    return (r.facts || []).map((f) => f.kind);
  });
  ok(xmlFacts.indexOf('port:389') !== -1 && xmlFacts.indexOf('service.ldap') !== -1 && xmlFacts.indexOf('ldap.reachable') !== -1, 'nmap XML (-oX -) parses ports/services despite its <!DOCTYPE nmaprun> (' + xmlFacts.length + ' facts)');

  // Reported case: a -sC -sV scan pasted onto the FAST move (tagged with the fast command) must
  // still prove BOTH scan markers — from the XML args + content — so the coach doesn't re-suggest a
  // scan already run (the double-paste friction).
  const scanMarkers = await page.evaluate(async () => {
    await window.OBOL.ingest.ensureParsers();
    const xml = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner="nmap" args="nmap -Pn -sC -sV -p 53,389,445 -oX - 10.129.95.210" version="7.95">\n'
      + '<host><status state="up"/><address addr="10.129.95.210" addrtype="ipv4"/><ports>'
      + '<port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Microsoft Windows Active Directory LDAP"/></port>'
      + '</ports></host><runstats><finished summary="Nmap done"/></runstats></nmaprun>';
    const r = window.OBOL.parsers.parseActionOutput({ actionId: 'nmap-fast-open-ports', command: 'nmap -Pn -p- --min-rate 5000 --open -oN scans/allports.txt 10.129.95.210', stdout: xml, source: 'nmap', scope: 'host:10.129.95.210', domain: '' });
    return (r.facts || []).map((f) => f.kind);
  });
  ok(scanMarkers.indexOf('scan.nmap.quick') !== -1 && scanMarkers.indexOf('scan.nmap.version') !== -1,
    'a -sC -sV scan pasted on the fast move proves BOTH scan markers in one paste (no re-suggest)');

  // Paste-anywhere: a full-terminal paste routes on its OWN prompt/command line (kali └─$ …), not the
  // move's canned command — so any tool's output mints its facts from any box (coach is proof-gated).
  const anywhere = await page.evaluate(async () => {
    await window.OBOL.ingest.ensureParsers();
    const paste = '┌──(kali㉿kali)-[~/x]\n'
      + "└─$ nxc ldap 10.10.10.9 -u '' -p '' --users\n"
      + 'LDAP 10.10.10.9 389 DC01 zoe.quinn 2020-01-01 0\n'
      + 'LDAP 10.10.10.9 389 DC01 tom.baker 2020-01-01 0\n';
    // opts.command is an UNRELATED move command (nmap) — the derived nxc command must win.
    const r = window.OBOL.ingest.run({ text: paste, command: 'nmap -Pn -p- --min-rate 5000 10.10.10.9', actionId: 'nmap-fast-open-ports', source: 'paste' });
    return { cmd: r.cmd, kinds: (r.facts || []).map((f) => f.kind) };
  });
  ok(anywhere.cmd.indexOf('nxc ldap') === 0, 'ingest routes on the paste\'s own kali-prompt command line, not the move\'s (' + anywhere.cmd + ')');
  ok(anywhere.kinds.indexOf('ad.user_list') !== -1, 'nxc --users pasted onto the NMAP move still mints ad.user_list (paste-anywhere routing)');

  // Facts sidebar collapses same-claim facts (kind+scope) — e.g. smb.reachable proven by nmap AND
  // nxc — into ONE row with an ×N count, instead of a pile of identical labels.
  await page.evaluate(() => {
    const S = window.OBOL.store, F = window.OBOL.facts;
    S.addFacts([
      F.makeFact({ kind: 'zz.collapsetest', scope: 'host:10.10.10.90', value: { tool: 'nmap' }, state: F.ProofState.SUPPORTED, source: 'test' }),
      F.makeFact({ kind: 'zz.collapsetest', scope: 'host:10.10.10.90', value: { tool: 'nxc' }, state: F.ProofState.SUPPORTED, source: 'test' }),
    ], 'test');
    window.OBOL.app.renderSidebar();
  });
  await page.waitForTimeout(80);
  const dupRows = page.locator('#facts-list .fact-item', { hasText: 'zz.collapsetest' });
  ok(await dupRows.count() === 1, 'the facts sidebar collapses two same-claim observations into ONE row (' + (await dupRows.count()) + ')');
  ok(await dupRows.locator('.fact-count').count() === 1 && (await dupRows.locator('.fact-count').textContent() || '').indexOf('2') !== -1, 'the collapsed row shows an ×N observation count');

  // Inline free-text token fill: an exec move's {{command}} placeholder gets a text box that
  // substitutes into the shown command (and the copy button) live — no trip to Tools required.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(250);
  const cmdFill = page.locator('.coach .cmd-fillable .cmd-fill[data-tok="command"]').first();
  ok(await cmdFill.count() >= 1, 'an exec move with a {{command}} placeholder offers an inline fill box on the coach');
  await cmdFill.fill('whoami /all');
  await page.waitForTimeout(60);
  const filledCmd = await cmdFill.evaluate((inp) => {
    const cmd = inp.closest('.cmd');
    return { code: cmd.querySelector('.cmd-run code').textContent, copy: cmd.querySelector('.btn-copy').getAttribute('data-copy') };
  });
  ok(filledCmd.code.indexOf('whoami /all') !== -1 && filledCmd.code.indexOf('{{command}}') === -1, 'typing fills {{command}} into the shown command live');
  ok(filledCmd.copy.indexOf('whoami /all') !== -1, 'the copy button now yields the filled command');

  // The + (new engagement) routes to the full setup form (profile, machine type, working directory),
  // not a name-only prompt that skips every option.
  await page.goto(`http://localhost:${PORT}/index.html#/path`, { waitUntil: 'networkidle' });
  await page.locator('#eng-new').click();
  await page.waitForTimeout(250);
  ok(page.url().indexOf('#/home') !== -1, 'the + button routes to the home setup surface');
  const setup = await page.evaluate(() => ({
    hasSetup: !!document.getElementById('eng-setup'),
    hasMt: !!document.getElementById('eng-mt'),
    hasWorkdir: !!document.getElementById('eng-workdir'),
    nameFocused: document.activeElement === document.getElementById('eng-name'),
  }));
  ok(setup.hasSetup && setup.hasMt && setup.hasWorkdir, 'the setup form exposes the profile, machine-type and Kali working-directory options');
  ok(setup.nameFocused, 'the new-run name field is focused so the operator can start typing');

  // New parity surfaces render without errors.
  await page.goto(`http://localhost:${PORT}/index.html#/playbooks`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.pb-card', { timeout: 6000 }).catch(() => {});
  ok(await page.locator('.pb-card').count() >= 1, 'playbooks route renders playbook cards (' + (await page.locator('.pb-card').count()) + ')');
  await page.goto(`http://localhost:${PORT}/index.html#/map`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.engmap-route, svg.obol-engmap, .em-target', { timeout: 6000 }).catch(() => {});
  ok(await page.locator('.engmap-route, svg.obol-engmap, .em-target').count() >= 1, 'engagement map route renders');
  await page.goto(`http://localhost:${PORT}/index.html#/scoreboard`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.score-total', { timeout: 6000 }).catch(() => {});
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
  ok(/10\.10\.10\.10/.test(palRun) || /nmap/i.test(palRun), 'palette fills the target into the command preview');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(100);
  ok(await page.locator('.pal-overlay.show').count() === 0, 'Escape closes the palette');

  // Engagement map: the legend swatches double as filters — clicking one hides that class of node.
  await page.goto(`http://localhost:${PORT}/index.html#/map`, { waitUntil: 'networkidle' });
  await page.waitForSelector('svg.obol-engmap .em-node', { timeout: 6000 }).catch(() => {});
  const pick = await page.evaluate(() => {
    const svg = document.querySelector('svg.obol-engmap');
    if (!svg) return null;
    for (const it of Array.from(document.querySelectorAll('.em-legend-item'))) {
      const cls = it.getAttribute('data-filter');
      if (svg.querySelector('.em-node.' + cls)) return { cls, count: svg.querySelectorAll('.em-node.' + cls).length };
    }
    return null;
  });
  ok(!!pick, 'the map legend has a swatch matching a rendered node' + (pick ? ' (' + pick.cls + ' ×' + pick.count + ')' : ''));
  if (pick) {
    const chip = page.locator('.em-legend-item[data-filter="' + pick.cls + '"]');
    await chip.click();
    await page.waitForTimeout(80);
    ok(await page.evaluate((c) => Array.from(document.querySelectorAll('.em-node.' + c)).every((n) => n.style.display === 'none'), pick.cls),
      'clicking a map legend swatch filters out that class of node');
    await chip.click();
    await page.waitForTimeout(80);
    ok(await page.evaluate((c) => Array.from(document.querySelectorAll('.em-node.' + c)).every((n) => n.style.display !== 'none'), pick.cls),
      'clicking the swatch again restores the nodes');
  }

  // Findings roll-up: a move the operator RAN that carries a report finding rolls up here, even with
  // no web-check finding.* facts (the AD case that used to leave this page empty).
  await page.evaluate(() => {
    window.OBOL.store.update((e) => {
      e.activities = e.activities || [];
      e.activities.unshift({ at: Date.now(), command: "nxc ldap 10.10.10.10 -u '' -p '' --users", source: 'paste',
        tool: 'nxc', target: '10.10.10.10', scope: 'host:10.10.10.10', action_id: 'ad-anon-ldap-enum', produced: ['ad.anonymous_bind', 'ad.user_list'] });
    }, 'seed');
  });
  await page.goto(`http://localhost:${PORT}/index.html#/findings`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.findings-route', { timeout: 6000 }).catch(() => {});
  ok(await page.locator('.findings-route').count() === 1, 'findings roll-up route renders');
  ok(await page.locator('.finding').count() >= 1, 'a run move with a report finding rolls up (' + (await page.locator('.finding').count()) + ')');
  ok((await page.locator('.findings-route').textContent() || '').indexOf('Anonymous LDAP Bind Permitted') !== -1, 'the derived finding names the issue (Anonymous LDAP Bind Permitted)');

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
  await page.waitForSelector('.rep-out pre.kali-term', { timeout: 6000 }).catch(() => {});
  ok(await page.locator('.rep-out pre.kali-term').count() >= 1, 'report renders the Kali-style terminal transcript');
  ok(await page.locator('.rep-out pre.kali-term .kt-u').count() >= 1, 'transcript shows the kali@kali prompt');
  ok(await page.locator('.rep-notes .rep-note-fld').count() >= 1, 'report shows the per-host notes editor');
  // redaction is opt-in: the toggle reads "Redact Secrets" and is unchecked (full detail) by default
  ok(await page.locator('#rep-redact').count() === 1 && !(await page.locator('#rep-redact').isChecked()), 'report redaction is opt-in (Redact Secrets toggle off by default)');
  const transcriptHasCmd = await page.evaluate(() => {
    var pre = document.querySelector('.rep-out pre.kali-term');
    return !!pre && pre.textContent.indexOf('nmap') !== -1 && pre.textContent.indexOf('kerberos') !== -1 && pre.textContent.indexOf('kali@kali') !== -1;
  });
  ok(transcriptHasCmd, 'transcript contains the prompt, command and output');
  // the on-screen report renders as white paper (black on white), like the printed output
  const paper = await page.evaluate(() => {
    const el = document.getElementById('rep-out'); if (!el) return null;
    const bg = getComputedStyle(el).backgroundColor;
    const m = bg.match(/\d+/g) || [0, 0, 0];
    return { bright: (Number(m[0]) + Number(m[1]) + Number(m[2])) / 3, text: el.textContent || '' };
  });
  ok(paper && paper.bright > 230, 'the report preview renders on white paper (bg brightness ' + (paper && Math.round(paper.bright)) + ')');
  // the "Generated" timestamp is a sane year, not a ms×1000 blowup (was rendering year 58707)
  ok(paper && !/\b(?:[3-9]\d{3,}|\d{5,})-\d\d-\d\d/.test(paper.text), 'the Generated date is a sane year (no ms-as-seconds blowup)');
  // OSCP exam report: candidate name + OSID are fillable right on the report page and land on the cover.
  ok(await page.locator('#rep-candidate').count() === 1 && await page.locator('#rep-osid').count() === 1, 'the report page exposes Candidate + OSID fields for an OSCP-style profile');
  await page.fill('#rep-candidate', 'Jordan Pace');
  await page.fill('#rep-osid', 'OS-98765');
  await page.waitForTimeout(120);
  const coverText = await page.evaluate(() => (document.getElementById('rep-out') || {}).textContent || '');
  ok(coverText.indexOf('Jordan Pace') !== -1 && coverText.indexOf('OS-98765') !== -1, 'the typed candidate + OSID appear on the report cover');
  ok(await page.evaluate(() => { const p = window.OBOL.store.active().profile || {}; return p.candidate === 'Jordan Pace' && p.osid === 'OS-98765'; }), 'candidate + OSID persist onto the engagement profile');
  // Export controls present + .docx builds with an embedded screenshot (JSZip loaded with the report bundle).
  ok(await page.locator('#rep-print').count() === 1 && await page.locator('#rep-docx').count() === 1, 'report has Print/PDF + .docx buttons');
  const docx = await page.evaluate(async () => {
    if (!window.JSZip || !window.OBOL.report.docxFiles) return { size: 0, media: 0 };
    // include a synthetic image block to exercise embedding
    var e = window.OBOL.store.active();
    var c = window.OBOL.report.buildContext({ facts: window.OBOL.store.factSet(), targets: (e.targets || []).map(function (t) { return Object.assign({}, t, { host: t.host || t.ip }); }), activities: e.activities || [], params: e.params || {} });
    var blocks = window.OBOL.report.document('oscp', c);
    var shot = (e.screenshots && e.screenshots[0]) ? e.screenshots[0].data_uri : null;
    if (shot) blocks = blocks.concat([{ t: 'image', caption: 'proof', data_uri: shot }]);
    var files = window.OBOL.report.docxFiles(blocks);
    var media = files.filter(function (f) { return f.path.indexOf('word/media/') === 0; }).length;
    var zip = new window.JSZip(); files.forEach(function (f) { zip.file(f.path, f.data, f.base64 ? { base64: true } : undefined); });
    var blob = await zip.generateAsync({ type: 'blob' });
    return { size: blob ? blob.size : 0, media: media, hasDrawing: files.some(function (f) { return f.path === 'word/document.xml' && f.data.indexOf('<w:drawing>') !== -1; }) };
  });
  ok(docx.size > 400, 'report builds a non-empty .docx (' + docx.size + ' bytes)');
  ok(docx.media >= 1 && docx.hasDrawing, 'the .docx embeds the proof screenshot as an image');

  // Target shell prompt: post-exploitation commands on a compromised host render with the box's
  // own prompt (not kali@kali). Built through the live engine so the feature is exercised end-to-end.
  const termPrompt = await page.evaluate(() => {
    var R = window.OBOL.report;
    var F = window.OBOL.facts;
    var host = '10.10.10.77';
    var fs = new F.FactSet([F.makeFact({ kind: 'foothold.linux', scope: 'host:' + host, source: 'ssh' })]);
    var c = R.buildContext({
      facts: fs, targets: [{ host: host, hostname: 'boxy', os: 'linux' }],
      activities: [
        { tool: 'nmap', command: 'nmap -sC -sV ' + host, at: 1, target: host, scope: 'host:' + host, stdout: 'PORT STATE\n22/tcp open ssh' },
        { tool: 'whoami', command: 'whoami', at: 2, target: host, scope: 'host:' + host, stdout: 'svc' },
      ], includeSecrets: true, name: 't',
    });
    var html = R.toHtml(R.document('oscp', c));
    return { hasTarget: /kali-term term-target/.test(html), hasBoxPrompt: html.indexOf('svc@boxy:~$') !== -1, hasKali: html.indexOf('kali@kali') !== -1 };
  });
  ok(termPrompt.hasTarget && termPrompt.hasBoxPrompt, 'on-target command renders the box shell prompt (svc@boxy:~$)');
  ok(termPrompt.hasKali, 'recon command keeps the kali@kali prompt alongside it');

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

  // Mobile mode: at phone width the layout must not scroll sideways, the hamburger shows, and it
  // opens the engagement drawer. Guards the grid-blowout / off-canvas regressions.
  const mob = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true });
  await mob.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await mob.waitForFunction(() => document.documentElement.getAttribute('data-obol-boot') === 'ready', { timeout: 8000 }).catch(() => {});
  await mob.waitForTimeout(300);
  const hOverflow = await mob.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(hOverflow <= 1, 'no horizontal page scroll at 390px (overflow ' + hOverflow + 'px)');
  ok(await mob.locator('#nav-toggle').isVisible(), 'hamburger shows at phone width');
  await mob.click('#nav-toggle');
  // Wait for the slide-in transition to actually finish rather than a fixed sleep — under CI load the
  // drawer can still be mid-animation (left < 0) at a fixed 300ms, which flaked this assertion.
  const drawer = await mob.waitForFunction(() => {
    var open = document.documentElement.classList.contains('drawer-open');
    var el = document.getElementById('sidebar');
    if (!open || !el) return false;
    var r = el.getBoundingClientRect();
    return r.left >= -1 && r.width > 0 && r.right <= window.innerWidth + 1;
  }, { timeout: 3000 }).then(() => true).catch(() => false);
  ok(drawer, 'hamburger opens the engagement drawer on-screen');
  await mob.close();

  // Whole-session import panel: paste a multi-command capture (with obol's prompt stamp), import it in one
  // pass, and confirm the segments run through the same pipeline (facts minted, LHOST learned, summary shown).
  // Placed late so its unshifted activities / minted hostname don't perturb the earlier ordered assertions.
  await page.goto(`http://localhost:${PORT}/index.html#/evidence`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.OBOL && window.OBOL.parsers && window.OBOL.parsers.parseActionOutput, { timeout: 8000 }).catch(() => {});
  await page.waitForTimeout(200);
  ok(await page.locator('.ev-import summary').count() >= 1, 'Evidence route shows the "Import a Full Session" panel');
  await page.evaluate(() => { document.querySelectorAll('.ev-import, .ev-import-setup').forEach(function (d) { d.open = true; }); });
  const stampShown = await page.evaluate(() => (document.getElementById('ev-stamp-code') || {}).textContent || '');
  ok(/precmd_functions\+=\(/.test(stampShown), 'the import panel surfaces the non-destructive zsh prompt-stamp snippet');
  // the route selector defaults to auto-route and lists the engagement's targets
  ok(await page.locator('#ev-imp-target').count() === 1, 'the import panel has a "Route facts to" target selector');
  ok((await page.evaluate(() => (document.getElementById('ev-imp-target') || {}).value)) === 'auto', 'the selector defaults to Auto-route by IP');
  ok(await page.locator('#ev-imp-oldip').count() === 1 && await page.locator('#ev-imp-newip').count() === 1, 'the import panel offers an old-IP → new-IP remap for reverted labs');
  const impCountBefore = await page.evaluate(() => (window.OBOL.store.active().activities || []).length);
  // A capture that touches TWO hosts: the launched target (10.10.10.10) and a NEW host (10.10.10.55).
  const sessionCap = [
    '[2026-09-27 18:00:01 UTC] [tun0:10.10.14.9]',
    '┌──(kali㉿kali)-[~/lab]', '└─$ nxc smb 10.10.10.10',
    'SMB 10.10.10.10 445 DC01 [*] Windows Server 2016 Build 14393 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)',
    '[2026-09-27 18:02:30 UTC] [tun0:10.10.14.9]',
    '┌──(kali㉿kali)-[~/lab]', '└─$ nmap -Pn -p- 10.10.10.55',
    'Nmap scan report for 10.10.10.55', 'Host is up.', 'PORT STATE SERVICE', '445/tcp open microsoft-ds', 'Nmap done',
  ].join('\n');
  await page.fill('#ev-imp-text', sessionCap);
  await page.click('#ev-imp-go');
  await page.waitForTimeout(400);
  const imp = await page.evaluate(() => ({
    lhost: (window.OBOL.store.active().params || {}).lhost || '',
    acts: (window.OBOL.store.active().activities || []).length,
    res: (document.getElementById('ev-imp-result') || {}).textContent || '',
    newTarget: (window.OBOL.store.active().targets || []).some((t) => t.ip === '10.10.10.55'),
    lhostIsTarget: (window.OBOL.store.active().targets || []).some((t) => t.ip === '10.10.14.9'),
  }));
  ok(imp.acts - impCountBefore === 2, 'importing a 2-command session records exactly 2 activities (' + (imp.acts - impCountBefore) + ')');
  ok(imp.lhost === '10.10.14.9', 'the configured attacker VM IP is in force as {{lhost}} during import');
  ok(/Imported 2 command/.test(imp.res), 'the import summary reports the commands imported');
  ok(/2 hosts/.test(imp.res), 'the import summary reports facts landed across 2 hosts');
  ok(imp.newTarget, 'auto-route registered the newly-touched host 10.10.10.55 as a target');
  ok(!imp.lhostIsTarget, 'the operator LHOST (10.10.14.9) was never added as a target');

  // Data reset controls: management sits near the top of Engagements; the store methods wipe cleanly.
  await page.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.eng-library', { timeout: 5000 });
  ok(await page.locator('.eng-library .eng-danger-toggle').count() === 1, 'engagement library carries a Manage / Reset disclosure near the top');
  await page.locator('.eng-danger-toggle > summary').click();
  ok(await page.locator('#eng-clear').isVisible() && await page.locator('#eng-reset').isVisible(), 'Delete-All-Engagements and Full-Reset buttons are present');
  ok(await page.locator('.obol-set-danger').count() === 1, 'the ⚙ settings panel carries an always-reachable Full Reset');
  // Delete All Engagements clears every run; init() reseeds one fresh engagement.
  const cleared = await page.evaluate(async () => { await window.OBOL.store.createEngagement('temp-run'); await window.OBOL.store.clearEngagements(); await window.OBOL.store.init(); return window.OBOL.store.listEngagements().length; });
  ok(cleared === 1, 'Delete All Engagements clears every run; a fresh one is seeded (' + cleared + ')');
  // Full Reset erases obol localStorage AND the IndexedDB database (the real "start completely fresh").
  const wiped = await page.evaluate(async () => {
    try { localStorage.setItem('obol.motion', 'off'); } catch (e) {}
    await window.OBOL.store.resetAll();
    let ls = false; try { for (let i = 0; i < localStorage.length; i++) if (/^obol/i.test(localStorage.key(i))) { ls = true; break; } } catch (e) {}
    const dbs = (indexedDB.databases ? await indexedDB.databases() : []).map((d) => d.name);
    return { ls: ls, hasDb: dbs.indexOf('obol-db') !== -1 };
  });
  ok(!wiped.ls && !wiped.hasDb, 'Full Reset erases all obol localStorage and the IndexedDB database');

  ok(errors.length === 0, 'no console errors (' + errors.length + (errors.length ? ': ' + errors.slice(0, 3).join(' | ') : '') + ')');

  // Boot must NOT hang when indexedDB.open is BLOCKED (another obol tab holding the DB, or a pending
  // Full-Reset delete) — openDB fires onblocked and never success/error. Stub that and assert the app
  // still boots (falls back to the localStorage snapshot + default seed) instead of the 2-min blank page.
  const blocked = await browser.newPage();
  await blocked.addInitScript(() => {
    indexedDB.open = function () { var req = {}; setTimeout(function () { if (req.onblocked) req.onblocked({}); }, 10); return req; };
  });
  await blocked.goto(`http://localhost:${PORT}/index.html#/home`, { waitUntil: 'domcontentloaded' });
  const bootedBlocked = await blocked.waitForFunction(
    () => document.documentElement.getAttribute('data-obol-boot') === 'ready' && ((document.getElementById('view') || {}).innerHTML || '').length > 50,
    { timeout: 6000 }).then(() => true).catch(() => false);
  ok(bootedBlocked, 'boot completes via fallback when IndexedDB.open is blocked (no infinite hang)');
  await blocked.close();

  // Loadout (step-zero tab): the leftmost nav item, the quickstart face, the Arsenal catalog, and the
  // paste-back round-trip that flips the page to the synced inventory face.
  ok((await page.locator('header.appbar .mainnav a[href="#/loadout"]').count()) === 1, 'Loadout is a primary nav item');
  ok(await page.evaluate(() => {
    var links = Array.from(document.querySelectorAll('header.appbar .mainnav a[data-nav]'));
    return links.length && (links[0].getAttribute('href') === '#/loadout');
  }), 'Loadout is the LEFTMOST nav item (step zero)');
  await page.goto(`http://localhost:${PORT}/index.html#/loadout`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.lo-route', { timeout: 6000 }).catch(() => {});
  ok((await page.locator('.lo-route .lo-steps .lo-download').count()) === 1, 'Loadout empty-state shows the guided quickstart with a download button');
  ok((await page.locator('.lo-route .lo-paste').count()) === 1, 'Loadout quickstart has the paste-back textarea');
  ok((await page.locator('.lo-route .lo-tool').count()) >= 10, 'Loadout renders the Arsenal catalog (' + (await page.locator('.lo-route .lo-tool').count()) + ' tool cards)');
  ok(await page.evaluate(() => !!(window.OBOL.ARSENAL && window.OBOL.arsenal && typeof window.OBOL.arsenal.buildScript === 'function')), 'ARSENAL data + arsenal.js loaded with the route');
  // the generated script is non-trivial and bash-shaped
  const scriptLen = await page.evaluate(() => (window.OBOL.arsenal.buildScript() || '').length);
  ok(scriptLen > 3000, 'buildScript() produces a substantial setup script (' + scriptLen + ' bytes)');
  // paste-back round-trip: feed an OBOL-ARSENAL block, ingest, and confirm the synced face appears
  await page.evaluate(() => {
    var inv = { v: 1, tools: { nxc: { present: true, invocation: 'nxc', path: '/usr/bin/nxc' }, 'impacket-psexec': { present: true, invocation: 'psexec.py', path: '/usr/bin/psexec.py' } }, staged: ['mimikatz.exe', 'Rubeus.exe'], wwwdir: '/home/kali/.obol/arsenal/www', digests: {}, wordlists: { rockyou: '/usr/share/wordlists/rockyou.txt' } };
    var ta = document.querySelector('.lo-paste'); ta.value = 'noise\nOBOL-ARSENAL v1\n' + JSON.stringify(inv) + '\n$ ';
    document.querySelector('.lo-ingest').click();
  });
  await page.waitForTimeout(150);
  ok((await page.locator('.lo-route .lo-synced-chip').count()) === 1 && (await page.locator('.lo-route .lo-fs').count()) === 1, 'pasting the OBOL-ARSENAL block flips Loadout to the synced "Your Box" face');
  ok(await page.evaluate(() => { try { return !!JSON.parse(localStorage.getItem('obol.arsenal-profile')).savedAt; } catch (e) { return false; } }), 'the machine profile is persisted per-browser');
  // a synced tool shows its resolved invocation when it differs from the canonical form.
  // impacket ships on Kali so it's under the "hide Kali-defaults" fold — untick to reveal (also exercises the toggle).
  await page.locator('.lo-route #lo-hidekali').uncheck();
  await page.waitForTimeout(100);
  ok(((await page.locator('.lo-route .lo-tool', { hasText: 'impacket-psexec' }).first().textContent().catch(() => '')) || '').indexOf('psexec.py') !== -1, 'a synced tool reflects the box\'s actual invocation (psexec.py)');
  await page.evaluate(() => { try { localStorage.removeItem('obol.arsenal-profile'); } catch (e) {} });

  await browser.close();
  server.close();
  console.log(fail ? ('\nBROWSER SMOKE: ' + fail + ' FAILURES') : '\nBROWSER SMOKE: all passed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
