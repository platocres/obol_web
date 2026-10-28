/* Real-app paste -> parse -> storage -> Coach -> user explanation checks.
 * The HTTP server serves static local files. Tool output is synthetic text only.
 */
'use strict';
const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = process.env.OBOL_BEHAVIOR_OUTPUT || path.join(os.tmpdir(), 'obol-outcome-browser');
const MIME = { '.js': 'text/javascript', '.html': 'text/html', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' };
const A = '10.0.0.10', B = '10.0.0.20';
let checks = 0;
function check(condition, message) { assert.ok(condition, message); checks++; }
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const file = path.resolve(ROOT, '.' + (url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname)));
  if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch(process.env.OBOL_BROWSER_EXECUTABLE ? { executablePath: process.env.OBOL_BROWSER_EXECUTABLE } : {});
  let page;
  try {
    page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port + '/index.html');
    await page.waitForFunction(() => window.OBOL && OBOL.store && document.documentElement.dataset.obolBoot === 'ready');
    async function fresh(name) {
      await page.evaluate(async ({ name, A, B }) => {
        await OBOL.store.createEngagement(name);
        OBOL.store.update(e => { e.params = { target: A }; e.activeTarget = A; e.targets = [
          { ip: A, hostname: 'ALPHA', domain: 'alpha.local' }, { ip: B, hostname: 'BETA', domain: 'beta.local' }]; });
        const fact = (kind, target, value = {}) => OBOL.facts.makeFact({ kind, scope: 'host:' + target, value, source: 'test' });
        OBOL.store.addFacts([fact('target.configured', A), fact('target.configured', B), fact('smb.reachable', A), fact('smb.reachable', B),
          fact('port:445', A), fact('port:445', B), fact('credential.available', A, { user: 'alice', password: 'AlphaPassword!', domain: 'alpha.local' }),
          fact('credential.available', B, { user: 'bob', password: 'BetaPassword!', domain: 'beta.local' })]);
        OBOL.store.setActiveTarget(A);
        const alice = OBOL.context.credentials(OBOL.store.active()).find(c => (c.user || c.principal) === 'alice');
        OBOL.store.selectCredential(alice.id, A);
        location.hash = '#/path';
        OBOL.router.render();
        await OBOL.ingest.ensureParsers();
      }, { name, A, B });
      await page.locator('.ns-card').first().waitFor();
    }
    async function paste(command, output, expectedKind, actionId = 'validate-credential') {
      await page.evaluate(({ command, actionId }) => {
        const context = OBOL.store.resolvedContext({ command, actionId });
        OBOL.ingest.setLastCopied({ command, actionId, target: context.target, context: OBOL.context.snapshot(context) });
      }, { command, actionId });
      await page.locator('#nav-paste').click();
      await page.locator('#qp-text').fill(output);
      const association = await page.locator('#qp-binding').textContent();
      check(/Association:/.test(association) && !association.includes('AlphaPassword!') && !association.includes('BetaPassword!'), 'Paste shows a secret-free association before committing evidence');
      await page.locator('#qp-go').click();
      await page.waitForFunction(() => {
        const el = document.getElementById('qp-result');
        const receipt = el && (el.querySelector('[data-outcome]') || (el.matches('[data-outcome]') ? el : null));
        return !!receipt && !!receipt.getAttribute('data-outcome') && !/^Reading/.test(el.textContent.trim());
      });
      const displayedKind = await page.locator('#qp-result').evaluate(el => (el.querySelector('[data-outcome]') || el).getAttribute('data-outcome'));
      check(displayedKind === expectedKind, 'User sees ' + expectedKind + ' (received ' + displayedKind + ')');
      const visible = await page.locator('#qp-result').textContent();
      const result = await page.evaluate(() => {
        const e = OBOL.store.active(); const a = e.activities[0];
        const scope = ip => OBOL.store.factSetForTarget(ip).facts.filter(f => f.state === 'supported').map(f => f.kind);
        return { outcome: a.outcome, stdout: a.stdout, target: a.target, a: scope('10.0.0.10'), b: scope('10.0.0.20'),
          done: OBOL.store.doneIdsForTarget('10.0.0.10'),
          ready: OBOL.coach.rankFor(OBOL.store.factSetForTarget('10.0.0.10'), { target: '10.0.0.10' }).onFlow.map(m => m.id) };
      });
      check(result.outcome.kind === expectedKind, 'Displayed ' + expectedKind + ' agrees with persisted outcome');
      check(result.stdout === output, expectedKind + ' retains original output');
      check(visible.length > 30 && !/No new facts\. That output did not prove/.test(visible), expectedKind + ' has a meaningful user explanation');
      await page.locator('[data-qp-close]').first().click();
      return { ...result, visible, association };
    }

    await fresh('Browser authentication outcomes');
    const command = "nxc smb " + A + " -u alice -p 'AlphaPassword!'";
    let result = await paste(command, 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!', 'success');
    check(result.a.includes('smb.authenticated') && !result.b.includes('smb.authenticated'), 'Browser paste authenticates only the output host');
    check(!result.a.includes('access.admin'), 'Browser login is not displayed or stored as administrator access');
    check(result.visible.includes(A) && /alice/i.test(result.visible) && /smb/i.test(result.visible), 'Visible authentication receipt names its host, identity, and service');
    await page.locator('.coach-flash [data-outcome="success"]').waitFor();
    await page.evaluate(() => OBOL.router.render());
    check(await page.locator('.coach-flash [data-outcome="success"]').count() === 1, 'Coach retains the result explanation across ordinary renders');
    await page.evaluate(({ A, B }) => { OBOL.store.setActiveTarget(B); OBOL.router.render(); OBOL.store.setActiveTarget(A); OBOL.router.render(); }, { A, B });
    check(await page.locator('.coach-flash [data-outcome="success"]').count() === 1, 'Returning to a target restores its latest result explanation');
    result = await paste(command + ' --shares', 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\nSMB ' + A + ' 445 ALPHA [-] Error enumerating shares: STATUS_ACCESS_DENIED', 'authorization-denied', 'smb-share-inventory');
    check(result.a.includes('smb.authenticated') && !result.a.includes('access.admin'), 'Authorization failure retains authentication without creating privilege');
    check(/authenticat/i.test(result.visible) && /denied|permission|authoriz/i.test(result.visible), 'User receives both accepted authentication and denied operation');
    result = await paste(command, 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!', 'duplicate');
    check(result.outcome.originalKind === 'success' && /confirm|duplicate|already|again/i.test(result.visible), 'Repeated success is explained as reconfirmation');

    await fresh('Browser unresolved outcomes');
    for (const [output, kind] of [['zsh: command not found: nxc', 'environment-error'],
      ['Connection opened.\nOperation started...\n[output truncated]', 'unknown']]) {
      result = await paste(command, output, kind);
      check(result.outcome.retryable && !result.done['validate-credential'], kind + ' keeps its move available for retry');
      check(!result.a.includes('smb.authenticated') && !result.a.includes('access.admin'), kind + ' creates no authentication or access');
      check(result.ready.includes('validate-credential'), 'Coach still offers credential validation after ' + kind);
    }

    await page.evaluate(() => {
      window.__outcomeOriginalParser = OBOL._parserCommon._parse_nxc_common;
      OBOL._parserCommon._parse_nxc_common = () => { throw new Error('intentional browser parser contract failure'); };
    });
    try { result = await paste(command, 'SMB ' + A + ' 445 ALPHA [*] parser failure fixture', 'parser-error'); }
    finally { await page.evaluate(() => { OBOL._parserCommon._parse_nxc_common = window.__outcomeOriginalParser; delete window.__outcomeOriginalParser; }); }
    check(result.outcome.retryable && /parser|read|review|unresolved/i.test(result.visible), 'Parser exception has an honest displayed recovery path');

    await fresh('Browser partial and completed negative');
    result = await paste(command + ' --shares', 'SMB ' + A + ' 445 ALPHA [+] alpha.local\\alice:AlphaPassword!\n[output truncated]', 'partial', 'smb-share-inventory');
    check(result.a.includes('smb.authenticated') && result.outcome.retryable && !result.done['smb-share-inventory'], 'Partial output retains authentication without completing its operation');
    check(/partial|incomplete|unresolved/i.test(result.visible), 'User can distinguish a partial result from a completed result');
    await fresh('Browser completed negative');
    result = await paste('nmap -sn ' + A, 'Starting Nmap 7.95\nNmap done: 1 IP address (0 hosts up) scanned in 0.12 seconds', 'completed-negative', 'nmap-fast-open-ports');
    check(!result.a.includes('host.up') && result.outcome.conclusive, 'Explicit completed negative scan produces no live-host proof');

    await fresh('Browser stale copied target');
    await page.evaluate(({ A, B }) => {
      const S = OBOL.store; S.setActiveTarget(B);
      const bob = OBOL.context.credentials(S.active()).find(c => c.user === 'bob');
      S.selectCredential(bob.id, B); S.setActiveTarget(A);
    }, { A, B });
    result = await paste(command, 'SMB ' + B + ' 445 BETA [+] beta.local\\bob:BetaPassword!', 'success');
    check(result.target === B && result.b.includes('smb.authenticated') && !result.a.includes('smb.authenticated'), 'Observed output target takes precedence over a stale copied target');
    check(result.outcome.context.target === B && /bob/.test(result.outcome.context.principal), 'Displayed interpretation uses the destination target identity');
    check(result.visible.includes(B) && /bob/.test(result.visible), 'Visible receipt explains the observed destination context');
    check(result.association.includes(B) && /bob/.test(result.association), 'Precommit association already identifies the observed destination');

    await fresh('Browser target and identity scope');
    await page.locator('.cred-pin-toggle').check();
    check(await page.evaluate(() => OBOL.store.credentialPin().enabled), 'Visible credential pin control enables the temporary override');
    await page.locator('.cred-pin-toggle').uncheck();
    check(!await page.evaluate(() => OBOL.store.credentialPin().enabled), 'Visible credential pin control clears the temporary override');
    await page.locator('.cred-none').click();
    check(await page.evaluate(() => !OBOL.store.resolvedContext({ service: 'smb' }).credentialId), 'Visible no-credential control clears the selected identity');
    await page.locator('.cred-row').filter({ has: page.locator('.cred-user', { hasText: 'alice' }) }).click();
    check(await page.evaluate(() => /alice/.test(OBOL.store.resolvedContext({ service: 'smb' }).principal)), 'Visible credential card selects an identity record');
    const scopeResult = await page.evaluate(({ A, B }) => {
      const S = OBOL.store, creds = OBOL.context.credentials(S.active());
      const a = creds.find(c => (c.user || c.principal) === 'alice'); const b = creds.find(c => (c.user || c.principal) === 'bob');
      S.setActiveTarget(B); S.selectCredential(b.id, B); S.setActiveTarget(A);
      const restoredA = S.resolvedContext({ service: 'smb' }); S.setCredentialPin(true); S.setActiveTarget(B);
      const pinned = S.resolvedContext({ service: 'smb' }); S.setCredentialPin(false);
      const restoredB = S.resolvedContext({ service: 'smb' });
      S.setActiveTarget(A); S.selectCredential(null, A); S.setActiveTarget(B); S.setActiveTarget(A);
      const none = S.resolvedContext({ service: 'smb' });
      return { restoredA: restoredA.credentialId === a.id, pinned: pinned.credentialId === a.id && pinned.targetDomain === 'beta.local' && pinned.authRealm === 'alpha.local',
        restoredB: restoredB.credentialId === b.id, none: !none.credentialId && !none.params.password && !none.params.nthash };
    }, { A, B });
    check(Object.values(scopeResult).every(Boolean), 'Real browser restores target choices, explicit none, and pin without changing the target domain');

    await fresh('Recovered credential handoff');
    const recovered = '$krb5asrep$23$charlie@ALPHA.LOCAL:' + '1'.repeat(32) + '$' + '2'.repeat(64) + ':FixtureCharliePassword!';
    result = await paste('hashcat -m 18200 loot/asrep.hashes --show', recovered, 'success', 'crack-asrep');
    check(await page.evaluate(() => OBOL.store.resolvedContext().credential.user === 'alice'), 'Recovering another credential preserves the active identity');
    const selectRecovered = page.getByRole('button', { name: /Select and Validate.*charlie/i });
    await selectRecovered.waitFor();
    fs.mkdirSync(OUTPUT, { recursive: true });
    await page.screenshot({ path: path.join(OUTPUT, 'credential-prompt.png'), fullPage: true });
    await page.evaluate(() => {
      // A rebuilt sidebar must not make one user click select the account repeatedly.
      for (let i = 0; i < 4; i++) {
        const sidebar = document.getElementById('cred-switch');
        sidebar.replaceWith(sidebar.cloneNode(false));
        OBOL.app.renderSidebar();
        OBOL.credbar.mount();
      }
      window.__selectionCalls = 0;
      window.__originalSelection = OBOL.store.selectCredential;
      OBOL.store.selectCredential = function (...args) { window.__selectionCalls++; return window.__originalSelection.apply(this, args); };
    });
    await selectRecovered.click();
    const selected = await page.evaluate(() => {
      OBOL.store.selectCredential = window.__originalSelection;
      const c = OBOL.store.resolvedContext({service:'smb'});
      return {calls:window.__selectionCalls,user:c.credential.user,authenticated:c.facts.has('smb.authenticated'),ready:OBOL.coach.compute().onFlow[0].id};
    });
    check(selected.calls === 1 && selected.user === 'charlie', 'One prompt click selects the recovered credential once after sidebar rebuilds');
    check(!selected.authenticated && selected.ready === 'validate-credential', 'Selection opens credential validation without fabricating authentication');
    await page.locator('.ns-card').first().getByRole('heading', {name:'Validate A Found Credential',exact:true}).waitFor();

    await fresh('Administrator proof attempt without prior validation');
    const adminHash = 'a'.repeat(32), proofPath = 'C:\\Users\\Administrator\\Desktop\\root.txt';
    await page.evaluate(({ A }) => {
      OBOL.store.addFacts(['os.windows','ad.dc_candidate','objective.local_flag'].map(kind => OBOL.facts.makeFact({kind,scope:'host:' + A,value:{}})));
      OBOL.router.render();
    }, { A });
    result = await paste('impacket-secretsdump alpha.local/alice@' + A + ' -just-dc',
      '[*] Using the DRSUAPI method to get NTDS.DIT secrets\nalpha.local\\Administrator:500:' + 'b'.repeat(32) + ':' + adminHash + ':::', 'success', 'dcsync');
    await page.getByRole('button', {name:/Select and Validate.*Administrator/i}).click();
    const rootCard = page.locator('.ns-card[data-action="flag-hunt-root-windows"]');
    await rootCard.locator('.ns-body').waitFor();
    check(await page.locator('.ns-card').first().getAttribute('data-action') === 'flag-hunt-root-windows', 'Selecting recovered Administrator opens the root proof attempt first');
    check(await rootCard.getByRole('button', {name:/^Remote/i}).getAttribute('aria-pressed') === 'true', 'Untested Administrator defaults to the remote proof attempt in the visible card');
    const proofCommands = await page.evaluate(() => {
      const c = OBOL.coach.compute(), move = c.onFlow.find(a => a.id === 'flag-hunt-root-windows');
      return {probe:OBOL.command.fillCommand(move,c.facts,{params:c.params},0).filled,admin:c.facts.forAction(move,move.commands[0]).has('access.admin')};
    });
    check(!proofCommands.admin && proofCommands.probe.includes('-H ' + adminHash), 'The visible proof attempt uses selected material without claiming administrative access');
    check((await rootCard.locator('.ns-body').textContent()).includes('-H ' + adminHash), 'The fully filled hash command is actually shown to the user');
    await page.screenshot({path:path.join(OUTPUT,'administrator-proof-attempt.png'),fullPage:true});
    result = await paste(proofCommands.probe,
      'SMB ' + A + ' 445 ALPHA [-] alpha.local\\Administrator:' + adminHash + ' STATUS_LOGON_FAILURE', 'rejected', 'flag-hunt-root-windows');
    check(!result.a.includes('access.admin') && !result.a.includes('objective.root_flag'), 'A failed browser proof attempt creates no administrative or objective proof');
    result = await paste(proofCommands.probe,
      'SMB ' + A + ' 445 ALPHA [+] alpha.local\\Administrator:' + adminHash + ' (Pwn3d!)\nSMB ' + A + ' 445 ALPHA ' + proofPath, 'success', 'flag-hunt-root-windows');
    check(result.a.includes('access.admin') && !result.b.includes('access.admin'), 'The successful proof attempt establishes administrative access only on its observed host');
    const proofRead = await page.evaluate(() => {
      const c = OBOL.coach.compute(), move = c.onFlow.find(a => a.id === 'flag-hunt-root-windows');
      return OBOL.command.fillCommand(move,c.facts,{params:c.params},5).filled;
    });
    check(proofRead.includes(proofPath) && !proofRead.includes('{{'), 'Pasting the located path fills the next flag read');
    result = await paste(proofRead,
      'SMB ' + A + ' 445 ALPHA [+] alpha.local\\Administrator:' + adminHash + ' (Pwn3d!)\nSMB ' + A + ' 445 ALPHA ' + 'f'.repeat(32), 'success', 'flag-hunt-root-windows');
    check(result.a.includes('objective.root_flag') && !result.b.includes('objective.root_flag'), 'The browser captures the root proof without a separate credential-validation step');

    await fresh('Credential ledger proof boundaries');
    await page.evaluate(() => { location.hash = '#/creds'; });
    await page.locator('.creds-route').waitFor();
    check(await page.locator('.cv-place.ok,.cv-place.adm').count() === 0, 'Credential ledger never labels recovered material as authenticated or administrative');
    check((await page.locator('.cv-place').allTextContents()).every(text => /Untested/.test(text)), 'Recovered credential rows explicitly remain untested');
    result = await paste("nxc winrm " + A + " -u alice -p 'AlphaPassword!'", 'WINRM ' + A + ' 5985 ALPHA [+] alpha.local\\alice:AlphaPassword!', 'success');
    check(!result.a.includes('foothold.windows') && !result.a.includes('access.shell'), 'Real WinRM authentication output never fabricates a shell');
    const ledgerStates = await page.evaluate(() => OBOL.routes.creds.render._entries.map(e => ({ user: e.user, status: e.status, worksOn: e.worksOn })));
    check(ledgerStates.some(e => e.user === 'alice' && e.worksOn.some(w => w.ip === '10.0.0.10' && w.services.includes('winrm'))), 'Credential ledger identifies the service actually authenticated');
    check(ledgerStates.filter(e => e.user === 'bob').every(e => e.worksOn.length === 0), 'Another recovered identity stays untested after Alice authenticates');
    await page.evaluate(({ A }) => { OBOL.store.addFacts([OBOL.facts.makeFact({kind:'credential.available',scope:'host:' + A,value:{user:'alice',domain:'alpha.local',password:'RotatedPassword!'}})]); OBOL.router.render(); }, { A });
    const rotatedLedger = await page.evaluate(() => OBOL.routes.creds.render._entries.filter(e => e.user === 'alice').map(e => ({ rotated: e.secret === 'RotatedPassword!', works: e.worksOn.length })));
    check(rotatedLedger.some(e => e.rotated && e.works === 0), 'Credential ledger does not transfer old authentication to a rotated secret');
    const reportBoundary = await page.evaluate(async ({ A }) => {
      await OBOL.lazy.loadGroup('report');
      const report = OBOL.report.buildContext({ facts:OBOL.store.factSet(),params:{target:A},targets:OBOL.store.active().targets,activities:OBOL.store.active().activities });
      return { access: report.tiles.access_state, foothold: report.access_ladder.some(s => /Foothold/i.test(s.stage) && s.reached), markdown:OBOL.report.toMarkdown(OBOL.report.document('oscp',report)) };
    }, { A });
    check(!reportBoundary.foothold && /no access proven/i.test(reportBoundary.access), 'Browser report retains the authentication-versus-shell boundary');
    check(/shell access unproven|no initial access demonstrated/i.test(reportBoundary.markdown), 'Actual report export explains that shell access remains unproven');

    await page.evaluate(async ({ A, B }) => {
      const e = await OBOL.store.createEngagement('Legacy realm collision');
      e.params = { target:B, domain:'beta.local', username:'alice', password:'SharedPassword!' }; e.activeTarget=B;
      e.targets=[{ip:A,domain:'alpha.local'},{ip:B,domain:'beta.local'}]; e.credentials=[];
      e.facts=[OBOL.facts.factToJson(OBOL.facts.makeFact({kind:'credential.available',scope:'host:' + A,value:{user:'alice',domain:'alpha.local',password:'SharedPassword!'}})),
        OBOL.facts.factToJson(OBOL.facts.makeFact({kind:'credential.available',scope:'host:' + B,value:{user:'alice',domain:'beta.local',password:'SharedPassword!'}}))];
      delete e.contextSelections; await OBOL.store._persistEngagement(e);
    }, { A, B });
    await page.reload();
    await page.waitForFunction(() => window.OBOL && OBOL.store && document.documentElement.dataset.obolBoot === 'ready');
    const migrated = await page.evaluate(() => { const c=OBOL.store.resolvedContext({service:'smb'}); return {realm:c.authRealm,domain:c.targetDomain,user:c.principal}; });
    check(migrated.realm === 'beta.local' && migrated.domain === 'beta.local' && /alice/.test(migrated.user), 'Legacy workspace reload preserves the known realm when usernames and secrets collide across domains');
    check(!errors.length, 'Outcome and context routes produce no browser exceptions: ' + errors.join('; '));
    fs.mkdirSync(OUTPUT, { recursive: true });
    await page.screenshot({ path: path.join(OUTPUT, 'outcome-coach.png'), fullPage: true });
    console.log('BROWSER OUTCOME FLOW: ' + checks + ' behavioral checks passed. Artifacts: ' + OUTPUT);
  } catch (error) {
    fs.mkdirSync(OUTPUT, { recursive: true });
    if (page) await page.screenshot({ path: path.join(OUTPUT, 'failure.png'), fullPage: true }).catch(() => {});
    throw error;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => server.close());
