/* Browser-local idle, paste work, and first-credential regression checks. */
'use strict';
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const { chromium } = require('playwright');
const ROOT = path.resolve(__dirname, '..');
const PROFILE = process.argv.includes('--profile');
const OUTPUT = process.env.OBOL_PERFORMANCE_OUTPUT || path.join(os.tmpdir(), 'obol-browser-performance');
const A = '10.0.0.10';
const record = '$krb5asrep$23$svc-alfresco@ALPHA.LOCAL:' + '1'.repeat(32) + '$' + '2'.repeat(64) + ':FixturePassword!';
const sources = new Map();
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const file = path.resolve(ROOT, '.' + (url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname)));
  if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
  const mime = {'.js':'text/javascript','.css':'text/css','.html':'text/html','.json':'application/json','.svg':'image/svg+xml'};
  res.writeHead(200, {'Content-Type':mime[path.extname(file)] || 'application/octet-stream'});
  if (process.env.OBOL_PROFILE_REF) {
    const rel = path.relative(ROOT,file).split(path.sep).join('/');
    if (!sources.has(rel)) sources.set(rel,cp.execFileSync('git',['show',process.env.OBOL_PROFILE_REF + ':' + rel],{cwd:ROOT,maxBuffer:16*1024*1024}));
    res.end(sources.get(rel)); return;
  }
  fs.createReadStream(file).pipe(res);
});
let checks = 0;
function check(value, message) { if (!PROFILE) assert.ok(value, message); checks++; }
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch(process.env.OBOL_BROWSER_EXECUTABLE ? {executablePath:process.env.OBOL_BROWSER_EXECUTABLE} : {});
  try {
    const page = await browser.newPage({viewport:{width:1920,height:1080}});
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => {
      localStorage.setItem('obol.motion', 'off');
      localStorage.setItem('obol.coins', 'off');
      window.__rafRuns = 0;
      const raf = window.requestAnimationFrame;
      window.requestAnimationFrame = fn => raf.call(window, ts => { window.__rafRuns++; fn(ts); });
    });
    await page.goto('http://127.0.0.1:' + server.address().port + '/index.html#/path');
    await page.waitForFunction(() => document.documentElement.dataset.obolBoot === 'ready');
    await page.evaluate(async ({A}) => {
      await OBOL.store.createEngagement('Idle and first credential regression');
      OBOL.store.update(e => { e.params={target:A}; e.activeTarget=A; e.targets=[{ip:A}]; });
      OBOL.store.addFacts(['target.configured','smb.reachable','port:445','os.windows','ad.dc_candidate'].map(kind => OBOL.facts.makeFact({kind,scope:'host:' + A})));
      location.hash = '#/path';
      OBOL.router.render();
      await OBOL.ingest.ensureParsers();
    }, {A});
    await page.locator('.ns-card').first().waitFor();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Performance.enable');
    const metrics = async () => Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(m => [m.name,m.value]));
    const before = await metrics();
    const idleRaf = await page.evaluate(() => window.__rafRuns);
    await new Promise(resolve => setTimeout(resolve, 3000));
    const after = await metrics();
    const idle = await page.evaluate(start => ({raf:window.__rafRuns-start,animations:document.getAnimations().filter(a => a.playState==='running').map(a => ({name:a.animationName,target:a.effect.target.className}))}), idleRaf);
    console.log(JSON.stringify({idle,taskSeconds:after.TaskDuration-before.TaskDuration,layoutSeconds:after.LayoutDuration-before.LayoutDuration,recalcSeconds:after.RecalcStyleDuration-before.RecalcStyleDuration}));
    check(idle.raf === 0 && idle.animations.length === 0, 'Motion Off leaves no running animation loops or CSS animations');
    const steadyBefore = await metrics();
    const system = await browser.newBrowserCDPSession();
    const processBefore = await system.send('SystemInfo.getProcessInfo');
    await new Promise(resolve => setTimeout(resolve, 3000));
    const steadyAfter = await metrics();
    const processAfter = await system.send('SystemInfo.getProcessInfo');
    const idleCpu = processAfter.processInfo.map(p => ({type:p.type,seconds:p.cpuTime-((processBefore.processInfo.find(b=>b.id===p.id)||{}).cpuTime||p.cpuTime)}));
    console.log(JSON.stringify({steadyIdleTaskSeconds:steadyAfter.TaskDuration-steadyBefore.TaskDuration,idleCpu}));
    check(steadyAfter.TaskDuration-steadyBefore.TaskDuration < 0.1, 'A settled Motion Off page uses less than 100 ms of main-thread work over three seconds');
    const hiddenStart = await page.evaluate(() => {
      const holder=document.createElement('div'); holder.id='hidden-graph-fixture'; holder.hidden=true;
      holder.innerHTML=OBOL.graphview.html('<svg viewBox="0 0 320 60"><rect width="320" height="60"/></svg>');
      document.body.appendChild(holder); OBOL.graphview.attach(holder); return window.__rafRuns;
    });
    await new Promise(resolve=>setTimeout(resolve,200));
    const hiddenFrames = await page.evaluate(start => window.__rafRuns-start,hiddenStart);
    console.log(JSON.stringify({hiddenGraphAnimationFrames:hiddenFrames}));
    check(hiddenFrames===0, 'A hidden graph does not poll for its dimensions on animation frames');
    await page.evaluate(()=>{document.getElementById('hidden-graph-fixture').hidden=false;});
    await page.waitForFunction(()=>!!document.querySelector('#hidden-graph-fixture svg').style.transform);
    check(true, 'A hidden graph fits when revealed without polling');
    await page.evaluate(()=>document.getElementById('hidden-graph-fixture').remove());

    await page.locator('#nav-paste').click();
    await page.locator('#qp-text').fill(record);
    await page.locator('#qp-go').click();
    await page.waitForFunction(() => {const el=document.getElementById('qp-result');return el && el.textContent.trim() && !/^Reading/.test(el.textContent.trim());});
    const selection = await page.evaluate(() => { const e=OBOL.store.active(),c=OBOL.context ? OBOL.store.resolvedContext() : null; return {user:c ? c.credential && c.credential.user : e.params.username,credentials:OBOL.context ? OBOL.context.credentials(e).map(c=>({user:c.user,scope:c.scope})) : [],selections:e.contextSelections,outcome:e.activities[0].outcome && e.activities[0].outcome.kind}; });
    console.log(JSON.stringify({firstCredential:selection}));
    check(selection.user === 'svc-alfresco', 'Global raw paste selects the first applicable cleartext credential from a blank identity');
    check(await page.locator('#params [data-param="username"]').inputValue() === 'svc-alfresco', 'The parameters visibly show the automatic selection');
    await new Promise(resolve => setTimeout(resolve, 100));
    const effects = await page.evaluate(() => ({raf:window.__rafRuns,coinCanvas:!!document.getElementById('obolcoin-fx'),animations:document.getAnimations().filter(a=>a.playState==='running').length}));
    console.log(JSON.stringify({afterPasteEffects:effects}));
    check(!effects.coinCanvas && effects.animations === 0, 'A successful paste cannot start coin or CSS effects with Motion Off');
    await page.locator('[data-qp-close]').first().click();
    if (!process.env.OBOL_PROFILE_REF) {
      const closed = page.locator('.ns-card[data-body-deferred]:visible').first();
      const id = await closed.getAttribute('data-action');
      check(await closed.locator('.ns-body').count() === 0, 'A closed card does not construct command bodies during a paste');
      await closed.press('Enter');
      await page.locator('.ns-card[data-action="' + id + '"] .ns-body').waitFor({state:'visible'});
      check(await page.locator('.ns-card[data-action="' + id + '"] .ns-cmd').count() > 0, 'Opening a deferred card by keyboard constructs its commands');
      await page.locator('#ns-multiopen').click();
      await page.locator('.ns-card[data-body-deferred]:visible').first().press('Enter');
      check(await page.locator('.ns-card.selected').count() >= 2, 'Deferred commands support Keep Cards Open');
      await page.locator('#ns-multiopen').click();
    }

    if (process.env.OBOL_PROFILE_WORKSPACE) await page.evaluate(async data => { await OBOL.store.importData(data); OBOL.router.render(); }, JSON.parse(fs.readFileSync(process.env.OBOL_PROFILE_WORKSPACE,'utf8')));
    else await page.evaluate(({A}) => OBOL.store.addFacts(Array.from({length:200},(_,index)=>OBOL.facts.makeFact({kind:'fixture.observation',scope:'host:' + A,value:{index}}))),{A});
    await page.evaluate(() => {
      window.__work = {};
      for (const [obj,names] of [[OBOL.facts,['fingerprint','FactSet']],[OBOL.pack,['planPath','opensUpNext']],[OBOL.context || {},['resolve']],[OBOL.store,['factSetForTarget']],[OBOL.app,['renderSidebar']],[OBOL.routes.path,['render']]]) {
        for(const name of names){const original=obj[name]; if(!original)continue; const key=(obj===OBOL.store?'store.':obj===OBOL.routes.path?'path.':'')+name;window.__work[key]={calls:0,ms:0};obj[name]=function(...args){const start=performance.now();window.__work[key].calls++;try{return original.apply(this,args);}finally{window.__work[key].ms+=performance.now()-start;}};obj[name].prototype=original.prototype;}
      }
    });
    await cdp.send('Profiler.enable');
    await cdp.send('Profiler.start');
    const start = Date.now();
    await page.locator('#nav-paste').click();
    await page.locator('#qp-text').fill(process.env.OBOL_PROFILE_PASTE_FILE ? fs.readFileSync(process.env.OBOL_PROFILE_PASTE_FILE,'utf8') : 'Connection opened.\nOperation started...\n[output truncated]');
    const mintStart = Date.now();
    await page.locator('#qp-go').click();
    await page.waitForFunction(() => {const el=document.getElementById('qp-result');return el && el.textContent.trim() && !/^Reading/.test(el.textContent.trim());});
    const elapsedMs = Date.now()-start;
    const mintMs = Date.now()-mintStart;
    const {profile} = await cdp.send('Profiler.stop');
    const work = await page.evaluate(() => window.__work);
    const ids = new Map(profile.nodes.map(n=>[n.id,n.callFrame]));
    const samples = new Map();
    (profile.samples||[]).forEach((id,i)=>{const f=ids.get(id);const key=(f.functionName||'(anonymous)')+' '+f.url+':'+(f.lineNumber+1);samples.set(key,(samples.get(key)||0)+(profile.timeDeltas[i]||0));});
    const hotspots=[...samples].sort((a,b)=>b[1]-a[1]).slice(0,12).map(([frame,us])=>({frame,ms:us/1000}));
    console.log(JSON.stringify({elapsedMs,mintMs,work,hotspots}));
    check(work['path.render'].calls <= 1, 'One global paste renders the Coach only once');
    check(work.renderSidebar.calls <= 2, 'One global paste coalesces sidebar rendering');
    check(!errors.length, 'No browser exceptions: ' + errors.join('; '));
    fs.mkdirSync(OUTPUT,{recursive:true});
    fs.writeFileSync(path.join(OUTPUT,'measurements.json'),JSON.stringify({idle,steadyIdleTaskSeconds:steadyAfter.TaskDuration-steadyBefore.TaskDuration,idleCpu,selection,effects,elapsedMs,mintMs,work,hotspots},null,2));
    await page.screenshot({path:path.join(OUTPUT,'paste.png'),fullPage:false});
    console.log('BROWSER PERFORMANCE: ' + checks + ' checks. Artifacts: ' + OUTPUT);
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>server.close());
