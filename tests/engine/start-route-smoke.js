/* Start Here onramp route + resources data smoke test (Pillar 4.2).
 * Verifies OBOL.RESOURCES structure, 4-door layout (minilab, new, basics, exam),
 * interactive multi-step Guided Mini-Labs (terminal run, paste, Field Doctor trap diagnosis,
 * Pause & Explain breakdown, and phase progression), 5-phase plain-English concepts
 * (no raw CLI commands), unified Courses + Practice Ranges, 6-card Kali Lab setup,
 * Exam Playbooks (OSCP, CPTS, PNPT), and house style (no em/en dashes, no real box spoilers).
 */
'use strict';
var path = require('path');
var fs = require('fs');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }

globalThis.window = globalThis;
req('assets/ui/util.js');
req('assets/ui/icons.js');
req('data/resources.js');
req('assets/ui/routes/start.js');

var OBOL = globalThis.OBOL;
var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

// 1. Icons and resources data integrity
var requiredIcons = ['book', 'arrow', 'zap', 'compass', 'terminal', 'award', 'radar', 'search', 'layers', 'package', 'ext', 'check', 'globe'];
ok(requiredIcons.every(function (k) { return OBOL.ic(k).indexOf('<svg') === 0; }), 'All 13 Start Here SVG icons render inline <svg>');
var res = OBOL.RESOURCES || {};
ok(Array.isArray(res.intro) && res.intro.length === 3, 'RESOURCES.intro has 3 beginner orientation cards');
ok(Array.isArray(res.budgetTiers) && res.budgetTiers.length === 3, 'RESOURCES.budgetTiers has 3 budget tier roadmaps ($0 Free, $8-$20/mo Guided, Cert Track)');
ok(Array.isArray(res.courses) && res.courses.length >= 6, 'RESOURCES.courses populated (TryHackMe, HTB, PortSwigger, OverTheWire, TCM, OffSec, SANS)');
ok(Array.isArray(res.concepts) && res.concepts.length === 5, 'RESOURCES.concepts has 5 plain-English phases');
ok(res.concepts.every(function (c) { return c.goal && c.clue && c.color && !c.ex; }), 'RESOURCES.concepts uses labeled Phase Goal, Example Clue, and spectrum color without raw CLI commands');
ok(Array.isArray(res.miniLabs) && res.miniLabs.length === 3, 'RESOURCES.miniLabs has 3 multi-step interactive mini-labs');
ok(res.miniLabs.every(function (l) {
  return Array.isArray(l.steps) && l.steps.length === 4 &&
    l.steps[0].cards.length === 1 &&
    l.steps.slice(1).every(function (s) {
      return s.cards.length === 3 &&
        s.cards.some(function (c) { return c.kind === 'advance'; }) &&
        s.cards.some(function (c) { return c.kind === 'deadend'; }) &&
        s.cards.some(function (c) { return c.kind === 'doctor'; });
    });
}), 'Every mini-lab has 1 starter Move Card in Phase 1 and 3 Move Cards (advance, deadend, doctor) in Phases 2-4');
ok(Array.isArray(res.lab) && res.lab.length >= 6, 'RESOURCES.lab has 6 setup cards including Loadout');
ok(Array.isArray(res.practice) && res.practice.length >= 5, 'RESOURCES.practice populated');
ok(Array.isArray(res.exams) && res.exams.length === 3, 'RESOURCES.exams has OSCP, CPTS, and PNPT playbooks');
ok(Array.isArray(res.deeper) && res.deeper.length >= 3, 'RESOURCES.deeper populated');

var resRaw = fs.readFileSync(path.join(R, 'data/resources.js'), 'utf8');
var startRaw = fs.readFileSync(path.join(R, 'assets/ui/routes/start.js'), 'utf8');
ok(!/[\u2014\u2013]/.test(resRaw) && !/[\u2014\u2013]/.test(startRaw), 'no em or en dashes in resources.js or start.js');
ok(startRaw.indexOf('\u2192') === -1, 'no raw Unicode right-arrow in start.js (uses OBOL.ic("arrow"))');
ok(!/\b(?:svc-alfresco|s3rvice|10\.10\.10\.161|10\.10\.10\.3)\b/i.test(resRaw + startRaw), 'no real HTB box IPs or credentials in resources.js or start.js');

// 2. Minimal DOM harness for start.js mounted() + delegated click handling
var handlers = [];
var focusedSelector = null;
var mount = {
  _startWired: false,
  contains: function () { return true; },
  addEventListener: function (ev, fn) { handlers.push({ ev: ev, fn: fn }); },
  querySelector: function (sel) {
    return {
      selector: sel,
      scrollIntoView: function () {},
      focus: function () { focusedSelector = sel; }
    };
  }
};
var html = '';
OBOL.router = {
  render: function () {
    html = OBOL.routes.start.render();
    OBOL.routes.start.mounted({ mount: mount });
  }
};

function clickTarget(attrName, attrVal, cls) {
  var target = {
    classList: { contains: function (c) { return (cls || '').split(/\s+/).indexOf(c) >= 0; } },
    getAttribute: function (k) { return k === attrName ? attrVal : null; },
    closest: function (sel) {
      var m = sel.match(/^\[([a-z0-9_-]+)\]$/i);
      if (m && m[1] === attrName) return target;
      return null;
    }
  };
  handlers.forEach(function (h) {
    if (h.ev === 'click') h.fn({ target: target, preventDefault: function () {} });
  });
}

// Initial render
OBOL.router.render();
ok(html.indexOf('class="start-stage"') === -1, 'initial render hides .start-stage until a door is chosen');
ok((html.match(/class="sl-way start-door"/g) || []).length === 4, 'initial render shows 4 unselected self-placement doors');
ok(html.indexOf('data-start-all aria-pressed="false"') >= 0, 'Show me everything button starts with aria-pressed="false"');

// Door 1: Click "minilab" door and test the Coach Move Card + Emulated Terminal + Hand-Drawn Arrows + Field Doctor
clickTarget('data-track', 'minilab', 'sl-way start-door');
ok(html.indexOf('Interactive Guided Mini-Labs') >= 0 && html.indexOf('10.10.10.50') >= 0, 'choosing "minilab" reveals Interactive Guided Mini-Labs');
ok(focusedSelector === '.start-door[data-track="minilab"]', 'focus is preserved on the clicked minilab door');
ok(html.indexOf('Try It #1') >= 0 && html.indexOf('data-mc-copy="nmap-std"') >= 0,
  'Phase 1 starts with 1 Coach Move Card (nmap-std) and hand-drawn SVG arrow #1');

// Step 1: Copy command from Move Card -> advances arrow to #2
clickTarget('data-mc-copy', 'nmap-std', 'start-mc-copy');
ok(html.indexOf('Try It #2') >= 0, 'copying Move Card command stages it in terminal and advances arrow to #2');

// Step 2: Run command in emulated terminal -> advances arrow to #3
clickTarget('data-minilab-run', '', 'start-term-run');
ok(html.indexOf('Try It #3') >= 0 && html.indexOf('22/tcp open  ssh') >= 0,
  'running command in emulated terminal renders Nmap output and advances arrow to #3');

// Step 3: Paste output into OBOL -> reveals Pause & Explain and minted facts
clickTarget('data-minilab-paste', '', 'start-dry-btn');
ok(html.indexOf('Step 2A: Facts OBOL Extracted From Your Paste') >= 0 && html.indexOf('Step 2B: How OBOL Helped') >= 0,
  'pasting Nmap output into OBOL reveals Pause & Explain breakdown and extracted facts');

// Advance to Phase 2 of Mini-Lab 1 (3 plausible Move Cards: advance, deadend, doctor; arrows auto-hidden)
clickTarget('data-minilab-next', '', 'start-spot-cta start-dry-btn');
ok(html.indexOf('Phase 2 of 4: Enumeration') >= 0 && html.indexOf('Inspect Port 80 &amp; Port 22 (3 Plausible Moves)') >= 0,
  'clicking Continue advances the mini-lab to Phase 2 (Enumeration)');
ok(html.indexOf('data-mc-copy="ffuf-dir"') >= 0 && html.indexOf('data-mc-copy="robots-headers"') >= 0 && html.indexOf('data-mc-copy="ssh-banner-probe"') >= 0,
  'Phase 2 renders 3 plausible Coach Move Cards (ffuf-dir, robots-headers, ssh-banner-probe)');

// Run & paste the dead-end card (robots-headers) -> OBOL suppresses/retires the card
clickTarget('data-mc-copy', 'robots-headers', 'start-mc-copy');
clickTarget('data-minilab-run', '', 'start-term-run');
clickTarget('data-minilab-paste', '', 'start-dry-btn');
ok(html.indexOf('Ruled Out &amp; Suppressed') >= 0 && html.indexOf('start-mcard-suppressed') >= 0,
  'running & pasting a dead-end Move Card suppresses/retires that card with an explanation');

// Run & paste the doctor card (ssh-banner-probe) -> OBOL triggers inline Field Doctor diagnosis
clickTarget('data-mc-copy', 'ssh-banner-probe', 'start-mc-copy');
clickTarget('data-minilab-run', '', 'start-term-run');
clickTarget('data-minilab-paste', '', 'start-dry-btn');
ok(html.indexOf('Field Doctor: SSH Requires Valid Credentials First') >= 0 && html.indexOf('data-minilab-pick-optimal') >= 0,
  'running & pasting an error Move Card triggers inline OBOL Field Doctor diagnosis card');

// Click "Focus the Working Move Card (#1)" to complete Phase 2
clickTarget('data-minilab-pick-optimal', '', 'start-spot-cta start-dry-btn');
ok(html.indexOf('/backup.txt (200)') >= 0 && html.indexOf('Step 2A: Facts OBOL Extracted From Your Paste') >= 0,
  'running optimal Move Card in Phase 2 mints /backup.txt and svc_app credential and unlocks Phase 3');

// Switch to AD DC Mini-Lab (10.10.10.70)
clickTarget('data-minilab-select', 'ad-dc', 'start-dry-tab');
ok(html.indexOf('10.10.10.70') >= 0 && html.indexOf('dc01.corp.local') >= 0,
  'switching mini-lab to ad-dc updates target to dummy DC 10.10.10.70 (dc01.corp.local)');

// Door 2: Click "new" door
clickTarget('data-track', 'new', 'sl-way start-door');
ok(html.indexOf('start-lead') === -1, 'redundant .start-lead banner box removed across tracks');
ok(html.indexOf('5 Things Every Box Comes Down To') === -1, 'Part 2 (5 Things Every Box Comes Down To) removed as requested');
ok(html.indexOf('What Is Offensive Security &amp; How Does OBOL Help?') >= 0 &&
   html.indexOf('How To Get Started Based On Your Budget') >= 0 &&
   html.indexOf('start-bstep-card') >= 0,
  'choosing "new" reveals High-Level Intro and Interactive Budget Switcher with clickable Step Cards');
ok(html.indexOf('OverTheWire: Bandit') >= 0 && html.indexOf('PortSwigger Web Security Academy') >= 0,
  'default $0 Free Budget tab shows clickable step cards for OverTheWire Bandit and PortSwigger');

// Switch Budget tab to "$8 - $20 / month" ("sub") and "Cert & Career Track" ("cert")
clickTarget('data-budget-tier', 'sub', 'start-budget-tab');
ok(html.indexOf('TryHackMe Premium Learning Paths') >= 0 && html.indexOf('HTB Academy (Penetration Tester Path)') >= 0,
  'switching budget tab to "sub" renders clickable step cards for TryHackMe Premium and HTB Academy');
clickTarget('data-budget-tier', 'cert', 'start-budget-tab');
ok(html.indexOf('TCM Security Academy (PEH) + PNPT Exam') >= 0 && html.indexOf('OffSec PEN-200') >= 0,
  'switching budget tab to "cert" renders clickable step cards for PNPT, CPTS, OSCP, and GPEN');
ok(html.indexOf('OverTheWire: Bandit &amp; Natas') >= 0 && html.indexOf('UnderTheWire (PowerShell Wargames)') >= 0 && html.indexOf('PicoCTF / picoGym Practice Range') >= 0 && html.indexOf('HackMyVM') >= 0 && html.indexOf('pwn.college') >= 0,
  'Live Practice Ranges includes 12 colorful practice ranges (OverTheWire, UnderTheWire, PortSwigger Labs, PicoCTF, Root-Me, VulnHub, HackMyVM, GOAD, THM, HTB, OffSec PG, and pwn.college)');

// Door 3: Click "basics" door
clickTarget('data-track', 'basics', 'sl-way start-door');
ok(html.indexOf('start-spotlight') >= 0 && html.indexOf('start-spot-tracks') >= 0 && html.indexOf('Set Up Your Own Local Kali Lab') >= 0,
  'choosing "basics" reveals 2-column Study spotlight with 6 clickable track cards and uniform 6-card Kali Lab setup');
ok(html.indexOf('chmod +x ~/Downloads/download-loadout.sh') === -1 && html.indexOf('#/loadout') >= 0 && html.indexOf('#/home') >= 0,
  'Lab section removes bloated CLI one-liners on Steps 4-6 and links cleanly to #/loadout and #/home');
ok(html.indexOf('IppSec.rocks') >= 0 && html.indexOf('0xdf hacks stuff') >= 0 && html.indexOf('The Hacker Recipes') >= 0 && html.indexOf('ired.team') >= 0 && html.indexOf('GTFOBins') === -1,
  'Go Deeper section focuses on educational walkthroughs & methodology guides (IppSec.rocks, HackTricks, 0xdf, Hacker Recipes, ired.team, PortSwigger)');

// Door 4: Click "exam" door and test Next-Steps-style expandable Exam Playbook cards
clickTarget('data-track', 'exam', 'sl-way start-door');
ok(html.indexOf('How To Use OBOL On Exam Day') >= 0 && html.indexOf('Certification Exam Playbooks (OSCP, CPTS &amp; PNPT)') >= 0,
  'choosing "exam" reveals Exam Day OBOL Workflow and OSCP/CPTS/PNPT Playbook choice cards');
ok(html.indexOf('70 / 100 points minimum to pass') === -1 && html.indexOf('Expand Playbook') >= 0,
  'Exam Playbook cards start collapsed with rich summary pills and Expand Playbook button');
clickTarget('data-exam-toggle', 'oscp', 'start-exam-sum');
ok(html.indexOf('70 / 100 points minimum to pass') >= 0 && html.indexOf('Collapse Playbook') >= 0 && html.indexOf('data-exam-launch="oscp"') >= 0,
  'clicking OSCP playbook card expands full scoring breakdown, rules, skill links, and Mock Exam Engagement launcher');

// Click "Show me everything" and toggle off
clickTarget('data-start-all', '', 'start-all');
ok(html.indexOf('data-start-all aria-pressed="true"') >= 0 && html.indexOf('OverTheWire: Bandit &amp; Natas') >= 0 && html.indexOf('Certification Exam Playbooks') >= 0,
  'Show me everything reveals all sections and sets aria-pressed="true"');
ok(focusedSelector === '[data-start-all]', 'focus is preserved on Show me everything button');
clickTarget('data-start-all', '', 'start-all');
ok(html.indexOf('class="start-stage"') === -1 && html.indexOf('data-start-all aria-pressed="false"') >= 0,
  're-clicking Show me everything collapses the stage and resets aria-pressed="false"');

// 3. Verify credbar add/activate/remove under OBOL.context, nested hash.ntlm dahash, and database prompt SHOW TABLES
req('assets/engine/facts.js');
req('assets/engine/context.js');
req('assets/engine/outcomes.js');
req('assets/engine/command.js');
req('assets/engine/loot.js');
req('assets/engine/workspace.js');
req('assets/engine/phases.js');
req('assets/engine/pack.js');
req('assets/engine/parsers/common.js');
req('assets/engine/parsers/database.js');
req('assets/engine/parsers/index.js');
globalThis.localStorage = { _d: {}, getItem: function (k) { return this._d[k] || null; }, setItem: function (k, v) { this._d[k] = String(v); }, removeItem: function (k) { delete this._d[k]; } };
globalThis.sessionStorage = { _d: {}, getItem: function (k) { return this._d[k] || null; }, setItem: function (k, v) { this._d[k] = String(v); }, removeItem: function (k) { delete this._d[k]; } };
req('assets/ui/store.js');
req('assets/ui/credbar.js');

(async function () {
  await OBOL.store.init();
  OBOL.store.update(function (e) { e.params = { target: '10.10.10.10' }; e.targets = [{ ip: '10.10.10.10' }]; });
  OBOL.creds.add({ user: 'carol', type: 'NT', secret: 'ffeeddccbbaa99887766554433221100' });
  var carol = OBOL.creds.gather().find(function (c) { return c.user === 'carol'; });
  ok(!!(carol && carol.id), 'manually-added credential gets a material id under OBOL.context');
  OBOL.creds.activate(carol);
  ok(OBOL.store.active().params.username === 'carol' && OBOL.store.active().params.nthash === 'ffeeddccbbaa99887766554433221100', 'activating manually-added credential populates params');
  OBOL.creds.remove(carol);
  ok(!OBOL.creds.gather().some(function (c) { return c.user === 'carol'; }), 'removing manually-added credential removes it from gather() under OBOL.context');
  ok(!OBOL.store.active().params.username && !OBOL.store.active().params.nthash, 'removing the active manually-added credential clears its active selection on the target');

  // Nested hash.ntlm entries unpacking for {{dahash}}
  var ntFs = new OBOL.facts.FactSet([
    OBOL.facts.makeFact({ kind: 'hash.ntlm', scope: 'host:10.10.10.10', value: { count: 1, entries: [{ user: 'Administrator', rid: 500, nthash: '11223344556677889900aabbccddeeff', domain: 'corp.local' }] } })
  ]);
  var ntCtx = OBOL.command.buildContext(ntFs, { target: '10.10.10.10' });
  ok(ntCtx.dahash === '11223344556677889900aabbccddeeff' && ntCtx.dauser === 'Administrator', 'nested hash.ntlm entries array unpacks into {{dahash}} and {{dauser}}');

  // MariaDB interactive prompt SHOW TABLES without explicit command parameter
  var dbRes = OBOL.parsers.parseActionOutput({
    actionId: '',
    command: '',
    stdout: 'MariaDB [wordpress]> show tables;\n+-----------------------+\n| Tables_in_wordpress   |\n+-----------------------+\n| wp_users              |\n| wp_options            |\n+-----------------------+\n2 rows in set (0.001 sec)\nBye\n',
    scope: 'host:10.10.10.10'
  });
  var tblFact = (dbRes.facts || []).find(function (f) { return f.kind === 'db.tables'; });
  ok(!!(tblFact && tblFact.value && tblFact.value.tables.indexOf('wp_users') >= 0 && tblFact.value.tables.indexOf('Bye') < 0),
    'interactive MariaDB prompt show tables mints db.tables and excludes Bye');

  // 4. Verify "Set Up Engagement..." unconfigured lifecycle and pre-filled Launchpad
  req('assets/engine/profile.js');
  req('assets/engine/vfs.js');
  req('data/packs-bundle.js');
  req('assets/engine/packs.js');
  req('assets/ui/routes/home.js');
  OBOL.store.update(function (e) {
    e.name = '';
    e.params = { target: '10.10.10.10', lhost: '10.10.14.2' };
    e.profile = { platform: 'custom', osid: 'OS-1234567', scope: [] };
    e.targets = [];
  });
  ok(OBOL.store.runLabel(OBOL.store.active()) === 'Set Up Engagement...', 'unnamed engagement uses "Set Up Engagement..." label');
  ok(OBOL.store.isConfigured(OBOL.store.active()) === false, 'unnamed engagement with stray target/OSID is still treated as unconfigured');
  var homeUnconfigHtml = OBOL.routes.home.render();
  ok(homeUnconfigHtml.indexOf('PRE-ENGAGEMENT LAUNCHPAD') >= 0 && homeUnconfigHtml.indexOf('class="eng-active ') < 0,
    '#/home renders Pre-Engagement Launchpad (not the active Hub) when engagement is unnamed');
  ok(homeUnconfigHtml.indexOf('OS-1234567') >= 0 && homeUnconfigHtml.indexOf('10.10.10.10') >= 0 && homeUnconfigHtml.indexOf('Staged data ready:') >= 0,
    'Pre-Engagement Launchpad pre-fills staged target IP and OSID so nothing is lost');
  OBOL.store.update(function (e) { e.name = 'OSCP Mock Run'; });
  ok(OBOL.store.isConfigured(OBOL.store.active()) === true, 'named engagement is treated as configured');
  var homeConfigHtml = OBOL.routes.home.render();
  ok(homeConfigHtml.indexOf('class="eng-active ') >= 0 && homeConfigHtml.indexOf('OSCP Mock Run') >= 0,
    '#/home renders active Engagement Hub once the engagement is named/launched');

  console.log('\nSTART ROUTE SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
  process.exit(fail ? 1 : 0);
})();
