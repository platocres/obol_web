/* Node coverage test for the Help content (data/help-content.js).
 *
 * Asserts the Help index cannot drift from the app: every real nav surface (the global sections and the
 * engagement sub-nav items) has a Help entry, the Workbench tools and Findings sub-views are all
 * covered, the glossary and quick-start are populated, and no authored string uses an em or en dash.
 * Run: node tests/engine/help-coverage.js
 */
'use strict';
require('../../data/help-content.js');
var OBOL = globalThis.OBOL, H = OBOL.HELP;

var fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

ok(H && Array.isArray(H.sections) && H.sections.length, 'OBOL.HELP.sections present');

// collect every id anywhere in the section tree
var ids = {};
(function walk(list) {
  (list || []).forEach(function (s) {
    if (s.id) ids[s.id] = 1;
    (s.groups || []).forEach(function (g) { walk(g.subs); });
    walk(s.subs);
  });
})(H.sections);

// the real nav surfaces that MUST have an entry (global nav + ctxbar SUBNAV + header actions)
var REQUIRED = [
  'study', 'loadout', 'engagements', 'tools', 'workbench', 'library', 'cruise',  // global nav
  'home', 'targets', 'path', 'evidence',                                           // Work the Box
  'map', 'domain', 'creds',                                                         // Analyze
  'checklist', 'findings', 'history', 'scoreboard', 'report',                       // Track & Report
  'paste', 'search',                                                               // header actions
];
REQUIRED.forEach(function (r) { ok(ids[r], 'surface "' + r + '" has a Help entry'); });

// Workbench tools (the live TABS ids, prefixed wb- in Help)
['revshell', 'hashid', 'encoder', 'decoder', 'jwt', 'gtfobins', 'wordlists', 'sqli', 'explain', 'spray']
  .forEach(function (t) { ok(ids['wb-' + t], 'Workbench tool "' + t + '" has a Help entry'); });

// Findings sub-views
['findings-list', 'findings-attack', 'findings-defensive', 'findings-compliance', 'findings-cves']
  .forEach(function (v) { ok(ids[v], 'Findings sub-view "' + v + '" has a Help entry'); });

// every section carries What, When, Tip, and href; glossary + quickstart populated
ok(H.sections.every(function (s) { return s.what && s.when && s.tip && (s.href || s.goto); }), 'every top section has what, when, tip, and href');
ok(Array.isArray(H.glossary) && H.glossary.length >= 20 && H.glossary.every(function (g) { return g.term && g.def; }), 'glossary populated with 20+ terms (term + def)');

// verify required OSCP / Obol methodology glossary terms
var REQUIRED_TERMS = [
  'Access Epoch', 'Blocker / Field Doctor', 'Cruise Batch', 'Earned Token',
  'Frontier', 'Goal Distance', 'Keystone Move', 'Locus (Remote / On-Host)',
  'Proof Discipline', 'Settled Command', 'Speculative Move', 'Station'
];
var glossaryTerms = {}; H.glossary.forEach(function (g) { glossaryTerms[g.term] = 1; });
REQUIRED_TERMS.forEach(function (t) { ok(glossaryTerms[t], 'glossary includes term "' + t + '"'); });

// quick-start 4 steps
ok(Array.isArray(H.quickstart) && H.quickstart.length === 4 && H.quickstart.every(function (q) { return q.goto && q.cta; }), 'quick-start steps populated (4 steps with target + CTA)');
var expectedSteps = ['Set Your Loadout', 'Create An Engagement & Target', 'Run & Paste Your First Scan', 'Follow Next Steps To Proof'];
expectedSteps.forEach(function (title, i) {
  ok(H.quickstart[i] && H.quickstart[i].title === title, 'quick-start step ' + (i + 1) + ' is "' + title + '"');
});
ok(typeof H.charonIntro === 'string' && /Charon/.test(H.charonIntro), 'Charon intro present');

// house style: no em or en dashes anywhere in the authored content
var dashHits = [];
(function scan(v, path) {
  if (typeof v === 'string') { if (/[–—]/.test(v)) dashHits.push(path); }
  else if (v && typeof v === 'object') { Object.keys(v).forEach(function (k) { scan(v[k], path + '.' + k); }); }
})(H, 'HELP');
ok(dashHits.length === 0, 'no em or en dashes in Help content' + (dashHits.length ? ' (' + dashHits.join(', ') + ')' : ''));

console.log(fail ? ('\nHELP COVERAGE: ' + fail + ' FAILURES') : '\nHELP COVERAGE: all passed');
process.exit(fail ? 1 : 0);
