/* Library engine (OBOL.library): the pure catalogue behind the Library tab. Verifies lanes derive from
 * the pack load order, facets index every axis (lane/phase/port/service/tool/os/kind), filter is OR
 * within a group and AND across groups plus free-text, the command catalogue dedupes to the distinct
 * template with back-links to every move, nxc capabilities split by protocol, and the ATT&CK technique
 * library maps technique -> moves with real names/tactics. Pure, no store, no DOM. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/profile.js');
require('../../assets/engine/command.js');
require('../../assets/engine/workspace.js');
require('../../data/parser-signatures.js');
require('../../data/attack-catalog.js');
require('../../data/attack-move-map.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, PK = OBOL.pack;

// Load packs in the real build order so lane derivation (load order) matches the app.
const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const ORDER = ['ad', 'web', 'recon', 'linux_privesc', 'windows_privesc', 'obol_local_pivot', 'obol_flag_hunt',
  'findings_checks', 'credential_access', 'web_exploit_checks', 'database', 'cracking', 'pivoting', 'shells'].map((x) => x + '_2026_09');
OBOL.packData = {}; OBOL.ACTION_PACKS = [];
const datas = [];
ORDER.forEach((pk) => {
  const fp = path.join(pdir, pk + '.json');
  if (fs.existsSync(fp)) { const j = JSON.parse(fs.readFileSync(fp, 'utf8')); OBOL.packData[pk] = j; OBOL.ACTION_PACKS.push(pk); datas.push(j); }
});
const PACK = PK.loadPacks(datas);
require('../../assets/engine/library.js');
const L = OBOL.library;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

// ── lanes ────────────────────────────────────────────────────────────────────────────────────────
const lanes = L.lanes();
ok(lanes.length >= 10, 'lanes derived from packs (' + lanes.length + ')');
ok(lanes[0].key === 'ad_2026_09' && lanes[0].label === 'Active Directory', 'first lane is AD (load order), labelled for humans');
ok(L.laneOf('asrep-roast') === 'ad_2026_09', 'laneOf maps a move to its pack');
ok(lanes.every((l) => l.hue && typeof l.hue === 'string'), 'every lane carries a hue key');

// ── facets ───────────────────────────────────────────────────────────────────────────────────────
const facets = L.facets(PACK);
const groups = facets.map((f) => f.group);
['lane', 'phase', 'service', 'port', 'tool', 'os', 'tag'].forEach((g) => ok(groups.indexOf(g) >= 0, 'facet group present: ' + g));
const laneF = facets.find((f) => f.group === 'lane');
ok(laneF.values.reduce((s, v) => s + v.count, 0) >= PACK.length, 'every move is counted under some lane');
const phaseF = facets.find((f) => f.group === 'phase');
ok(phaseF.values[0].key === 'recon', 'phase facet is in recon->loot order');
const serviceF = facets.find((f) => f.group === 'service');
ok(serviceF.values.some((v) => v.key === 'http'), 'service facet includes http');
const portF = facets.find((f) => f.group === 'port');
ok(portF.values.every((v, i, a) => i === 0 || (+a[i - 1].key) <= (+v.key)), 'port facet is numeric-sorted');

// ── filter: OR within group, AND across groups, + search ─────────────────────────────────────────
const adMoves = L.filter(PACK, { lane: ['ad_2026_09'] }, '');
ok(adMoves.length > 0 && adMoves.every((a) => L.laneOf(a.id) === 'ad_2026_09'), 'filter by one lane returns only that lane');
const adCreds = L.filter(PACK, { lane: ['ad_2026_09'], phase: ['creds'] }, '');
ok(adCreds.length > 0 && adCreds.length < adMoves.length, 'AND across groups narrows (AD + creds < AD alone)');
const twoLanes = L.filter(PACK, { lane: ['ad_2026_09', 'web_2026_09'] }, '');
ok(twoLanes.length > adMoves.length, 'OR within a group widens (AD + Web > AD alone)');
const searched = L.filter(PACK, {}, 'kerberoast');
ok(searched.length > 0 && searched.some((a) => /roast/i.test(a.id + a.title)), 'free-text search matches id/title');

// ── command catalogue (hero): dedupe-to-template + back-links ────────────────────────────────────
const cat = L.commandCatalog(PACK);
ok(cat.length > 400, 'command catalogue has the full lineup (' + cat.length + ' distinct templates)');
ok(cat.every((e) => e.template && e.tool && e.capability && Array.isArray(e.moves) && e.moves.length), 'every catalogue entry has a template, tool, capability, and at least one back-linked move');
const dupTemplates = cat.map((e) => e.template);
ok(new Set(dupTemplates).size === dupTemplates.length, 'templates are deduped (one entry per distinct command)');
const reused = cat.filter((e) => e.moves.length > 1);
ok(reused.length > 0, 'a command shared by multiple moves back-links to all of them (' + reused.length + ' shared)');

// ── grouped by tool -> capability (nxc split by protocol), and by phase / lane ───────────────────
const grouped = L.commandsGrouped(PACK, '', 'tool');
ok(grouped.length > 0 && grouped[0].count >= grouped[grouped.length - 1].count, 'by tool: groups sorted by command count desc');
ok(grouped.every((g) => g.key && g.label && Array.isArray(g.subs)), 'grouped shape is uniform {key,label,count,subs}');
const nxc = grouped.find((g) => g.key === 'nxc');
ok(nxc && nxc.subs.some((c) => c.label === 'nxc smb') && nxc.subs.some((c) => c.label === 'nxc ldap'), 'nxc is sub-grouped by protocol (smb, ldap, ...)');
const impacket = grouped.find((g) => g.key === 'impacket');
ok(impacket && impacket.subs.some((c) => /secretsdump|getnpusers|getuserspns/.test(c.label)), 'impacket capability is the script name');
// group by phase (recon -> loot order, hue carried) and by lane (load order)
const byPhase = L.commandsGrouped(PACK, '', 'phase');
ok(byPhase[0].key === 'recon' && byPhase.every((g) => g.hue), 'by phase: recon leads and every group carries a hue');
const byLane = L.commandsGrouped(PACK, '', 'lane');
ok(byLane[0].key === 'ad_2026_09' && byLane.every((g) => g.hue && g.label), 'by lane: AD leads (load order), labelled, hued');
const byOutcome = L.commandsGrouped(PACK, '', 'outcome');
ok(byOutcome.length >= 4 && byOutcome.every((g) => g.label && g.hue !== undefined), 'by outcome: groups present and labelled (' + byOutcome.map((g) => g.key).join(', ') + ')');
ok(byOutcome[0].key === 'discover', 'by outcome: Discover leads (lowest rank first)');
const creds = byOutcome.find((g) => g.key === 'creds');
ok(creds && creds.subs.some((s) => /hashcat|john|secretsdump|nxc/.test(s.label)), 'by outcome: Harvest Credentials holds the cracking/dumping tools');
// search narrows every axis
const g2 = L.commandsGrouped(PACK, 'evil-winrm', 'tool');
ok(g2.length && g2.every((t) => t.subs.every((c) => c.cmds.every((e) => /evil-winrm/i.test(e.template + ' ' + e.moves.map((m) => m.title).join(' '))))), 'command search filters the grouped view');

// ── ATT&CK technique library ─────────────────────────────────────────────────────────────────────
const techs = L.techniqueLibrary(PACK);
ok(techs.length >= 55, 'technique library maps obol moves to ATT&CK (' + techs.length + ' techniques)');
ok(techs.every((t) => /^T\d{4}/.test(t.id) && t.name && t.name !== t.id), 'every technique has a real ATT&CK id and a resolved name');
ok(techs.every((t) => Array.isArray(t.moves) && t.moves.length && t.moves.every((m) => m.id && m.title && m.lane)), 'every technique back-links to moves with lane + title');
ok(techs.some((t) => (t.tactics || []).length), 'techniques carry their tactic ids for colouring');
ok(techs.every((t) => typeof t.cmdCount === 'number'), 'every technique carries a command count');
ok(L.tactics().length >= 14, 'tactic list available for the matrix (' + L.tactics().length + ')');
// the union with byKind(produces) must reach moves that carry NO explicit byMove tag
const movesMapped = techs.reduce((s, t) => s + t.moves.length, 0);
ok(movesMapped > 200, 'byKind-over-produces lights far more than the ~109 byMove-tagged moves (' + movesMapped + ' move links)');
const t1482 = techs.find((t) => t.id === 'T1482');  // Domain Trust Discovery, reached only via ad.trusts
ok(t1482 && t1482.moves.some((m) => m.id === 'trust-enum'), 'a move tagged only through its produced fact (trust-enum -> T1482) is mapped');

// ── fill reuses the one filler ───────────────────────────────────────────────────────────────────
const fs2 = new OBOL.facts.FactSet([]);
const filledTok = L.fill('nxc smb {{target}} -u {{user}}', fs2, {});
ok(/\{\{target\}\}/.test(filledTok) || /target/.test(filledTok), 'fill leaves tokens when no facts/params');
const filledVal = L.fill('nxc smb {{target}}', fs2, { target: '10.10.10.5' });
ok(/10\.10\.10\.5/.test(filledVal), 'fill substitutes a known param (reuses OBOL.command.fillCommand)');

// house style: no em/en dashes in any human label the engine emits
const labels = [].concat(lanes.map((l) => l.label), facets.map((f) => f.label), techs.map((t) => t.name));
ok(labels.every((s) => !/[–—]/.test(String(s))), 'no em/en dashes in engine-emitted labels');

if (fail) { console.error('\nlibrary-smoke: ' + fail + ' FAILED'); process.exit(1); }
console.log('\nlibrary-smoke: all passed');
