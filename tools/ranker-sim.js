/*!
 * tools/ranker-sim.js, the ranking simulator / scoreboard.
 *
 * Generates many box states (archetype x progression stage), runs the REAL coach ranker over each,
 * and judges the top moves against a rubric of operator-methodology principles. Prints a scoreboard of
 * violations (by principle, with example states) so ranker tuning is measured, not vibes. Read-only:
 * it never changes the ranker. A later pass A/B-tests candidate rules against this same scoreboard.
 *
 * Run: node tools/ranker-sim.js            (summary)
 *      node tools/ranker-sim.js --verbose  (every violation)
 */
'use strict';
var fs = require('fs'), path = require('path');
require('../assets/engine/facts.js');
require('../assets/engine/phases.js');
require('../assets/engine/pack.js');
require('../assets/engine/profile.js');
require('../assets/engine/command.js');
require('../assets/engine/workspace.js');
require('../data/parser-signatures.js');
require('../data/stuck-catalog.js');
require('../assets/engine/stuck.js');
var OBOL = globalThis.OBOL, PK = OBOL.pack, F = OBOL.facts, S = OBOL.stuck;

var pdir = path.join(__dirname, '..', 'data', 'packs');
var PACK = PK.loadPacks(fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); })
  .map(function (f) { try { return JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) { return {}; } }));
var VERBOSE = process.argv.indexOf('--verbose') >= 0;
var byId = {}; PACK.forEach(function (a) { byId[a.id] = a; });

// ── archetypes: realistic port sets + the facts a scan would mint ──────────────────────────────
var ARCHETYPES = {
  ad_dc:        { os: 'windows', ad: true, ports: [53, 88, 135, 139, 389, 445, 464, 636, 3268, 5985, 9389], facts: ['smb.reachable', 'ldap.reachable', 'kerberos.reachable', 'winrm.reachable'] },
  ad_dc_noisy:  { os: 'windows', ad: true, ports: [21, 22, 53, 88, 135, 139, 389, 445, 636, 3268, 5985], facts: ['ftp.reachable', 'ssh.reachable', 'smb.reachable', 'ldap.reachable', 'kerberos.reachable', 'winrm.reachable'] },
  ad_member:    { os: 'windows', ad: true, ports: [135, 139, 445, 3389, 5985], facts: ['smb.reachable', 'rdp.reachable', 'winrm.reachable'] },
  linux_web:    { os: 'linux', ad: false, ports: [22, 80, 443], facts: ['ssh.reachable', 'http.reachable'] },
  linux_web_db: { os: 'linux', ad: false, ports: [22, 80, 3306], facts: ['ssh.reachable', 'http.reachable', 'service.mysql'] },
  windows_web:  { os: 'windows', ad: false, ports: [80, 443, 445, 3389], facts: ['http.reachable', 'smb.reachable', 'rdp.reachable'] },
  linux_std:    { os: 'linux', ad: false, ports: [21, 22, 80], facts: ['ftp.reachable', 'ssh.reachable', 'http.reachable'] },
};

// ── progression stages: cumulative facts layered onto an archetype ─────────────────────────────
// Each stage returns the EXTRA facts to add (beyond host.up + the archetype's ports/facts).
function stageFacts(arch, stage) {
  var f = [];
  if (stage === 'recon_ports') return f;
  f.push('scan.nmap.version'); if (stage === 'recon_versioned') return f;
  // a foothold
  f.push('access.shell', arch.os === 'windows' ? 'foothold.windows' : 'foothold.linux');
  if (stage === 'foothold') return f;
  if (stage === 'cred_found') { f.push('credential.available'); return f; }
  if (stage === 'cred_valid') { f.push('credential.available', 'credential.validated'); return f; }
  if (stage === 'admin') { f.push('access.admin'); return f; }
  return f;
}
var STAGES = ['recon_ports', 'recon_versioned', 'foothold', 'cred_found', 'cred_valid', 'admin'];

function buildState(archKey, stage) {
  var arch = ARCHETYPES[archKey];
  var sb = S.sandbox();
  S.assert(sb, 'host.up', { scope: 'host:t' });
  arch.ports.forEach(function (p) { S.togglePort(sb, p, 'host:t'); });
  arch.facts.forEach(function (k) { S.assert(sb, k, { scope: 'host:t' }); });
  stageFacts(arch, stage).forEach(function (k) { S.assert(sb, k, { scope: 'host:t' }); });
  return { sb: sb, arch: arch, archKey: archKey, stage: stage };
}

// ── move classification (for the rubric) ───────────────────────────────────────────────────────
function isBrute(m) { return /brute|hydra|\bspray\b|password.?guess/i.test((m.id || '') + ' ' + (m.title || '')); }
function isVersionCve(m) { return /CVE-\d{4}/i.test(m.title || '') || /_enumusers|enum-?users|cve/i.test(m.id || ''); }
function isAdMove(m) { return /^ad-/.test(m.id || '') || /kerber|ldap|bloodhound|roast|domain controller|null session|smb anon|rid.?brute/i.test((m.id || '') + ' ' + (m.title || '')); }
function isScanMove(m) { return /scan|nmap|service.?scan|version/i.test((m.id || '') + ' ' + (m.title || '')); }
function phaseOf(m) { return OBOL.phases.phaseOfAction(m) || ''; }
function hasVersionOrVuln(sb) { return sb.has('scan.nmap.version') || sb.has('scan.nmap.vuln'); }
function hasUserlist(sb) { return sb.has('ad.user_list') || sb.has('web.users'); }
function hasFoothold(sb) { return sb.has('access.shell') || sb.has('foothold.linux') || sb.has('foothold.windows') || sb.has('foothold.webshell'); }
function hasDomainAccess(sb) { return sb.has('credential.validated') || sb.has('access.admin') || sb.has('access.system') || sb.has('loot.ntds'); }

// ── the rubric: each check inspects the ranked list and returns violations ─────────────────────
// A violation is { principle, detail }. Checks look at the top N moves.
function judge(state, ranked) {
  var sb = state.sb, v = [], topN = ranked.slice(0, 5), top3 = ranked.slice(0, 3), top1 = ranked[0];

  // P2: no last-resort brute in the top 3 without a userlist
  top3.forEach(function (m) { if (isBrute(m) && !hasUserlist(sb)) v.push({ p: 'no_brute_in_lead', detail: m.id + ' (brute) in top 3 with no userlist' }); });

  // P3: no unguarded version-specific CVE as #1 when the version is unknown
  if (top1 && isVersionCve(top1) && !hasVersionOrVuln(sb)) v.push({ p: 'no_unguarded_cve_lead', detail: top1.id + ' leads but no version/vuln known' });

  // P4: no premature loot in the top 3. A move that claims a CREDENTIAL or a domain secret
  // (gpp/ntds/secretsdump) while requiring no credential, foothold, or validated access is under-gated,
  // it is surfacing loot you have not earned. Anonymous enum (listing readable shares) is NOT flagged.
  top3.forEach(function (m) {
    var claimsSecret = (m.produces || []).some(function (k) { return /^credential\.|^loot\.ntds|^hash\.(krbtgt|ntlm)/.test(k); });
    if (!claimsSecret || phaseOf(m) !== 'loot') return;
    // You have a basis for the loot if you hold a credential/foothold/admin, OR a proven anonymous
    // session (null/guest share read is legitimate early loot), OR the move exploits a CONFIRMED vuln
    // (exploiting web.*_confirmed to get creds is not premature, it is the point).
    var hasAccess = sb.has('credential.available') || hasFoothold(sb) || hasDomainAccess(sb) || sb.has('smb.null_session') || sb.has('smb.guest_session');
    var exploitsConfirmedVuln = (m.requires_all || []).concat(m.requires_any || []).some(function (k) { return /_confirmed$/.test(k); });
    if (!hasAccess && !exploitsConfirmedVuln) v.push({ p: 'no_premature_loot', detail: m.id + ' claims a credential/secret in top 3 with no access basis' });
  });

  // P5a: no LOCAL privesc lead before a foothold (a move producing a privesc.* lead). Web exploitation
  // that happens to be phase 'escalate' is excluded, it is pre-foothold by design.
  top3.forEach(function (m) { if ((m.produces || []).some(function (k) { return /^privesc\./.test(k); }) && !hasFoothold(sb)) v.push({ p: 'privesc_before_foothold', detail: m.id + ' (local privesc) in top 3 with no foothold' }); });

  // P5b: validate a found-but-unvalidated credential before leaning on it
  if (sb.has('credential.available') && !sb.has('credential.validated')) {
    var hasValidate = topN.some(function (m) { return (m.produces || []).indexOf('credential.validated') >= 0 || m.id === 'validate-credential'; });
    if (!hasValidate) v.push({ p: 'validate_first', detail: 'found credential, but no validate move in top 5' });
  }

  // P1: AD lane leads on an AD box at recon. The AD orient line (confirm DC/domain, anon LDAP, enum)
  // should be in the top 3; a box with LDAP/SMB/Kerberos open should not bury it under FTP/SSH/DNS/web
  // single-service recon. A scan/orient move leading is fine.
  if (state.arch.ad && (state.stage === 'recon_ports' || state.stage === 'recon_versioned')) {
    var adInTop3 = top3.some(function (m) { return isAdMove(m); });
    // Only a violation when AD is buried under pure RECON NOISE (scans, single-service ftp/ssh/dns enum).
    // A high-value service lead (a database or web login/exploitation) ahead of AD is a legitimate choice,
    // not noise, so it does not count as burying the AD line.
    var strongNonAd = top3.some(function (m) { return /login|sqli|sql-inj|sqlmap|redis|mongo|elastic|web-|http-|jwt|upload/i.test((m.id || '') + ' ' + (m.title || '')) || (m.produces || []).some(function (k) { return /^db\.|^foothold\.webshell|_confirmed/.test(k); }); });
    if (!adInTop3 && !isScanMove(top1) && !strongNonAd) v.push({ p: 'ad_lane_leads', detail: 'AD orient buried under recon noise (top: ' + top3.map(function (m) { return m.id; }).join(', ') + ')' });
  }

  // P6: command sanity, the #1 move's first command should not sit on an EARNED token whose backing
  // fact is absent. (user/password/nthash are excluded: they fill from the selected credential, which
  // exists whenever credential.available does, so a leftover there is a sim artifact, not a ranker bug.)
  if (top1) {
    try {
      var filled = OBOL.command.fillAll(top1, sb, { params: { target: '10.10.10.5' } });
      var cmd = (filled[0] && filled[0].filled) || '';
      var needs = [
        { tok: 'domain', ok: sb.has('ad.domain_known') || sb.has('host.domain') },
        { tok: 'basedn', ok: sb.has('ad.base_dn') },
        { tok: 'userlist', ok: hasUserlist(sb) },
        { tok: 'hashfile', ok: sb.has('hash.ntlm') || sb.has('hash.asrep') || sb.has('hash.tgs') },
        { tok: 'krbtgt_hash', ok: sb.has('hash.krbtgt') },
      ];
      needs.forEach(function (n) {
        if (!n.ok && new RegExp('\\{\\{' + n.tok + '\\}\\}').test(cmd)) v.push({ p: 'command_sanity', detail: '#1 ' + top1.id + ' command needs {{' + n.tok + '}} you do not have yet' });
      });
    } catch (e) {}
  }
  return v;
}

// Exported so the broad sweep (tools/ranker-sweep.js) reuses this exact rubric + engine, no drift.
module.exports = {
  OBOL: OBOL, PK: PK, S: S, F: F, PACK: PACK, ARCHETYPES: ARCHETYPES, STAGES: STAGES,
  buildState: buildState, stageFacts: stageFacts, judge: judge,
  isBrute: isBrute, isVersionCve: isVersionCve, isAdMove: isAdMove, isScanMove: isScanMove, phaseOf: phaseOf,
};
if (require.main !== module) return;

// ── run the simulation ─────────────────────────────────────────────────────────────────────────
var states = [], tally = {}, total = 0, dirty = 0;
Object.keys(ARCHETYPES).forEach(function (ak) { STAGES.forEach(function (st) { states.push(buildState(ak, st)); }); });

var rows = [];
states.forEach(function (state) {
  var ranked = PK.rankActions(state.sb, PACK);
  var vios = judge(state, ranked);
  total++;
  if (vios.length) dirty++;
  vios.forEach(function (x) { tally[x.p] = (tally[x.p] || 0) + 1; });
  rows.push({ state: state.archKey + '/' + state.stage, top: ranked.slice(0, 5).map(function (m) { return m.id; }), vios: vios });
});

console.log('RANKING SIMULATION  (' + total + ' states: ' + Object.keys(ARCHETYPES).length + ' archetypes x ' + STAGES.length + ' stages)');
console.log('states with >=1 violation: ' + dirty + ' / ' + total + '\n');
console.log('VIOLATIONS BY PRINCIPLE');
Object.keys(tally).sort(function (a, b) { return tally[b] - tally[a]; }).forEach(function (p) {
  console.log('  ' + String(tally[p]).padStart(3) + '  ' + p);
});
if (!Object.keys(tally).length) console.log('  (none)');

if (VERBOSE) {
  console.log('\nPER-STATE');
  rows.forEach(function (r) {
    console.log('\n' + r.state + '  top: ' + r.top.join(' > '));
    r.vios.forEach(function (x) { console.log('    ! ' + x.p + ': ' + x.detail); });
  });
} else {
  console.log('\nWORST STATES (most violations)');
  rows.filter(function (r) { return r.vios.length; }).sort(function (a, b) { return b.vios.length - a.vios.length; }).slice(0, 10).forEach(function (r) {
    console.log('  ' + r.state.padEnd(24) + ' [' + r.vios.length + ']  ' + r.vios.map(function (x) { return x.p; }).join(', '));
    console.log('      top: ' + r.top.slice(0, 4).join(' > '));
  });
}
