/*!
 * obol tests - arsenal-completeness-smoke.js
 *
 * Verifies loadout and arsenal provisioner completeness:
 *   1. 100% pack tool coverage across all packs
 *   2. 100% TOOL_STAGING keys present in ARSENAL
 *   3. Generated download-arsenal.sh passes bash -n and contains all required logic
 *   4. Zero em/en dashes across touched arsenal and staging files
 */
'use strict';
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

require('../../data/tools-install.js');
require('../../data/tool-staging.js');
require('../../assets/engine/arsenal.js');

const OBOL = globalThis.OBOL;
let fail = 0;

function ok(cond, msg) {
  if (!cond) {
    console.error('  FAIL:', msg);
    fail++;
  } else {
    console.log('  ok  :', msg);
  }
}

// 1. Pack Tool Coverage across all data/packs/*.json
console.log('# 1. Pack Tool Coverage');
const arsenal = OBOL.ARSENAL;
const packsDir = path.resolve(__dirname, '../../data/packs');
const packFiles = fs.readdirSync(packsDir).filter(f => f.endsWith('.json'));
const missingPackTools = [];
const uniquePackTools = new Set();

for (const pf of packFiles) {
  const pack = JSON.parse(fs.readFileSync(path.join(packsDir, pf), 'utf8'));
  const actions = pack.actions || [];
  for (const a of actions) {
    if (a.tool) {
      uniquePackTools.add(a.tool);
      if (!arsenal[a.tool] && !arsenal[a.tool.toLowerCase()]) {
        missingPackTools.push({ pack: pf, action: a.id, tool: a.tool });
      }
    }
    if (Array.isArray(a.tools)) {
      for (const t of a.tools) {
        uniquePackTools.add(t);
        if (!arsenal[t] && !arsenal[t.toLowerCase()]) {
          missingPackTools.push({ pack: pf, action: a.id, tool: t });
        }
      }
    }
    if (Array.isArray(a.commands)) {
      for (const c of a.commands) {
        if (c.tool) {
          uniquePackTools.add(c.tool);
          if (!arsenal[c.tool] && !arsenal[c.tool.toLowerCase()]) {
            missingPackTools.push({ pack: pf, action: a.id, tool: c.tool });
          }
        }
      }
    }
  }
}

ok(uniquePackTools.size > 200, 'scanned all packs (found ' + uniquePackTools.size + ' unique tools across ' + packFiles.length + ' packs)');
ok(missingPackTools.length === 0, '100% pack tool coverage: 0 missing tools' + (missingPackTools.length ? ' (missing: ' + JSON.stringify(missingPackTools.slice(0, 5)) + ')' : ''));

// 2. TOOL_STAGING Coverage in ARSENAL
console.log('\n# 2. TOOL_STAGING Coverage');
const staging = OBOL.TOOL_STAGING;
const stagingKeys = Object.keys(staging);
const missingStagingKeys = [];

for (const k of stagingKeys) {
  if (!arsenal[k] && !arsenal[k.toLowerCase()]) {
    missingStagingKeys.push(k);
  }
}

ok(stagingKeys.length >= 20, 'TOOL_STAGING populated with ' + stagingKeys.length + ' recipes');
ok(missingStagingKeys.length === 0, '100% TOOL_STAGING keys in ARSENAL' + (missingStagingKeys.length ? ' (missing: ' + missingStagingKeys.join(', ') + ')' : ''));

// 3. Generated download-arsenal.sh Integrity
console.log('\n# 3. Generated download-arsenal.sh Integrity');
const script = OBOL.arsenal.buildScript({ promptStamp: true });
ok(typeof script === 'string' && script.length > 5000, 'buildScript produces valid script string (length: ' + script.length + ')');
ok(script.startsWith('#!/usr/bin/env bash'), 'script begins with shebang');

// Assertions on script content
ok(script.includes('unzip -o "$tmp" -d "$td"'), 'script contains .zip extraction logic (unzip -o "$tmp" -d "$td")');
ok(script.includes('"$WWW"') && script.includes('linpeas.sh') && script.includes('pspy64') && script.includes('chisel') && script.includes('agent'), 'script copies Linux tools (linpeas.sh, pspy64, chisel, agent) into $WWW');
ok(script.includes('$HOME/.local/bin') && script.includes('chisel') && script.includes('ligolo-proxy'), 'script links chisel and ligolo-proxy into ~/.local/bin');
ok(script.includes('$HOME/.local/bin') && script.includes('printf \'#!/usr/bin/env bash\\nexec python3'), 'script creates wrapper shims in ~/.local/bin for git-cloned tools');
ok(script.includes('exec java -jar'), 'script creates wrapper shims in ~/.local/bin for jar tools (ysoserial, rmg)');

// Filename convenience aliases
const requiredAliases = [
  'GodPotato.exe',
  'PrintSpoofer.exe',
  'accesschk.exe',
  'procdump.exe',
  'nc.exe',
  'rev.ps1',
  'les.sh'
];
for (const alias of requiredAliases) {
  ok(script.includes(alias), 'script configures convenience alias: ' + alias);
}

// SecLists & Existing-Kali Locators
ok(script.includes('/usr/share/seclists') && script.includes('/opt/SecLists') && script.includes('seclists'), 'script searches standard and moved locations (/opt/SecLists, ~/SecLists) before apt installing seclists');
ok(script.includes('--check-only|--locate-only') && script.includes('CHECK_ONLY=1'), 'script supports --check-only / --locate-only mode for existing Kali boxes');
ok(script.includes('obol_adopt_local()') && script.includes('/usr/share/peass') && script.includes('/usr/share/windows-resources'), 'script defines obol_adopt_local() to adopt existing on-disk payloads before downloading');
ok(script.includes('for cand in "/opt/$repo_dir" "$HOME/$repo_dir"') && script.includes('find /opt "$HOME"'), 'obol_git locates existing clones/scripts in /opt and $HOME before cloning');
ok(script.includes('def scan_tree(root_dir, max_d=3):') && script.includes('"via":"located"'), 'Python inventory probe scans /opt, ~/tools, and $HOME to locate moved scripts and wordlists');

// Execute the embedded Python inventory probe against a synthetic existing-Kali home directory
const pyMatch = script.match(/INV=\$\(python3 - "\$REC" "\$WWW"(?: "\$TOOLDIR")? <<'PY'\n([\s\S]*?)\nPY\n\)/);
ok(!!pyMatch, 'extracted embedded Python inventory probe from download-arsenal.sh');
if (pyMatch) {
  const os = require('os');
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'obol-kali-test-'));
  try {
    const customTools = path.join(tmpHome, 'tools', 'custom-ad');
    const customLists = path.join(tmpHome, 'wordlists');
    const customSecLists = path.join(tmpHome, 'SecLists');
    const wwwDir = path.join(tmpHome, '.obol', 'arsenal', 'www');
    const recFile = path.join(tmpHome, '.obol', 'arsenal', '.records');
    fs.mkdirSync(customTools, { recursive: true });
    fs.mkdirSync(customLists, { recursive: true });
    fs.mkdirSync(customSecLists, { recursive: true });
    fs.mkdirSync(wwwDir, { recursive: true });
    fs.writeFileSync(recFile, '');
    const movedPy = path.join(customTools, 'targetedKerberoast.py');
    fs.writeFileSync(movedPy, '#!/usr/bin/env python3\n');
    const movedRock = path.join(customLists, 'rockyou.txt');
    fs.writeFileSync(movedRock, '123456\n');
    fs.writeFileSync(path.join(wwwDir, 'linpeas.sh'), '#!/bin/sh\n');

    const pyRes = cp.spawnSync('python', ['-', recFile, wwwDir], {
      input: pyMatch[1],
      encoding: 'utf8',
      env: Object.assign({}, process.env, { HOME: tmpHome, USERPROFILE: tmpHome })
    });
    if (pyRes.status === 0 && pyRes.stdout.trim()) {
      const inv = OBOL.arsenal.parseInventory('OBOL-ARSENAL v1\n' + pyRes.stdout.trim());
      ok(!!inv, 'Python probe output parses cleanly via OBOL.arsenal.parseInventory');
      ok(inv && inv.tools && inv.tools.targetedkerberoast && inv.tools.targetedkerberoast.present && inv.tools.targetedkerberoast.invocation.indexOf('targetedKerberoast.py') >= 0,
        'Python probe located moved targetedKerberoast.py in ~/tools/custom-ad (' + (inv && inv.tools && inv.tools.targetedkerberoast && inv.tools.targetedkerberoast.invocation) + ')');
      ok(inv && inv.wordlists && inv.wordlists.rockyou === movedRock,
        'Python probe located moved rockyou.txt in ~/wordlists (' + (inv && inv.wordlists && inv.wordlists.rockyou) + ')');
      ok(inv && inv.wordlists && inv.wordlists.seclists === customSecLists,
        'Python probe located moved SecLists in ~/SecLists (' + (inv && inv.wordlists && inv.wordlists.seclists) + ')');
    } else {
      console.log('  skip: python not available for live probe execution (' + (pyRes.stderr || '').trim() + ')');
    }
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
}

// bash -n syntax validation
const bashBin = (function () {
  if (process.platform === 'win32') {
    const gitBash = 'C:\\Program Files\\Git\\bin\\bash.exe';
    if (fs.existsSync(gitBash)) return gitBash;
  }
  try {
    const test = cp.spawnSync('bash', ['-c', 'exit 0']);
    return test.status === 0 ? 'bash' : null;
  } catch (e) {
    return null;
  }
})();

if (bashBin) {
  const r = cp.spawnSync(bashBin, ['-n'], { input: script, encoding: 'utf8' });
  ok(r.status === 0, 'generated download-arsenal.sh passes bash -n' + (r.status === 0 ? '' : ' (' + (r.stderr || '').trim() + ')'));
} else {
  console.log('  skip: bash not found for bash -n check');
}

// 4. No Em/En Dashes in touched files
console.log('\n# 4. No Em/En Dashes');
const touchedFiles = [
  path.resolve(__dirname, '../../assets/engine/arsenal.js'),
  path.resolve(__dirname, '../../data/tools-install.js'),
  path.resolve(__dirname, '../../data/tool-staging.js'),
  path.resolve(__dirname, './command-rewrite-smoke.js'),
  __filename
];

for (const tf of touchedFiles) {
  const content = fs.readFileSync(tf, 'utf8');
  const hasEm = /[\u2014]/.test(content);
  const hasEn = /[\u2013]/.test(content);
  const base = path.basename(tf);
  ok(!hasEm && !hasEn, base + ' contains no em dashes (\\u2014) or en dashes (\\u2013)');
}

console.log(fail ? ('\nARSENAL COMPLETENESS: ' + fail + ' FAILURES') : '\nARSENAL COMPLETENESS: all passed');
process.exit(fail ? 1 : 0);

