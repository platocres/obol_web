/* Reference resolver (OBOL.resolve) + the GTFOBins bundle. Locks the fact-to-exact-escape loop: the sudo
 * form is the shell code prefixed with sudo, the SUID form prefers the -p variant, path basenames resolve,
 * known-but-not-inlined binaries (inherit cases) still report known with a link, and unknown binaries report
 * not known. Generic data. */
'use strict';
require('../../assets/engine/facts.js');
require('../../data/gtfobins.js');
require('../../assets/engine/resolve.js');
const OBOL = globalThis.OBOL, R = OBOL.resolve;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }

ok(Object.keys(OBOL.GTFOBINS).length > 300, 'gtfobins bundle has the binaries (' + Object.keys(OBOL.GTFOBINS).length + ')');
ok((OBOL.GTFOBINS_ALL || []).length > 400, 'gtfobins name list is present (' + (OBOL.GTFOBINS_ALL || []).length + ')');

// sudo form: shell code prefixed with sudo
const findSudo = R.gtfoEscape('find', 'sudo');
ok(findSudo && findSudo.command.indexOf('sudo find') === 0, 'find sudo escape starts with "sudo find"');
// suid form: prefers the -p variant
const findSuid = R.gtfoEscape('find', 'suid');
ok(findSuid && /-p\b/.test(findSuid.command) && findSuid.command.indexOf('sudo ') !== 0, 'find suid escape uses the -p variant, no sudo prefix');
// path basename resolves
ok(R.gtfoEscape('/usr/bin/awk', 'sudo') && R.gtfoEscape('/usr/bin/awk', 'sudo').command.indexOf('sudo ') === 0, 'a full path resolves by basename');

// known-but-inherit: a command we cannot inline still reports known with a link
const vim = R.gtfoLookup('vim', 'sudo');
ok(vim.known === true, 'vim is known to GTFOBins');
ok(vim.command === null, 'vim escape is not inlined (inherit), link-only');
ok(/gtfobins\.github\.io\/gtfobins\/vim\//.test(vim.url), 'vim lookup carries the deep link');

// unknown binary
ok(R.gtfoLookup('definitely-not-a-binary', 'sudo').known === false, 'an unknown binary reports not known');

// fact-driven, per move
const fs = new OBOL.facts.FactSet();
fs.add(OBOL.facts.makeFact({ kind: 'privesc.sudo_binary', scope: 'host:1', value: { bin: 'find', gtfobins_id: 'find' }, source: 't' }));
fs.add(OBOL.facts.makeFact({ kind: 'privesc.sudo_binary', scope: 'host:1', value: { bin: 'awk', gtfobins_id: 'awk' }, source: 't' }));
const r = R.gtfobinsForMove('sudo-abuse', fs);
ok(r && r.context === 'sudo' && r.items.length === 2, 'sudo-abuse resolves both identified binaries');
ok(R.gtfobinsForMove('recon-smb-anon', fs) === null, 'a non-GTFOBins move returns null');

// gtfoFunctions: the full per-function listing for the Workbench browser
const findFns = R.gtfoFunctions('find');
ok(findFns.known === true && findFns.inlined === true, 'find has inlined functions');
ok(findFns.functions.some(function (f) { return f.name === 'shell' && f.codes.length; }), 'find lists its shell function with code');
ok(findFns.functions[0].name === 'shell' || findFns.functions[0].name === 'command', 'functions are ordered shell/command first');
// a binary present in GTFOBINS_ALL but with no inlined functions (link-only, e.g. an inherit-only entry)
const linkOnly = (OBOL.GTFOBINS_ALL || []).filter(function (n) { return !(OBOL.GTFOBINS || {})[n]; })[0];
const loFns = R.gtfoFunctions(linkOnly);
ok(loFns.known === true && loFns.inlined === false && loFns.functions.length === 0, 'a link-only binary (' + linkOnly + ') is known but not inlined');
ok(R.gtfoFunctions('definitely-not-a-binary').known === false, 'unknown binary is not known');

// gtfoSuggest: name search, inlined binaries first
const sug = R.gtfoSuggest('pyth');
ok(sug.indexOf('python') >= 0, 'suggest finds python for "pyth"');
ok(R.gtfoSuggest('').length === 0, 'empty query suggests nothing');

console.log(fail ? ('\nRESOLVE: ' + fail + ' FAILURES') : '\nRESOLVE: all passed');
process.exit(fail ? 1 : 0);
