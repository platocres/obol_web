/* gloss-coverage.js — "What Each Part Does" completeness guardrail. For every builder, build a MAXIMAL
 * command (every toggle on, every field filled, across each primary-mode value) and assert that every FLAG
 * token it can contain has a glossary entry (OBOL.TOOL_GLOSSARY, resolved the way the UI resolves it). A
 * switch with no explainer is the LAPS bug class; this keeps the teaching panel complete as tools grow.
 */
'use strict';
var path = require('path');
var ROOT = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(ROOT, p)); }
req('assets/engine/toolbuilder.js'); req('data/toolset.js'); req('data/tool-glossary.js'); req('assets/engine/toolkit.js');
var OBOL = globalThis.OBOL, TB = OBOL.toolbuilder, TK = OBOL.toolkit;

var CTX = { target: { value: '10.10.10.10', ip: '10.10.10.10', hostname: 'dc01.corp.local', url: 'http://10.10.10.10', fuzzurl: 'http://10.10.10.10/FUZZ' }, context: { domain: 'corp.local', baseDn: 'DC=corp,DC=local', username: 'svc', port: '445', lhost: '10.10.14.5', lport: '4444' }, workspace: { wordlist: 'rockyou.txt', outputDir: 'loot', hashfile: 'hashes.txt' } };
var PRIMARY = ['protocol', 'mode', 'method', 'authMode', 'role', 'engine', 'action', 'source', 'inputMode', 'requestMode', 'client', 'gobusterMode', 'listPayloads'];

function maximalStates(b) {
  var base = TB.defaultsFor(b, CTX);
  (b.fields || []).forEach(function (f) {
    if (f.type === 'checkbox') base[f.id] = true;
    else if (f.type === 'select') { if ((f.options || []).length) base[f.id] = base[f.id] || f.options[0].value; }
    else if (base[f.id] === undefined || base[f.id] === '') base[f.id] = f.type === 'secret' ? 'S3cret' : (f.type === 'number' ? '7' : 'probeval');
  });
  var states = [base];
  (b.fields || []).filter(function (f) { return f.type === 'select' && PRIMARY.indexOf(f.id) >= 0; }).forEach(function (sel) {
    sel.options.forEach(function (o) { var s = Object.assign({}, base); s[sel.id] = o.value; states.push(s); });
  });
  return states;
}

var fail = 0, gaps = [];
(OBOL.TOOLSET || []).forEach(function (b) {
  var missing = {};
  maximalStates(b).forEach(function (st) {
    var cmd; try { cmd = TB.compile(b, TB.normalizeValues(b, st, CTX), CTX); } catch (e) { return; }
    var glossed = {}; TK.glossCommand(cmd, b).forEach(function (g) { glossed[g.flag] = 1; });
    TK.tokenize(cmd).forEach(function (tok, i) {
      if (i === 0 || !/^-/.test(tok)) return; // executable, or a non-flag value
      var key = tok.indexOf('=') > 0 ? tok.slice(0, tok.indexOf('=')) : tok;
      if (!glossed[key]) missing[key] = 1;
    });
  });
  var keys = Object.keys(missing);
  if (keys.length) { gaps.push('  ' + b.id + ': ' + keys.join('  ')); fail += keys.length; }
});

if (gaps.length) { console.error('un-glossed switches:'); gaps.forEach(function (g) { console.error('  FAIL:' + g); }); console.error('gloss-coverage: ' + fail + ' FAIL'); process.exit(1); }
console.log('gloss-coverage: OK (every flag a tool can emit has a What Each Part Does entry)');
