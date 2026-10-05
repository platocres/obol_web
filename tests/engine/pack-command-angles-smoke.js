/* Pack-wide sweep: no coach command may carry a bare <angle-bracket> fill-placeholder.
 *
 * The coach convention is strict: `{{token}}` is a value the operator fills in (path.js renders a
 * labelled input and the command resolves from facts/params); `<...>` is dead text the coach CANNOT
 * turn into an input, so a "fill this in" placeholder written as <database> or <user-sid> silently
 * hands the operator an un-runnable command. Genuine markup (XXE/XSS payloads, XML-RPC bodies) is a
 * different thing: it is literal command text the operator copies verbatim, and it always appears as a
 * matched tag pair (<r>...</r>, <script>...</script>, <methodCall>...</methodCall>) or an XML
 * declaration (<?xml, <!DOCTYPE, <!ENTITY). So the rule that separates the two with no allowlist:
 * an opening <tag> whose matching </tag> is absent from the same command is a bare placeholder, and
 * is banned. */
'use strict';
var path = require('path');
var fs = require('fs');
var R = path.join(__dirname, '..', '..');
var pdir = path.join(R, 'data', 'packs');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }

var OPEN = /<([a-zA-Z][\w .\/-]*)>/g;
var offenders = [];
var scanned = 0;
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) {
  var j = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8'));
  (j.actions || []).forEach(function (a) {
    (a.commands || []).forEach(function (c, i) {
      scanned++;
      var run = c.run || '', m;
      OPEN.lastIndex = 0;
      while ((m = OPEN.exec(run))) {
        var tag = m[1];
        if (run.indexOf('</' + tag + '>') < 0) offenders.push(f + ' :: ' + a.id + ' #' + i + ' :: <' + tag + '> :: ' + run);
      }
    });
  });
});

ok(scanned > 0, 'scanned every pack command (' + scanned + ' across the pack set)');
ok(offenders.length === 0, 'no coach command carries a bare <angle-bracket> fill-placeholder; use {{token}} instead'
  + (offenders.length ? ('\n        ' + offenders.join('\n        ')) : ''));

console.log('\nPACK COMMAND ANGLES: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
