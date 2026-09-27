/* Pack command denylist: reject AD commands that tools reject on sight, so audited breakage
 * (bogus netexec flags/modules, an SPN-mismatched Kerberos psexec) can't creep back into a pack. */
'use strict';
var fs = require('fs'), path = require('path');
var PACKS = path.join(__dirname, '..', '..', 'data', 'packs');

var fail = 0;
function bad(msg) { console.error('  FAIL:', msg); fail++; }

// Each rule: a regex the RUN string must NOT match, and why.
var DENY = [
  { re: /--trusted-to-auth\b/, why: '--trusted-to-auth is not a netexec flag (aborts the whole delegation-enum command)' },
  { re: /-M\s+gpo_privesc\b/, why: 'netexec has no gpo_privesc module (use bloodyAD get writable / BloodHound)' },
  // A Kerberos (-k) psexec must target the FQDN the SPN was minted for. A BARE {{target_sam}} (a SAM
  // name, not FQDN) mismatches an FQDN SPN → silent failure. {{target_sam}}.{{domain}} (FQDN) is fine.
  { re: /\bpsexec\b(?=.*\s-k\b)(?=.*\{\{target_sam\}\}(?!\.))/, why: 'a Kerberos (-k) psexec must target the SPN host FQDN ({{spn_host}} or {{target_sam}}.{{domain}}), not a bare {{target_sam}} — silent Kerberos failure' },
];

var names = fs.readdirSync(PACKS).filter(function (f) { return /\.json$/.test(f); });
var checked = 0;
names.forEach(function (fname) {
  var pack = JSON.parse(fs.readFileSync(path.join(PACKS, fname), 'utf8'));
  (pack.actions || []).forEach(function (a) {
    var cmds = (a.commands && a.commands.length) ? a.commands : [{ run: a.command }];
    cmds.forEach(function (c) {
      [c && c.run, c && c.web, a.command, a.web_command].filter(Boolean).forEach(function (run) {
        checked++;
        DENY.forEach(function (rule) {
          if (rule.re.test(run)) bad(fname + ' · ' + (a.id || '?') + ': ' + rule.why + '\n         → ' + run);
        });
      });
    });
  });
});

if (!fail) console.log('  ok  : ' + checked + ' pack commands, none match the broken-command denylist');
console.log(fail ? ('\nPACK COMMAND AUDIT: ' + fail + ' FAILURES') : '\nPACK COMMAND AUDIT: all passed');
process.exit(fail ? 1 : 0);
