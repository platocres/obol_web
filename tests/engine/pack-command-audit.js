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

// Ordering: on the ACL-abuse move the DCSync GRANT (add dcsync) must come before the tangential
// set-owner / genericAll edges, so once you have joined a WriteDACL group the coach promotes the grant
// (the real cash-in) as the next step — not an unrelated WriteOwner primitive.
(function () {
  var adPack = JSON.parse(fs.readFileSync(path.join(PACKS, 'ad_2026_09.json'), 'utf8'));
  var acl = (adPack.actions || []).filter(function (a) { return a.id === 'bloodyad-acl'; })[0];
  if (!acl) { bad('bloodyad-acl move not found'); return; }
  var runs = (acl.commands || []).map(function (c) { return c.run || ''; });
  function idxOf(sub) { for (var i = 0; i < runs.length; i++) if (runs[i].indexOf(sub) >= 0) return i; return -1; }
  var dcsync = idxOf('add dcsync'), owner = idxOf('set owner'), generic = idxOf('add genericAll');
  var dcsyncCmd = (acl.commands || []).filter(function (c) { return (c.run || '').indexOf('add dcsync') >= 0; })[0];
  if (!dcsyncCmd || dcsyncCmd.win !== true) bad('bloodyad-acl: the `add dcsync` grant should carry win:true (the Pwn This Target flag)');
  if (dcsync < 0) bad('bloodyad-acl: no `add dcsync` grant command');
  else if (owner >= 0 && dcsync > owner) bad('bloodyad-acl: `add dcsync` (the DCSync cash-in) must be ordered BEFORE `set owner`');
  else if (generic >= 0 && dcsync > generic) bad('bloodyad-acl: `add dcsync` must be ordered BEFORE `add genericAll`');
  else console.log('  ok  : ACL-abuse move promotes the DCSync grant ahead of the tangential owner/genericAll edges');
})();
console.log(fail ? ('\nPACK COMMAND AUDIT: ' + fail + ' FAILURES') : '\nPACK COMMAND AUDIT: all passed');
process.exit(fail ? 1 : 0);
