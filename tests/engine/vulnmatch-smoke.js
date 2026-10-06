/* Node test for the vulnmatch fingerprint parser (assets/engine/parsers/shape.js _parse_vulnmatch).
 * It proves the evidence loop for the promoted known-exploit modules: pasting a service/version
 * banner, a CHANGELOG, or a vuln-script verdict mints a vuln.<name> LEAD that the matching module
 * keys on. Also asserts the conservative boundary (unrelated / plain-version output mints nothing)
 * and that every minted vuln.* fact is actually consumed by its module's requires_any. */
'use strict';
require('../../assets/engine/facts.js');
require('../../assets/engine/phases.js');
require('../../assets/engine/pack.js');
require('../../assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog']
  .forEach(function (m) { require('../../assets/engine/parsers/' + m + '.js'); });
require('../../assets/engine/parsers/index.js');
const fs = require('fs'), path = require('path');
const OBOL = globalThis.OBOL, P = OBOL.parsers, PK = OBOL.pack;

let fail = 0;
function ok(cond, msg) { if (!cond) { console.error('  FAIL:', msg); fail++; } else { console.log('  ok  :', msg); } }
function kinds(cmd, out) {
  return P.parseActionOutput({ actionId: 'operator-ingest', command: cmd, stdout: out, scope: 'host:10.10.10.10' })
    .facts.map(function (f) { return f.kind; });
}
function vulns(cmd, out) { return kinds(cmd, out).filter(function (k) { return k.indexOf('vuln.') === 0; }); }

// --- positive fingerprints: a banner/version/CVE/verdict mints the right lead ---
const CASES = [
  ['nmap -sV 10.10.10.10', '21/tcp open  ftp  vsftpd 2.3.4', 'vuln.vsftpd_234'],
  ['nmap -sV 10.10.10.10', '21/tcp open  ftp  ProFTPD 1.3.5', 'vuln.proftpd_modcopy'],
  ['nmap --script smb-os-discovery', 'OS: Unix (Samba 3.0.20-Debian)', 'vuln.samba_usermap'],
  ['nmap -p445 --script smb-protocols', 'SMBGhost scanner: Vulnerable', 'vuln.smbghost'],
  ['nmap --script rdp-vuln-ms19-0708', 'VULNERABLE: CVE-2019-0708', 'vuln.bluekeep'],
  ['gobuster', '/cgi-bin/status.sh (Status: 200)', 'vuln.shellshock'],
  ['nmap --script ssl-heartbleed', 'VULNERABLE: The Heartbleed Bug', 'vuln.heartbleed'],
  ['curl', 'Drupal 7.57, 2018-02-21', 'vuln.drupalgeddon2'],
  ['curl', 'phpMyAdmin 4.8.1', 'vuln.phpmyadmin_lfi'],
  ['nmap -sV', '10000/tcp open  http  MiniServ 1.910 (Webmin httpd)', 'vuln.webmin'],
  ['curl', '<title>Login to Usermin</title>', 'vuln.usermin'],
  ['curl', '<title>OFBiz: Web Tools</title>', 'vuln.ofbiz'],
  ['curl', 'Cacti version 1.2.22', 'vuln.cacti'],
  ['curl', '<title>Zabbix SIA</title>', 'vuln.zabbix'],
  ['curl', 'Splunk build 9.1.0', 'vuln.splunk'],
  ['curl', 'Apache Commons Text 1.9 / Text4Shell', 'vuln.text4shell'],
  ['nmap -sV', '8021/tcp open  freeswitch-event', 'vuln.freeswitch'],
  ['nc', 'JDWP-Handshake', 'vuln.jdwp'],
  ['nc', 'Aerospike database info', 'vuln.aerospike'],
  ['nc', 'WiFi Mouse Server', 'vuln.wifi_mouse'],
];
CASES.forEach(function (c) {
  ok(vulns(c[0], c[1]).indexOf(c[2]) >= 0, 'mints ' + c[2] + ' from ' + JSON.stringify(c[1]).slice(0, 44));
});

// --- conservative boundary: unrelated and plain-version output mint NO vuln lead ---
ok(vulns('ls -la', 'total 8\ndrwxr-xr-x 2 root root 4096 .').length === 0, 'unrelated output mints no vuln lead');
ok(vulns('nmap -sV', '22/tcp open  ssh  OpenSSH 8.2p1 Ubuntu').length === 0, 'a non-vulnerable SSH banner mints no vuln lead');
ok(vulns('nmap -sV', '21/tcp open  ftp  vsftpd 3.0.3').length === 0, 'a patched vsftpd version mints no vuln lead');

// --- loop integrity: every vuln.* the recognizer can mint is consumed by a module's requires_any ---
const pdir = path.join(__dirname, '..', '..', 'data', 'packs');
const bundle = {};
fs.readdirSync(pdir).filter(function (f) { return f.endsWith('.json'); }).forEach(function (f) {
  try { bundle[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(pdir, f), 'utf8')); } catch (e) {}
});
const A = PK.loadPacks(Object.keys(bundle).map(function (k) { return bundle[k]; }));
const required = {};
A.forEach(function (a) { (a.requires_any || []).concat(a.requires_all || []).forEach(function (r) { required[r] = 1; }); });
const allVulnFacts = {}; CASES.forEach(function (c) { allVulnFacts[c[2]] = 1; });
Object.keys(allVulnFacts).forEach(function (vf) {
  ok(required[vf] === 1, vf + ' is consumed by a module (no orphan lead)');
});

if (fail) { console.error('\nvulnmatch-smoke: ' + fail + ' FAILURES'); process.exit(1); }
console.log('\nvulnmatch-smoke: all passed');
