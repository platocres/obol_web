/* Bare ini/conf credential field (outcome/loot axis): a config file disclosed over HTTP (curl/wget of
 * a .conf/.ini) or read on-host (cat/type/Get-Content) carries an unprefixed, unquoted password field.
 * websource `_parse_source_secret` now mints a config_secret credential.candidate for it (source
 * 'config-field'), with tight guards so SecureString/.NET type names, binary gMSA blobs, booleans,
 * password_hash/_min keys, comments, and prose never mint. Cases are drawn from real 0xdf corpus units
 * (Cascade, FriendZone, Monitors/Cacti, Shibboleth/Zipper zabbix, icinga). */
'use strict';
var path = require('path');
var R = path.join(__dirname, '..', '..');
function req(p) { return require(path.join(R, p)); }
req('assets/engine/facts.js'); req('assets/engine/phases.js'); req('assets/engine/pack.js');
req('assets/engine/profile.js'); req('assets/engine/command.js'); req('assets/engine/workspace.js');
var OBOL = globalThis.OBOL;
req('assets/engine/parsers/common.js');
['nmap', 'directory', 'creds', 'host', 'web', 'services', 'database', 'websource', 'findings', 'shape', 'pivot', 'dns', 'blockers', 'nxc-catalog'].forEach(function (m) { req('assets/engine/parsers/' + m + '.js'); });
req('assets/engine/parsers/index.js');

var fail = 0;
function ok(c, m) { if (!c) { console.error('  FAIL:', m); fail++; } else { console.log('  ok  :', m); } }
function creds(cmd, out) {
  var r = OBOL.parsers.parseActionOutput({ actionId: '', command: cmd, stdout: out, scope: 'host:10.10.10.10', domain: '' });
  return (r.facts || []).filter(function (f) { return f.kind === 'credential.candidate' && f.value && f.value.kind === 'config_secret'; });
}
function mintsPw(cmd, out, pw) { return creds(cmd, out).some(function (f) { return f.value.password === pw; }); }
function mintsAnyConfigSecret(cmd, out) { return creds(cmd, out).length > 0; }

// ---- true positives: unprefixed/unquoted config fields the old extractors missed ----
ok(mintsPw('curl http://t/icingaweb2/config.ini', '[icingaweb2]\ntype = "db"\npassword = "IcingaWeb2DBPassword"\nusername = "icingaweb2"', 'IcingaWeb2DBPassword'),
  'icinga .ini bare quoted password field mints config_secret');
ok(mintsPw('ldapsearch -x', 'cascadeLegacyPwd = YmFDVDNyMWFOMDBkbGVz', 'YmFDVDNyMWFOMDBkbGVz'),
  'cascade cascadeLegacyPwd (bare, no quotes) mints config_secret');
ok(mintsPw('cat mysql_data.conf', 'db_user = admin\ndb_pass = Agpyu12!0.213$', 'Agpyu12!0.213$'),
  'friendzone db_pass (short _pass form) mints config_secret');
ok(mintsPw('cat zabbix_server.conf', 'DBName=zabbix\nDBUser=zabbix\nDBPassword=bloooarskybluh', 'bloooarskybluh'),
  'zabbix DBPassword=value (no spaces, no quotes) mints config_secret');
ok(mintsPw('cat zabbix_server.conf', 'DBPassword=f.YMeMd$pTbpY3-449', 'f.YMeMd$pTbpY3-449'),
  'zipper zabbix DBPassword with punctuation mints config_secret');
ok(mintsPw('type backup.conf', 'config_passwd = Verti3alEdge2020', 'Verti3alEdge2020'),
  'config_passwd variant mints config_secret');
ok(mintsAnyConfigSecret('Get-Content C:\\app\\db.ini', 'DBPassword = P@ssw0rd!2026'),
  'PowerShell Get-Content of an ini mints config_secret (universal dispatch, not just curl)');

// ---- false positives: must mint NO config_secret ----
ok(!mintsAnyConfigSecret('ConvertFrom-ADManagedPasswordBlob', 'SecureCurrentPassword = System.Security.SecureString'),
  'gMSA SecureString .NET type name does not mint');
ok(!mintsAnyConfigSecret('ConvertFrom-ADManagedPasswordBlob', 'CurrentPassword = \u0001\u00a3\u00ff\u0002\u0080blob\u00c0'),
  'gMSA binary/unicode blob value does not mint');
ok(!mintsAnyConfigSecret('cat shadow.conf', 'password_hash = $6$abc$deadbeefdeadbeef'),
  'password_hash key (ends in hash, not pass) does not mint');
ok(!mintsAnyConfigSecret('cat sshd_config', 'PasswordAuthentication = yes'),
  'a boolean config value does not mint');
ok(!mintsAnyConfigSecret('cat app.conf', '# password = changeme_in_prod_please'),
  'a commented-out field does not mint');
ok(!mintsAnyConfigSecret('notes', 'the admin password = supersecretvalue appears in the body'),
  'a password mentioned mid-line in prose does not mint (line-anchored)');
ok(!mintsAnyConfigSecret('cat .env.example', 'DB_PASSWORD = <your-password-here>'),
  'a placeholder value does not mint');
ok(!mintsAnyConfigSecret('grep -i pass app.py', 'bypass_cache = true'),
  'bypass_ (contains pass but no _pass suffix) does not mint');
ok(!mintsAnyConfigSecret('cat /etc/nsswitch.conf', 'passwd:         files systemd'),
  '/etc/nsswitch.conf passwd: files does not mint config_secret');
ok(!mintsAnyConfigSecret('cat env.txt', 'pwd = /var/www/html'),
  'a filesystem path assigned to pwd does not mint config_secret');

console.log('\nCONFIG-FIELD CRED SMOKE: ' + (fail ? fail + ' FAILURE(S)' : 'all passed'));
process.exit(fail ? 1 : 0);
