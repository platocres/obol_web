const fs = require('fs');
const path = require('path');

console.log('=== VERIFYING INTEGRITY ACROSS ALL 20 MINED LABS ===');

// 1. Verify packs-bundle.js integrity and field notes 1:1 match
require(path.resolve(__dirname, '../data/packs-bundle.js'));
const packData = globalThis.OBOL.packData;

// Load field-notes.js
require(path.resolve(__dirname, '../data/field-notes.js'));
const fieldNotes = globalThis.OBOL.FIELD_NOTES;

console.log('Total packs loaded:', Object.keys(packData).length);

// Check key moves updated across the 4 batches:
const checks = [
  // Batch 1:
  { pack: 'ad_2026_09', action: 'laps-read', mustHave: ['nxc smb', '--laps'], produces: 'credential.admin' },
  { pack: 'ad_2026_09', action: 'bloodyad-acl', mustHave: ['ACCOUNTDISABLE', 'includeDeletedObjects'] },
  // Batch 2:
  { pack: 'ad_2026_09', action: 'adcs-esc', mustHave: ['-add-officer', 'SubCA', '-issue-request'] },
  { pack: 'linux_privesc_2026_09', action: 'sudo-abuse', mustHave: ['systemctl status'] },
  { pack: 'ad_2026_09', action: 'dump-secrets', mustHave: ['diskshadow'] },
  { pack: 'ad_2026_09', action: 'ad-acl-abuse', mustHave: ['setuserinfo2'] },
  // Batch 3:
  { pack: 'ad_2026_09', action: 'gmsa-read', mustHave: ['--gmsa', 'get gmsa'], produces: 'credential.available' },
  { pack: 'ad_2026_09', action: 'delegation-abuse', mustHave: ['add rbcd'] },
  { pack: 'ad_2026_09', action: 'unconstrained-delegation', mustHave: ['tgtdeleg'] },
  { pack: 'database_2026_09', action: 'mssql-login', mustHave: ['xp_dirtree'] },
  // Batch 4 (Set 1):
  { pack: 'windows_privesc_2026_09', action: 'windows-service-dacl-abuse', mustHave: ['sc.exe config', 'Server Operators'] },
  { pack: 'windows_privesc_2026_09', action: 'windows-enum', mustHave: ['ConsoleHost_history.txt'] },
  { pack: 'ad_2026_09', action: 'win-interactive-shell', mustHave: ['evil-winrm', '-c', '-k'] },
  { pack: 'ad_2026_09', action: 'adidns-abuse', mustHave: ['bloodyAD', 'add dns'] },
  // Set 2 additions:
  { pack: 'ad_2026_09', action: 'adcs-esc', mustHave: ['-save-old', 'ESC4'] },
  { pack: 'ad_2026_09', action: 'dump-secrets', mustHave: ['Azure-AD-Connect.ps1'] },
  { pack: 'ad_2026_09', action: 'wsus-abuse', mustHave: ['SharpWSUS.exe create'] },
  { pack: 'ad_2026_09', action: 'shadow-credentials', mustHave: ['Whisker.exe', 'KrbRelayUp.exe'] },
  { pack: 'linux_privesc_2026_09', action: 'wildcard-injection', mustHave: ['7z a archive.zip'] },
  { pack: 'linux_privesc_2026_09', action: 'python-library-hijack', mustHave: ['__pycache__'] },
  { pack: 'findings_checks_2026_09', action: 'check-exposed-files', mustHave: ['actuator/heapdump'] },
  { pack: 'recon_2026_09', action: 'recon-ike-vpn', mustHave: ['hashcat -m 5400'] },
  { pack: 'recon_2026_09', action: 'vnc-desktop-shell', mustHave: ['vncpwd'] },
  // Batch 2 (Ranks 26-45 additions):
  { pack: 'ad_2026_09', action: 'timeroasting', mustHave: ['-M timeroast', '31300'], produces: 'hash.sntp' },
  { pack: 'ad_2026_09', action: 'ad-recycle-bin-enum', mustHave: ['isDeleted', '1.2.840.113556.1.4.417'], produces: 'ad.deleted_objects' },
  { pack: 'ad_2026_09', action: 'azuread-connect-dump', mustHave: ['Get-MSOLCredentials.ps1'], produces: 'credential.admin' },
  { pack: 'cracking_2026_09', action: 'vnc-decrypt', mustHave: ['vncpwd'], produces: 'credential.available' },
  { pack: 'linux_privesc_2026_09', action: 'wildcard-symlink-privesc', mustHave: ['ln -s /root/root.txt', 'unzip -p'], produces: 'objective.root_flag' },
  // Batch 3 (Ranks 48-67 additions):
  { pack: 'linux_privesc_2026_09', action: 'git-repo-forensics', mustHave: ['git log -p', 'cat .git/config'], produces: 'credential.candidate' },
  { pack: 'web_2026_09', action: 'jenkins-cli-fileread', mustHave: ['jenkins-cli.jar', '@/etc/passwd'], produces: 'loot.files' },
  { pack: 'cracking_2026_09', action: 'keepass-dump-recover', mustHave: ['keepass_dump_masterkey', 'keepass2john'], produces: 'credential.candidate' },
  { pack: 'web_2026_09', action: 'activemq-cve-2023-46604', mustHave: ['activemq_cve_2023_46604', '61616'], produces: 'foothold.shell' },
  { pack: 'windows_privesc_2026_09', action: 'nsclient-web-privesc', mustHave: ['nsclient.ini', '8443'], produces: 'access.system' },
  { pack: 'web_2026_09', action: 'nvms1000-traversal', mustHave: ['win.ini', 'root.txt'], produces: 'loot.files' },
  { pack: 'web_2026_09', action: 'ssrf', mustHave: ['Internal Port Fuzzing'] },
  { pack: 'obol_flag_hunt_2026_09', action: 'flag-hunt-root-windows', mustHave: ['dir /r', 'Stream'] },
  // Batch 4 (Ranks 68-87 additions):
  { pack: 'cracking_2026_09', action: 'cisco-decrypt', mustHave: ['cisco-decrypt', 'hashcat -m 500'], produces: 'credential.available' },
  { pack: 'findings_checks_2026_09', action: 'access-db-export', mustHave: ['mdb-tables', 'mdb-export'], produces: 'credential.available' },
  { pack: 'recon_2026_09', action: 'http3-quic-probe', mustHave: ['quic-info', 'quiche-client'], produces: 'service.http3' },
  { pack: 'web_2026_09', action: 'exiftool-cve-2021-22204', mustHave: ['exiftool -ver', 'payload = b'], produces: 'foothold.linux' },
  { pack: 'web_2026_09', action: 'wordpress', mustHave: ['static=1'] },
  { pack: 'windows_privesc_2026_09', action: 'alwaysinstallelevated', mustHave: ['msiexec /quiet'] },
  { pack: 'web_exploit_checks_2026_09', action: 'splunk-app-rce', mustHave: ['services/apps/local'] },
  // Batch 5 (Ranks 88-107 additions):
  { pack: 'web_2026_09', action: 'php-backdoor-useragent', mustHave: ['User-Agentt: zerodium', 'system('], produces: 'foothold.linux' },
  { pack: 'web_2026_09', action: 'opennetadmin-rce', mustHave: ['ona/dcm.php', 'xajaxargs'], produces: 'foothold.linux' },
  { pack: 'web_2026_09', action: 'nostromo-rce', mustHave: ['/.%0d%0a/bin/sh', 'POST'], produces: 'foothold.linux' },
  { pack: 'database_2026_09', action: 'adminer-mysql-fileread', mustHave: ['rogue_mysql_server.py', 'LOAD DATA LOCAL INFILE'], produces: 'credential.available' },
  { pack: 'recon_2026_09', action: 'ipmi-bmc-cipher0', mustHave: ['ipmitool -I lanplus -C 0', 'hashcat -m 7300'], produces: 'credential.available' },
  { pack: 'findings_checks_2026_09', action: 'ole-macro-analysis', mustHave: ['olevba', 'oledump.py'], produces: 'credential.available' },
  { pack: 'web_exploit_checks_2026_09', action: 'zabbix-script-rce', mustHave: ['system.run'] },
  // Batch 6 (Ranks 109-128 additions):
  { pack: 'web_2026_09', action: 'jackson-databind-rce', mustHave: ['DriverManagerConnectionSource', 'INIT=RUNSCRIPT'], produces: 'foothold.linux' },
  { pack: 'web_2026_09', action: 'pfsense-rrd-rce', mustHave: ['status_rrd_graph_img.php', 'database=queues'], produces: 'access.root' },
  { pack: 'recon_2026_09', action: 'unrealircd-backdoor', mustHave: ['AB;', 'nc -vn'], produces: 'foothold.linux' },
  { pack: 'recon_2026_09', action: 'heartbleed-memory-leak', mustHave: ['ssl-heartbleed', 'heartbleed.py'], produces: 'credential.available' },
  { pack: 'database_2026_09', action: 'redis-rogue-server-rce', mustHave: ['redis-cli', 'redis-rogue-server.py'], produces: 'foothold.linux' },
  { pack: 'database_2026_09', action: 'nosqli-regex-extract', mustHave: ['username[$ne]', '$regex'], produces: 'credential.available' },
  { pack: 'linux_privesc_2026_09', action: 'lxd-container-privesc', mustHave: ['lxc image import', 'security.privileged=true'], produces: 'access.root' },
  // Batch 7 (Ranks 129-148 additions):
  { pack: 'windows_privesc_2026_09', action: 'vhd-mount-sam-extract', mustHave: ['guestmount', 'secretsdump'], produces: 'credential.candidate' },
  { pack: 'windows_privesc_2026_09', action: 'wsl-bash-enum', mustHave: ['wsl.exe whoami', '.bash_history'], produces: 'credential.candidate' },
  { pack: 'web_2026_09', action: 'web-config-upload-bypass', mustHave: ['web.config'], produces: 'foothold.webshell' },
  { pack: 'web_2026_09', action: 'nibbleblog-myimage-upload-rce', mustHave: ['admin.php', 'my_image'], produces: 'foothold.webshell' },
  { pack: 'linux_privesc_2026_09', action: 'gdbserver-remote-execution', mustHave: ['1337', 'target remote'], produces: 'foothold.shell' },
  { pack: 'linux_privesc_2026_09', action: 'gnu-screen-root-attach', mustHave: ['screen -x', 'tmux -S'], produces: 'access.admin' },
  { pack: 'web_2026_09', action: 'solr-velocity-template-rce', mustHave: ['params.resource.loader.enabled', 'velocity'], produces: 'foothold.shell' },
  // Batch 8 (Ranks 149-168 additions):
  { pack: 'windows_privesc_2026_09', action: 'prtg-config-extract', mustHave: ['PRTG Configuration.old.xml', 'dbpassword'], produces: 'credential.candidate' },
  { pack: 'windows_privesc_2026_09', action: 'prtg-notification-rce', mustHave: ['setnotification', 'script=rev.bat'], produces: 'access.admin' },
  { pack: 'web_2026_09', action: 'gitlab-ci-webshell', mustHave: ['git checkout', 'curl'], produces: 'foothold.webshell' },
  { pack: 'windows_privesc_2026_09', action: 'chm-payload-exec', mustHave: ['out2chm', '.chm'], produces: 'access.admin' },
  { pack: 'web_2026_09', action: 'iis6-webdav-scstorage', mustHave: ['cve_2017_7269', 'PROPFIND'], produces: 'foothold.windows' },
  { pack: 'web_2026_09', action: 'pdf-export-xss-fileread', mustHave: ['XMLHttpRequest', 'pdftotext'], produces: 'loot.files' },
  { pack: 'web_2026_09', action: 'amportal-conf-leak', mustHave: ['amportal.conf', 'AMPDBPASS'], produces: 'credential.candidate' },
  // Batch 9 (Ranks 88, 169-187 additions):
  { pack: 'windows_privesc_2026_09', action: 'sireprat-iot-exec', mustHave: ['SirepRAT.py', 'LaunchCommandWithOutput'], produces: 'access.admin' },
  { pack: 'linux_privesc_2026_09', action: 'chkrootkit-local-privesc', mustHave: ['/tmp/update', '/bin/bash -p'], produces: 'access.root' },
  { pack: 'web_2026_09', action: 'rejetto-hfs-rce', mustHave: ['search=%00', 'powershell.exe'], produces: 'foothold.windows' },
  { pack: 'web_2026_09', action: 'coldfusion-scheduled-task-rce', mustHave: ['password.properties', 'scheduleedit.cfm'], produces: 'foothold.webshell' },
  { pack: 'recon_2026_09', action: 'samba-usermap-script-rce', mustHave: ['logon "/=`nohup', 'smbclient'], produces: 'access.root' },
  { pack: 'database_2026_09', action: 'h2-database-console-rce', mustHave: ['CREATE ALIAS EXEC', 'CALL EXEC'], produces: 'foothold.shell' },
  { pack: 'database_2026_09', action: 'oracle-tns-odat-rce', mustHave: ['odat dbmsscheduler', 'sidguesser'], produces: 'access.system' },
  { pack: 'web_2026_09', action: 'ftp-webroot-upload-webshell', mustHave: ['ftp://anonymous', 'shell.aspx'], produces: 'foothold.webshell' },
  // Batch 10 (Ranks 188-194 final corpus completion):
  { pack: 'findings_checks_2026_09', action: 'gpg-private-key-decrypt', mustHave: ['gpg2john', 'gpg --import'], produces: 'loot.files' },
  { pack: 'linux_privesc_2026_09', action: 'npm-package-privesc', mustHave: ['preinstall', 'npm i -g'], produces: 'access.root' },
  { pack: 'web_2026_09', action: 'http-request-smuggling-auth', mustHave: ['Transfer-Encoding: chunked', 'Content-Length: 4'], produces: 'access.admin' },
  { pack: 'web_2026_09', action: 'nginx-log-poisoning-lfi', mustHave: ['access.log', 'system($_GET'], produces: 'foothold.linux' },
  { pack: 'web_exploit_checks_2026_09', action: 'zabbix-agent-system-run', mustHave: ['zabbix_get', 'system.run'], produces: 'foothold.linux' },
  { pack: 'web_2026_09', action: 'myfaces-viewstate-deserialization-rce', mustHave: ['javax.faces.ViewState', 'CommonsCollections5'], produces: 'foothold.windows' },
  { pack: 'web_2026_09', action: 'node-serialize-rce', mustHave: ['_$$ND_FUNC$$_', 'node-serialize'], produces: 'foothold.linux' }
];

let failed = false;

checks.forEach(chk => {
  const p = packData[chk.pack];
  if (!p) {
    console.error(`FAIL: Pack ${chk.pack} not found`);
    failed = true;
    return;
  }
  const a = (p.actions || []).find(x => x.id === chk.action);
  if (!a) {
    console.error(`FAIL: Action ${chk.action} in ${chk.pack} not found`);
    failed = true;
    return;
  }

  // Check required strings in commands or notes
  chk.mustHave.forEach(str => {
    const found = a.commands.some(c => (c.run && c.run.includes(str)) || (c.note && c.note.includes(str)));
    if (!found) {
      console.error(`FAIL: Action ${chk.action} missing substring: ${str}`);
      failed = true;
    }
  });

  if (chk.produces && !a.produces.includes(chk.produces)) {
    console.error(`FAIL: Action ${chk.action} missing produces: ${chk.produces}`);
    failed = true;
  }

  // Check field notes coverage
  const notes = fieldNotes[chk.action];
  if (!notes) {
    console.warn(`WARN: Action ${chk.action} has no authored field notes (using fallback)`);
  } else {
    if (notes.length !== a.commands.length) {
      console.warn(`NOTE: Action ${chk.action} commands count (${a.commands.length}) vs field notes count (${notes.length})`);
    } else {
      console.log(`PASS: ${chk.action} perfectly aligned (${a.commands.length} commands, ${notes.length} notes)`);
    }
  }
});

// Check bloodhound and directory parsers
const bhCode = fs.readFileSync(path.resolve(__dirname, '../assets/engine/bloodhound.js'), 'utf8');
if (!bhCode.includes('ReadLAPSPassword: 1') || !bhCode.includes('ReadGMSAPassword: 1')) {
  console.error('FAIL: bloodhound.js missing ReadLAPSPassword or ReadGMSAPassword');
  failed = true;
} else {
  console.log('PASS: bloodhound.js has both ReadLAPSPassword and ReadGMSAPassword in ABUSABLE_ACE');
}

const dirCode = fs.readFileSync(path.resolve(__dirname, '../assets/engine/parsers/directory.js'), 'utf8');
if (!dirCode.includes('_parse_ldap_descriptions')) {
  console.error('FAIL: directory.js missing _parse_ldap_descriptions');
  failed = true;
} else {
  console.log('PASS: directory.js defines _parse_ldap_descriptions');
}

const credsCode = fs.readFileSync(path.resolve(__dirname, '../assets/engine/parsers/creds.js'), 'utf8');
if (!credsCode.includes('_parse_timeroast') || !credsCode.includes('_parse_generic_dumped_credentials')) {
  console.error('FAIL: creds.js missing _parse_timeroast or _parse_generic_dumped_credentials');
  failed = true;
} else if (!credsCode.includes('_PRTG_DBPASS_RE') || !credsCode.includes('_AMPORTAL_PASS_RE')) {
  console.error('FAIL: creds.js missing _PRTG_DBPASS_RE or _AMPORTAL_PASS_RE');
  failed = true;
} else if (!credsCode.includes('_COLDFUSION_HASH_RE') || !credsCode.includes('_ODAT_CRED_RE')) {
  console.error('FAIL: creds.js missing _COLDFUSION_HASH_RE or _ODAT_CRED_RE');
  failed = true;
} else {
  console.log('PASS: creds.js defines Batch 8 & 9 credential parsers (_PRTG_DBPASS_RE, _AMPORTAL_PASS_RE, _COLDFUSION_HASH_RE, _ODAT_CRED_RE)');
}

const shapeCode = fs.readFileSync(path.resolve(__dirname, '../assets/engine/parsers/shape.js'), 'utf8');
if (!shapeCode.includes('vuln.iis6_webdav') || !shapeCode.includes('vuln.prtg') || !shapeCode.includes('vuln.gitlab') || !shapeCode.includes('vuln.october_cms')) {
  console.error('FAIL: shape.js missing Batch 8 VULN_SIGS signatures');
  failed = true;
} else if (!shapeCode.includes('vuln.rejetto_hfs') || !shapeCode.includes('vuln.coldfusion') || !shapeCode.includes('vuln.oracle_tns') || !shapeCode.includes('vuln.h2_console')) {
  console.error('FAIL: shape.js missing Batch 9 VULN_SIGS signatures');
  failed = true;
} else if (!shapeCode.includes('vuln.zabbix_agent') || !shapeCode.includes('vuln.myfaces_jsf') || !shapeCode.includes('vuln.node_serialize') || !shapeCode.includes('vuln.gitea')) {
  console.error('FAIL: shape.js missing Batch 10 VULN_SIGS signatures');
  failed = true;
} else {
  console.log('PASS: shape.js defines Batch 8, 9 & 10 VULN_SIGS signatures');
}

const blockersCode = fs.readFileSync(path.resolve(__dirname, '../assets/engine/parsers/blockers.js'), 'utf8');
if (!blockersCode.includes('blocker.protected_users') || !blockersCode.includes('blocker.account_not_delegated')) {
  console.error('FAIL: blockers.js missing blocker.protected_users or blocker.account_not_delegated');
  failed = true;
} else {
  console.log('PASS: blockers.js defines blocker.protected_users and blocker.account_not_delegated');
}

if (!failed) {
  console.log('\nALL 20 MINED LAB VERIFICATIONS PASSED WITH 100% SUCCESS!');
} else {
  process.exit(1);
}
