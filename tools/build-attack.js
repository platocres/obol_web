#!/usr/bin/env node
/*!
 * tools/build-attack.js — compile the MITRE ATT&CK Enterprise STIX bundle into a compact,
 * browser-bundled catalog (data/attack-catalog.js) for the Frameworks view.
 *
 * Source (fetch first, then pass the path):
 *   curl -sSL -o /tmp/enterprise-attack.json \
 *     https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
 *   node tools/build-attack.js /tmp/enterprise-attack.json
 *
 * Emits OBOL.ATTACK = { version, tactics: [{id,name}] (matrix order), techniques: { Txxxx: {
 *   n: name, ta: [tactic shortnames], sub: isSubtechnique, p: parentId, det: trimmed detection,
 *   ds: [data sources], mit: [mitigation names], url } } }.
 *
 * ATT&CK is (C) The MITRE Corporation, provided under the ATT&CK Terms of Use
 * (https://attack.mitre.org/resources/terms-of-use/). Attribution retained in the emitted file.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const SRC = process.argv[2] || '/tmp/enterprise-attack.json';
const OUT = path.join(__dirname, '..', 'data', 'attack-catalog.js');

// Detection backfill. ATT&CK v19 dropped the free-text x_mitre_detection field in favour of
// detection strategies/analytics, so most techniques ship with no detection prose. These obol-
// authored blue-team blurbs fill that gap for the techniques the Frameworks view actually surfaces
// (the hover card's "Blue Team Detects" line). Applied ONLY when ATT&CK itself carries no detection
// text, so a future ATT&CK release that restores it wins. Plain prose, house style (no em/en dashes).
// These blurbs are obol's own content, not MITRE's; the ATT&CK names/structure remain (C) MITRE.
const DET_OVERRIDES = {
  'T1003': 'Watch for processes opening a handle to lsass.exe (Sysmon event 10 targeting lsass), reads of the SAM/SYSTEM/SECURITY registry hives or ntds.dit, and Mimikatz or comsvcs.dll MiniDump behaviour. On Linux, reads of /etc/shadow by a non-root process.',
  'T1003.006': 'A directory replication pull (DRSUAPI GetNCChanges) from a host that is not a domain controller. Alert on event 4662 carrying the DS-Replication-Get-Changes GUIDs sourced from a workstation or member server.',
  'T1046': 'Many connection attempts across sequential ports or hosts in a short window from one source: the fan-out signature of a port scan. Watch NetFlow, firewall denies, and IDS scan signatures.',
  'T1053': 'New or changed scheduled tasks (Windows event 4698/4702 and the Task Scheduler operational log) or cron entries. Correlate task creation with the account and the binary it runs.',
  'T1053.003': 'A new or edited crontab under /etc/cron*, /var/spool/cron, or a user crontab, especially one invoking a shell, an interpreter, or a writable script. Monitor file writes and the cron service logs.',
  'T1057': 'Execution of tasklist, ps, Get-Process, or WMI Win32_Process enumeration shortly after a foothold. Telling as a sequence alongside other discovery commands rather than on its own.',
  'T1059': 'Interpreter processes (cmd, powershell, bash, wscript) spawned by an unexpected parent, with suspicious or encoded command lines. PowerShell script-block logging (event 4104) and process creation with command line (4688) are the key sources.',
  'T1068': 'A low-privilege process suddenly running as SYSTEM or root, an unexpected child of a service process, or a driver/service crash just before the escalation. EDR process-lineage and kernel-exploit signatures.',
  'T1078': 'Logons that are valid but anomalous: a new source host, odd hours, impossible travel, or a service account used interactively (event 4624/4625 with logon type and source). Baselining normal account use is what surfaces this.',
  'T1087': 'Enumeration of users and groups: net user, net group, LDAP queries for user objects, or Get-ADUser/Get-NetUser. A spike of directory reads from one host is the signal.',
  'T1087.002': 'Bulk LDAP queries against the domain for user and group objects (SharpHound/BloodHound collection, net group /domain). Watch one host reading the directory broadly, and event 4661 on sensitive objects.',
  'T1098': 'Changes to account properties or group membership (events 4728/4732/4738, and 5136 for directory object edits), added credentials or keys, or a password reset. Alert on privilege-group additions and adminCount changes.',
  'T1110': 'Many failed authentications against one or many accounts (4625 clustering, auth.log failures) followed by a success. Spraying shows few attempts across many accounts; cracking is offline, so watch instead for the hash theft that precedes it.',
  'T1110.002': 'Offline by nature, so detect the theft that feeds it: a dump of SAM or NTDS, Kerberos ticket or AS-REP extraction, then later a successful logon with a previously unused credential.',
  'T1110.003': 'A small number of logon failures against many distinct accounts from one source in a short window, often one password per round to stay under lockout thresholds. Correlate 4625 across accounts, not per account.',
  'T1134': 'Processes duplicating or impersonating tokens (DuplicateTokenEx, ImpersonateLoggedOnUser), SeImpersonate abuse (the Potato family), and privilege-use events 4673/4674. EDR token-context changes.',
  'T1134.001': 'A service account holding SeImpersonatePrivilege spawning a SYSTEM process (the Potato pattern), or a process whose token owner differs from its creating user. Watch event 4673 and parent/child token mismatches.',
  'T1135': 'Enumeration of shares with net view, net share, an SMB query (nxc/CrackMapExec --shares), or srvsvc NetShareEnum. One host querying shares across many targets is the tell.',
  'T1190': 'Web and app server logs showing exploit payloads (path traversal, deserialization, injection), anomalous requests to a vulnerable endpoint, then a new child process of the web service. WAF alerts plus 4688 under w3wp or httpd.',
  'T1203': 'A document or browser process (winword, Acrobat, a browser) spawning an interpreter or an unexpected child, or crashing just before the spawn. Office child-process rules and EDR exploit signatures.',
  'T1210': 'Exploit traffic to a service port (SMB, RDP, a database, an app RPC) followed by remote code execution: an IDS signature for the CVE, a service crash, and a new process on the target not tied to a normal logon.',
  'T1505': 'A new or modified module or extension loaded by a server (an IIS module, an Apache module, a SQL stored procedure, a web shell). Watch file writes in web roots and module directories, and the server process spawning a shell.',
  'T1505.003': 'A new script file in a web-served directory and the web server process (w3wp, httpd, php-fpm) spawning cmd, powershell, or sh. File-integrity monitoring on web roots plus process lineage under the server account.',
  'T1548': 'Elevation that bypasses normal controls: UAC auto-elevate abuse, setuid misuse, or sudo caching. Watch for a medium-integrity process gaining high integrity, and setuid or sudo invocations outside the norm.',
  'T1548.001': 'Execution of setuid/setgid binaries by an unprivileged user, and new files gaining the setuid bit (chmod u+s). auditd on execve of setuid binaries and on chmod, plus find scans a defender can baseline.',
  'T1548.002': 'A medium-integrity process launching an auto-elevating Windows binary or a hijacked path/registry key to reach high integrity with no consent prompt (fodhelper, eventvwr, sdclt). Watch registry writes to known UAC-bypass keys.',
  'T1548.003': 'Unexpected sudo use, edits to /etc/sudoers or sudoers.d, and abuse of a cached sudo timestamp. auditd on sudoers writes and sudo invocations; a user running sudo to a shell or an unusual binary.',
  'T1550': 'Authentication with a hash, ticket, or token instead of a password: an NTLM logon with no preceding interactive logon, overpass-the-hash, or ticket reuse. Logon type 3 from an anomalous source with no password event.',
  'T1550.002': 'An NTLM network logon (event 4624 type 3, NTLM package) using an account hash from an unusual source, often a tooling host, with no matching interactive logon. Correlate with lateral SMB or WinRM connections.',
  'T1552': 'Reads of files, scripts, registry keys, or config that store secrets, plus command-line and history scraping. File-access auditing on credential stores and greps for password patterns.',
  'T1552.001': 'Access to files likely to hold secrets (config, scripts, .env, unattend.xml, web.config) and tools grepping for password patterns across a filesystem. File-read auditing on sensitive paths.',
  'T1552.004': 'Reads or exfiltration of key files (id_rsa, .pem, .pfx, .key) and certificate stores. Alert on access to ~/.ssh and certificate directories by an unexpected process.',
  'T1552.006': 'Reads of the SYSVOL Groups.xml and other Group Policy Preferences files that carry the AES-encrypted cpassword. Watch SMB reads of SYSVOL Groups.xml from a non-admin host.',
  'T1555': 'Access to browser credential stores, the Windows Credential Manager or DPAPI vault, or OS keychains by a process that is not the owning application.',
  'T1557': 'Spoofed name-resolution replies (LLMNR, NBT-NS, mDNS) or rogue SMB/HTTP listeners capturing authentication. Watch for Responder-style answers and an unexpected host replying to broadcast name queries.',
  'T1557.001': 'LLMNR/NBT-NS/mDNS poisoning (Responder) and relayed NTLM authentication (ntlmrelayx) to SMB or LDAP. Detect answers to broadcast name queries from a non-authoritative host, and an SMB logon relayed to a third party.',
  'T1558': 'Anomalous Kerberos activity: TGS requests for many SPNs, RC4 ticket requests, or tickets whose lifetime and encryption do not match policy. Watch events 4769 and 4768 and ticket-encryption downgrades.',
  'T1558.001': 'A TGT forged with the krbtgt key: tickets with anomalous lifetimes, accounts that never authenticated to the KDC, or a TGS request (4769) with no matching TGT request (4768). Baseline krbtgt and alert on impossible ticket properties.',
  'T1558.003': 'A burst of Kerberos service-ticket requests (event 4769) for SPN accounts, especially with RC4 encryption, from one host. Honeypot SPN accounts and RC4 downgrade alerts are the classic detections.',
  'T1558.004': 'AS-REQ activity (event 4768) for accounts with Kerberos pre-authentication disabled, yielding a crackable AS-REP. Alert on DONT_REQ_PREAUTH accounts and on AS-REP requests for them from unusual hosts.',
  'T1574': 'A program loading an attacker-controlled binary through a search-order, path, or permissions weakness. Watch for DLLs loaded from writable or unusual paths and a service resolving to an unexpected image.',
  'T1574.001': 'A process loading a DLL from a writable or non-standard directory ahead of the legitimate one (search-order or side-loading). Sysmon event 7 image loads from user-writable paths, and DLLs unsigned or mismatched to their host.',
  'T1574.009': 'A service with an unquoted ImagePath containing spaces resolving to an attacker-placed binary in a parent directory (for example C:\\Program.exe). Audit service ImagePath values and writes to the intercept location.',
  'T1574.010': 'A service whose binary or directory is writable by non-admins being replaced, then restarted as SYSTEM. Watch for writes to a service binary and a service restart tied to a permission-weak path.',
  'T1592': 'Largely external and low-signal, but internal host recon (systeminfo, hostname, OS and patch enumeration) after a foothold clusters with other discovery. Mostly a correlation, not a standalone alert.',
  'T1595': 'Port and vulnerability scanning against your perimeter: many connections across ports and hosts from one source, scanner user agents, and IDS scan signatures in firewall and NetFlow data.',
  'T1611': 'A process breaking out of a container to the host: a privileged container, a host mount, or kernel abuse. Watch container-runtime audit logs, unexpected host filesystem writes from a container, and anomalous syscalls.',
  'T1649': 'AD CS abuse: an anomalous certificate request (especially with a subjectAltName for another user), enrollment on a vulnerable template, then a logon with a certificate. Watch CA issuance events 4886/4887 and PKINIT authentications.',
  'T1003.001': 'A process opening a handle to lsass.exe to read its memory (Sysmon event 10 with a GrantedAccess like 0x1010/0x1410), a MiniDump of lsass via comsvcs.dll, or Mimikatz sekurlsa behaviour. Alert on non-system processes touching lsass.',
  'T1003.002': 'Reads of the SAM and SYSTEM registry hives, reg save of HKLM\\SAM, or a volume shadow copy created to grab them. Watch event 4656/4663 on the SAM hive and reg.exe saving protected keys.',
  'T1053.005': 'A new or changed Windows scheduled task (events 4698/4702, the Task Scheduler operational log) running an interpreter or a binary from a user-writable path. Correlate the task author with the action it runs.',
  'T1053.006': 'A new or edited systemd service or timer unit under /etc/systemd or a user unit directory, especially one with a writable ExecStart or a short OnCalendar. Monitor file writes to unit paths and systemctl daemon-reload.',
  'T1110.001': 'Online password guessing: repeated logon attempts against a service (SSH, RDP, a web login, SMB) with a wordlist, clustering of 4625 or auth.log failures from one source, then a success. Distinct from offline cracking, which leaves no auth logs.',
  'T1484': 'Changes to domain or tenant policy that widen privilege: edits to a Group Policy Object or a tenant security setting. Watch directory object-change events (5136) on policy containers and unexpected GPO links.',
  'T1484.001': 'Edits to a Group Policy Object that push a privileged action (a scheduled task, a script, a new local admin) to linked hosts. Watch event 5136 on GPO objects, changes to SYSVOL policy files, and new GPO links (5141).',
  'T1550.003': 'Authentication with a stolen or forged Kerberos ticket rather than a password: a TGS or TGT used from a host that never requested it (a 4769 with no matching 4768), or ticket lifetimes and encryption that break policy. Overpass-the-hash shows an RC4 TGT request after a hash theft.',
  'T1552.005': 'A request to the cloud instance metadata endpoint (169.254.169.254) from a workload that should not call it, often via SSRF in a web app. Watch outbound requests to the metadata IP and app logs showing a server-side fetch of that URL.',
  'T1558.002': 'A forged service ticket (TGS) encrypted with a service account or computer NTLM hash, used without a corresponding TGS request to the KDC (a service logon 4624 with no 4769). Watch for tickets whose encryption or PAC does not match a real KDC issuance.',
  'T1574.007': 'A program run with an attacker-controlled PATH so a planted binary resolves ahead of the real one, common with SUID or cron jobs that call a command by bare name. Watch execve of binaries from writable PATH entries and unexpected PATH values in service or cron context.',
  'T1021': 'A remote interactive or service logon into a host (RDP, SMB admin shares, SSH, VNC, telnet, r-services) from an unusual source or account. Watch network logons (event 4624 type 3/10), new sessions on these ports, and lateral connections that do not match normal admin paths.',
  'T1021.002': 'Remote execution over SMB admin shares (ADMIN$/C$/IPC$), the psexec/smbexec/wmiexec pattern: a service created from a remote logon, a binary written to ADMIN$, or named-pipe activity. Watch event 5145 on admin shares, 7045 service installs, and 4624 type 3 from a tooling host.',
  'T1021.005': 'A VNC session into a host, often after planting or enabling a VNC server. Watch connections on 5900-5906, a new VNC service or registry config, and an interactive session with no corresponding console logon.',
  'T1072': 'Abuse of a software deployment or patch system (WSUS, SCCM, a config-management server) to push code to many hosts. Watch for unexpected deployment packages or update approvals, and a deployment server initiating execution on endpoints out of the normal maintenance window.',
  'T1134.005': 'SID-History injected into an account so it carries the privileges of another (often across a domain or forest trust). Watch directory changes to the sIDHistory attribute (event 5136) and logons whose authorization SIDs include a privileged domain the account should not hold.',
  'T1505.001': 'Abuse of SQL stored procedures for command execution (MSSQL xp_cmdshell, extended or CLR procedures). Watch for xp_cmdshell being enabled via sp_configure, a SQL service account spawning cmd or powershell, and database audit logs showing procedure creation or execution.',
  'T1543': 'A new or modified system-level service or daemon used to run code with high privilege or at boot. Watch service creation (Windows event 7045, 4697) and new or edited unit files on Linux, especially a service whose binary sits in a writable path.',
  'T1543.003': 'A Windows service created or reconfigured to run an attacker binary as SYSTEM (sc create / config, a changed ImagePath, or a DACL edit that allows reconfiguration). Watch events 7045 and 4697, service-config changes (4670 on the service), and a service resolving to an unexpected image.',
  'T1546': 'Execution bound to a trigger so code runs when an event fires (a logon, a WMI event, a COM object load, an accessibility feature). Watch for new autostart registrations, WMI event subscriptions, and registry edits that hook an event to a command.',
  'T1546.015': 'A COM object hijacked so a program loads an attacker DLL or command when it instantiates that CLSID, often via a per-user HKCU registration that shadows the machine one. Watch registry writes to CLSID InprocServer32 keys and a trusted process loading a DLL from a user-writable path.',
};

function clean(text) {
  // Strip ATT&CK's inline citations and markdown so the detection reads as plain prose, then trim.
  let s = String(text || '');
  s = s.replace(/\(Citation:[^)]*\)/g, '');            // (Citation: ...)
  s = s.replace(/\[([^\]]+)\]\((?:https?:\/\/)?[^)]*\)/g, '$1'); // [label](url) -> label
  s = s.replace(/`([^`]*)`/g, '$1');                   // `code` -> code
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > 280) {                                // keep ~2 sentences, bounded
    const cut = s.slice(0, 280);
    const lastDot = cut.lastIndexOf('. ');
    s = (lastDot > 120 ? cut.slice(0, lastDot + 1) : cut.trimEnd() + '…');
  }
  return s;
}

function extId(obj) {
  const refs = obj.external_references || [];
  const m = refs.find(r => r.source_name === 'mitre-attack' && r.external_id);
  return m ? { id: m.external_id, url: m.url || '' } : null;
}

function main() {
  const bundle = JSON.parse(fs.readFileSync(SRC, 'utf8'));
  const objs = bundle.objects || [];
  const byRef = {};
  objs.forEach(o => { if (o.id) byRef[o.id] = o; });

  // version
  const coll = objs.find(o => o.type === 'x-mitre-collection');
  const version = (coll && coll.x_mitre_version) || 'enterprise';

  // tactics in matrix order (from the x-mitre-matrix tactic_refs)
  const matrix = objs.find(o => o.type === 'x-mitre-matrix');
  const tacticObjs = {};
  objs.filter(o => o.type === 'x-mitre-tactic').forEach(t => { tacticObjs[t.id] = t; });
  let tactics = [];
  if (matrix && Array.isArray(matrix.tactic_refs)) {
    tactics = matrix.tactic_refs.map(ref => tacticObjs[ref]).filter(Boolean)
      .map(t => ({ id: t.x_mitre_shortname, name: t.name }));
  }

  // mitigations: course-of-action (Mxxxx) + 'mitigates' relationships -> technique
  const mitName = {};   // coa stix id -> mitigation name
  objs.filter(o => o.type === 'course-of-action').forEach(c => { if (c.id) mitName[c.id] = c.name; });
  const techMit = {};   // technique stix id -> [mitigation names]
  objs.filter(o => o.type === 'relationship' && o.relationship_type === 'mitigates').forEach(r => {
    if (mitName[r.source_ref] && r.target_ref) {
      (techMit[r.target_ref] = techMit[r.target_ref] || []).push(mitName[r.source_ref]);
    }
  });

  // techniques
  const techniques = {};
  objs.filter(o => o.type === 'attack-pattern' && !o.revoked && !o.x_mitre_deprecated).forEach(ap => {
    const ext = extId(ap);
    if (!ext) return;
    const id = ext.id;
    const ta = (ap.kill_chain_phases || [])
      .filter(k => k.kill_chain_name === 'mitre-attack')
      .map(k => k.phase_name);
    const sub = !!ap.x_mitre_is_subtechnique;
    const parent = sub && id.indexOf('.') >= 0 ? id.split('.')[0] : '';
    const mit = (techMit[ap.id] || []).slice().sort();
    const rec = { n: ap.name, ta: ta };
    if (sub) { rec.sub = 1; rec.p = parent; }
    // Prefer ATT&CK's own detection text; fall back to an obol-authored blurb where it ships none.
    const det = clean(ap.x_mitre_detection) || clean(DET_OVERRIDES[id]);
    if (det) rec.det = det;
    const ds = (ap.x_mitre_data_sources || []).map(d => String(d).split(':')[0].trim())
      .filter((v, i, a) => v && a.indexOf(v) === i);
    if (ds.length) rec.ds = ds;
    if (mit.length) rec.mit = mit;
    if (ext.url) rec.url = ext.url;
    techniques[id] = rec;
  });

  const count = Object.keys(techniques).length;
  const header = '/*!\n'
    + ' * data/attack-catalog.js — compact MITRE ATT&CK Enterprise catalog for the Frameworks view.\n'
    + ' * GENERATED by tools/build-attack.js from the ATT&CK STIX bundle. Do not hand-edit.\n'
    + ' * ATT&CK (C) The MITRE Corporation, used under the ATT&CK Terms of Use\n'
    + ' * (https://attack.mitre.org/resources/terms-of-use/). ATT&CK v' + version + '.\n'
    + ' * Where a technique carries no ATT&CK detection text, the `det` field holds an obol-authored\n'
    + ' * blue-team detection blurb (see DET_OVERRIDES in tools/build-attack.js), not MITRE content.\n'
    + ' */\n';
  const body = '(function (root) {\n  "use strict";\n  var OBOL = root.OBOL = root.OBOL || {};\n'
    + '  OBOL.ATTACK = {\n'
    + '    version: ' + JSON.stringify(version) + ',\n'
    + '    tactics: ' + JSON.stringify(tactics) + ',\n'
    + '    techniques: ' + JSON.stringify(techniques) + '\n'
    + '  };\n'
    + '  if (typeof module !== "undefined" && module.exports) { module.exports = OBOL.ATTACK; }\n'
    + '})(typeof globalThis !== "undefined" ? globalThis : this);\n';
  fs.writeFileSync(OUT, header + body);
  const kb = (fs.statSync(OUT).size / 1024).toFixed(0);
  console.log('wrote', OUT, '(' + kb + ' KB)');
  console.log('ATT&CK v' + version + ': ' + tactics.length + ' tactics, ' + count + ' techniques');
  console.log('tactics:', tactics.map(t => t.id).join(', '));
}

main();
