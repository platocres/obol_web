/*!
 * data/attack-move-map.js — MITRE ATT&CK technique maps for the Frameworks view. Two tables:
 *
 *   BY_KIND (fact-kind -> technique): the fact that PROVES a step maps to the technique. Powers
 *     (1) the recorded-moves trail (a Run Log activity's produced kinds light the matrix) and
 *     (2) finding gap-fill (a matched finding with no authored `attack` derives one from its trigger).
 *     Produce-side semantics: good for "a technique was performed here."
 *
 *   BY_MOVE (move-id -> technique): the ACT a move embodies, which the fact-kind map cannot always
 *     name (an exploitation or privesc move produces a generic access.* fact; a lateral move and a
 *     credential-dumping move can share a fact but are different techniques). This is what powers the
 *     example-command feature (a grayed cell shows the obol command that would perform the technique)
 *     and sharpens the recorded-moves trail (running password-spray lights T1110.003, not just T1078).
 *     BY_MOVE WINS over BY_KIND for a move it names. Advice/troubleshooter moves are deliberately left
 *     out (they perform no technique).
 *
 * Conservative and standard; omit where a map would be a guess. Hand-authored; extend as the pack
 * grows (tools/attack-coverage.js reports the gaps). ATT&CK (C) The MITRE Corporation.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var BY_KIND = {
    // recon / discovery
    'host.up': 'T1046', 'ports.open': 'T1046', 'scan.nmap.quick': 'T1046', 'scan.nmap.version': 'T1046',
    'scan.masscan': 'T1046', 'snmp.community': 'T1046',
    'smb.null_session': 'T1135', 'smb.guest_session': 'T1135', 'smb.shares': 'T1135',
    'ad.user_list': 'T1087.002', 'ad.users': 'T1087.002', 'rid.users': 'T1087.002', 'ad.anonymous_bind': 'T1087.002',
    'web.source': 'T1592', 'web.dirs': 'T1595', 'web.vhosts': 'T1595',
    'host.processes': 'T1057', 'privesc.process_lead': 'T1057',
    // exploit / execution (public-facing app and injection classes)
    'web.sqli_confirmed': 'T1190', 'web.cmdi_confirmed': 'T1190', 'web.ssti_confirmed': 'T1190',
    'web.xxe_confirmed': 'T1190', 'web.nosqli_confirmed': 'T1190', 'web.deserial_confirmed': 'T1190',
    'web.lfi_confirmed': 'T1190', 'web.rce': 'T1190', 'web.authz_bypass': 'T1190', 'exploit.candidate': 'T1190',
    'access.shell': 'T1059', 'foothold.shell': 'T1059', 'web.shell': 'T1505.003',
    // credential access
    'hash.ntlm': 'T1003', 'credential.ntlm_hash': 'T1003', 'loot.sam': 'T1003',
    'loot.ntds': 'T1003.006', 'hash.krbtgt': 'T1003.006', 'ad.dcsync': 'T1003.006',
    'hash.asrep': 'T1558.004', 'hash.kerberoast': 'T1558.003', 'hash.tgs': 'T1558.003',
    'credential.weak_hash': 'T1110.002',
    'credential.plaintext': 'T1078', 'credential.available': 'T1078', 'credential.validated': 'T1078',
    'gpp.cpassword': 'T1552.006', 'loot.gpp': 'T1552.006', 'privesc.stored_credentials': 'T1552.001',
    'loot.ssh_key': 'T1552.004', 'loot.creds': 'T1552.001',
    // AD escalation
    'adcs.vulnerable': 'T1649', 'credential.certificate': 'T1649',
    'ad.control_paths': 'T1098', 'ad.attack_paths': 'T1098', 'ad.acl_lead': 'T1098', 'ad.gpo_control': 'T1098',
    'ad.zerologon': 'T1210', 'ad.coerced_auth': 'T1557.001',
    // privilege escalation
    'privesc.sudo_rights': 'T1548.003', 'privesc.sudo_binary': 'T1548.003',
    'privesc.suid_candidate': 'T1548.001', 'privesc.capability': 'T1548',
    'privesc.cron_writable': 'T1053.003',
    'privesc.kernel': 'T1068', 'privesc.patch_gap': 'T1068', 'privesc.service_bof_candidate': 'T1068',
    'privesc.nfs_no_root_squash': 'T1068',
    'privesc.dll_hijack_candidate': 'T1574.001', 'privesc.unquoted_service_path': 'T1574.009',
    'privesc.always_install_elevated': 'T1548.002',
    'privesc.docker_group': 'T1611', 'privesc.lxd_group': 'T1611',
    'privesc.windows_privilege': 'T1134.001',
    // lateral / relay
    'smb.signing_disabled': 'T1557.001', 'relay.target': 'T1557.001',
  };

  // move id -> the ATT&CK technique that move's action embodies (wins over BY_KIND for named moves).
  var BY_MOVE = {
    // discovery (moves whose produced kind is not itself in BY_KIND)
    'content-discovery': 'T1595', 'vhost-discovery': 'T1595',
    // credential access: cracking is T1110.002 (offline); on-box dumping names its sub-technique
    'crack-asrep': 'T1110.002', 'crack-tgs': 'T1110.002', 'crack-kerberoast': 'T1110.002',
    'crack-asrep-offline': 'T1110.002', 'crack-ntlm': 'T1110.002', 'crack-netntlmv2': 'T1110.002',
    'crack-shadow': 'T1110.002', 'crack-archive': 'T1110.002', 'crack-mscache2': 'T1110.002',
    'lsass-dump-onbox': 'T1003.001', 'windows-old-hives': 'T1003.002', 'gpp-passwords': 'T1552.006',
    // online brute / spray
    'password-spray': 'T1110.003', 'web-login-brute': 'T1110.001',
    'online-brute-ssh': 'T1110.001', 'online-brute-ftp': 'T1110.001', 'online-brute-rdp': 'T1110.001',
    'blind-brute-ssh': 'T1110.001',
    // alternate auth material + Kerberos ticket forging
    'own-domain-pth': 'T1550.002', 'ticket-reuse': 'T1550.003',
    'golden-ticket': 'T1558.001', 'silver-ticket': 'T1558.002', 'diamond-ticket': 'T1558',
    'getst-impersonation': 'T1558',
    // coercion / relay
    'coerce-auth': 'T1557.001', 'ntlm-relay-attack': 'T1557.001', 'kerberos-relay': 'T1557.001',
    // AD escalation / domain policy
    'gpo-abuse': 'T1484.001', 'dnsadmins-abuse': 'T1574.001',
    // cloud credential (SSRF to metadata)
    'azure-imds': 'T1552.005', 'gcp-metadata': 'T1552.005',
    // Linux privilege escalation
    'suid-gtfobins': 'T1548.001', 'nfs-squash': 'T1548.001',
    'sudo-abuse': 'T1548.003', 'linux-ld-preload': 'T1548.003',
    'linux-path-hijack': 'T1574.007', 'cron-abuse': 'T1053.003', 'systemd-timer-abuse': 'T1053.006',
    'docker-socket': 'T1611', 'lxc-lxd-escape': 'T1611',
    'linux-kernel-exploit': 'T1068', 'baron-samedit': 'T1068',
    // Windows privilege escalation
    'seimpersonate': 'T1134.001', 'windows-namedpipe-impersonation': 'T1134.001',
    'unquoted-service-path': 'T1574.009', 'weak-service-permissions': 'T1574.010',
    'windows-dll-hijack': 'T1574.001', 'windows-schtask-abuse': 'T1053.005',
    'windows-patch-exploit': 'T1068',
    // web shells (planting a shell on a server) + remote-service hop
    'web-shells': 'T1505.003', 'http-put-webshell': 'T1505.003', 'ftp-upload-webshell': 'T1505.003',
    'tomcat-deploy': 'T1505.003', 'proftpd-modcopy': 'T1505.003', 'ajp-ghostcat': 'T1505.003',
    'mssql-linked-server': 'T1210',
    // public-facing web app exploitation
    'authz-abuse': 'T1190', 'deserialization': 'T1190', 'drupalgeddon2': 'T1190', 'file-upload': 'T1190',
    'manual-sqli-exploitation': 'T1190', 'ofbiz-deser': 'T1190', 'phpmyadmin-lfi': 'T1190',
    'sqlmap-automation': 'T1190', 'verb-tampering': 'T1190', 'zabbix-script-rce': 'T1190',
    // remote-service exploitation (network / DB / RPC RCE)
    'aerospike-udf': 'T1210', 'bluekeep': 'T1210', 'eternalblue': 'T1210', 'elasticsearch-rce': 'T1210',
    'freeswitch-esl': 'T1210', 'jdwp-debug': 'T1210', 'jenkins-access': 'T1210', 'oracle-rce': 'T1210',
    'postgres-rce': 'T1210', 'printnightmare': 'T1210', 'smbghost': 'T1210', 'splunk-app-rce': 'T1210',
    'wifi-mouse-rce': 'T1210', 'mysql-outfile-rce': 'T1210', 'nfs-to-foothold': 'T1210',
    'mssql-xp-cmdshell': 'T1505.001',
    // Linux local privilege-escalation exploits + container escape
    'dirtycow': 'T1068', 'dirtypipe': 'T1068', 'polkit-abuse': 'T1068', 'container-escape': 'T1611',
    'capabilities': 'T1548', 'python-library-hijack': 'T1574',
    // Windows elevation + service abuse + COM
    'uac-bypass': 'T1548.002', 'alwaysinstallelevated': 'T1548.002',
    'windows-service-dacl-abuse': 'T1543.003', 'com-hijack': 'T1546.015',
    // lateral movement + remote-service logins
    'lateral-exec': 'T1021.002', 'telnet-login': 'T1021', 'rservices-login': 'T1021', 'vnc-desktop-shell': 'T1021.005',
    // AD delegation / Kerberos forgery / cross-forest + deployment-tool abuse
    'unconstrained-delegation': 'T1558', 'ms14-068': 'T1558', 'sid-history-abuse': 'T1134.005', 'wsus-abuse': 'T1072',
  };

  OBOL.ATTACK_MOVE = { byKind: BY_KIND, byMove: BY_MOVE };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.ATTACK_MOVE; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
