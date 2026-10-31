/*!
 * data/attack-move-map.js - MITRE ATT&CK technique maps for the Frameworks view. Three tables:
 *
 *   BY_KIND (fact-kind -> technique): the fact that PROVES a step maps to the technique. Powers
 *     (1) the recorded-moves trail fallback and (2) finding gap-fill (a matched finding with no authored
 *     `attack` derives one from its trigger).
 *
 *   BY_MOVE (move-id -> technique): the ACT a move embodies across all non-advice pack moves.
 *     Powers example-command lookup on unused OBOL cells and guarantees every executed move lights its
 *     exact ATT&CK technique rather than collapsing into a generic produced-fact bucket.
 *     Advice/troubleshooter moves (producing only advice.*) are deliberately excluded.
 *
 *   BY_CMD (ordered [pattern, technique] signatures): deterministic command-line fallback when an operator
 *     uses global Paste without a Cockpit move `action_id` (so `nxc ldap --kerberoasting` resolves directly
 *     to T1558.003 instead of bleeding across incidental discovery/auth facts).
 *
 * ATT&CK (C) The MITRE Corporation.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  var BY_KIND = {
    // recon / discovery
    'host.up': 'T1046', 'ports.open': 'T1046', 'scan.nmap.quick': 'T1046', 'scan.nmap.version': 'T1046',
    'scan.masscan': 'T1046', 'snmp.community': 'T1046', 'scan.nmap.vuln': 'T1595.002', 'scan.nmap.udp': 'T1046',
    'dns.zone': 'T1590.002', 'dns.a_record': 'T1590.002', 'dns.email': 'T1590.002', 'dns.takeover': 'T1584.001',
    'scan.local.dns': 'T1016', 'scan.local.listeners': 'T1049',
    'scan.local.interfaces': 'T1016', 'scan.local.routes': 'T1016', 'scan.local.neighbors': 'T1016',
    'smb.null_session': 'T1135', 'smb.guest_session': 'T1135', 'smb.shares': 'T1135', 'smb.ms17_010': 'T1210',
    'ad.user_list': 'T1087.002', 'ad.users': 'T1087.002', 'rid.users': 'T1087.002', 'ad.anonymous_bind': 'T1087.002',
    'ad.dc_candidate': 'T1018', 'ad.trusts': 'T1482', 'ad.deleted_objects': 'T1087.002',
    'web.source': 'T1592', 'web.tech': 'T1592.002', 'web.server': 'T1592.002',
    'web.dirs': 'T1595.003', 'web.vhosts': 'T1595.003', 'web.param_candidate': 'T1595.003',
    'http.headers': 'T1592.002', 'http.methods': 'T1595.002', 'http.cors': 'T1595.002',
    'http.body': 'T1592.002', 'http.exposed': 'T1595.003', 'http.redirect': 'T1592.002', 'tls.info': 'T1592.002',
    'vuln.candidates': 'T1595.002', 'defense.control': 'T1518.001',
    'host.processes': 'T1057', 'privesc.process_lead': 'T1057',
    'host.kernel': 'T1082', 'host.arch': 'T1082',
    'loot.files': 'T1083', 'loot.material': 'T1005',
    // exploit / execution (public-facing app and injection classes)
    'web.sqli_confirmed': 'T1190', 'web.cmdi_confirmed': 'T1190', 'web.ssti_confirmed': 'T1190',
    'web.xxe_confirmed': 'T1190', 'web.nosqli_confirmed': 'T1190', 'web.deserial_confirmed': 'T1190',
    'web.lfi_confirmed': 'T1190', 'web.rce': 'T1190', 'web.authz_bypass': 'T1190',
    'web.idor_candidate': 'T1190', 'exploit.candidate': 'T1190',
    'access.shell': 'T1059', 'foothold.shell': 'T1059', 'web.shell': 'T1505.003', 'foothold.webshell': 'T1505.003',
    // credential access
    'hash.ntlm': 'T1003', 'credential.ntlm_hash': 'T1003', 'loot.sam': 'T1003.002', 'loot.shadow': 'T1003.008',
    'loot.ntds': 'T1003.006', 'hash.krbtgt': 'T1003.006', 'ad.dcsync': 'T1003.006',
    'hash.asrep': 'T1558.004', 'hash.kerberoast': 'T1558.003', 'hash.tgs': 'T1558.003',
    'hash.ike_psk': 'T1110.002', 'credential.weak_hash': 'T1110.002',
    'credential.plaintext': 'T1078', 'credential.available': 'T1078', 'credential.validated': 'T1078',
    'gpp.cpassword': 'T1552.006', 'loot.gpp': 'T1552.006', 'privesc.stored_credentials': 'T1552.001',
    'loot.ssh_key': 'T1552.004', 'loot.creds': 'T1552.001', 'credential.candidate': 'T1552',
    'kerberos.tickets': 'T1558',
    // AD escalation
    'adcs.vulnerable': 'T1649', 'credential.certificate': 'T1649',
    'ad.control_paths': 'T1098', 'ad.attack_paths': 'T1098', 'ad.acl_lead': 'T1098', 'ad.gpo_control': 'T1484.001',
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
    // lateral / relay / collection / C2
    'smb.signing_disabled': 'T1557.001', 'relay.target': 'T1557.001',
    'objective.local_flag': 'T1005', 'objective.root_flag': 'T1005',
    'tunnel.socks': 'T1090.001', 'tunnel.route': 'T1090', 'tunnel.dns': 'T1071.004',
  };

  // move id -> exact ATT&CK technique across all 337 non-advice pack moves (wins over BY_KIND).
  var BY_MOVE = {
    // ── Reconnaissance & Active Scanning ──────────────────────────────────────────────────────
    'nmap-fast-open-ports': 'T1046', 'nmap-version-scripts': 'T1046', 'nmap-udp-top': 'T1046',
    'nmap-host-unresponsive': 'T1046', 'nmap-vuln-scripts': 'T1595.002', 'nikto-scan': 'T1595.002',
    'content-discovery': 'T1595', 'vhost-discovery': 'T1595', 'param-discovery': 'T1595.003',
    'recon-dns': 'T1590.002', 'check-dns-email': 'T1590.002', 'check-subdomain-takeover': 'T1584.001',
    'recon-web-triage': 'T1592.002', 'http3-quic-probe': 'T1595.002',
    'check-web-headers': 'T1592.002', 'check-web-components': 'T1592.002', 'check-cms-version': 'T1592.002',
    'check-tls-config': 'T1592.002', 'check-http-methods': 'T1595.002', 'check-cors': 'T1595.002',
    'check-web-body': 'T1592.002', 'check-exposed-files': 'T1595.003', 'check-http-redirect': 'T1592.002',
    'recon-smb-anon': 'T1135', 'smb-share-inventory': 'T1135', 'smb-share-browse-download': 'T1039',
    'nfs-enum': 'T1135', 'recon-rsync': 'T1135', 'recon-ftp': 'T1083', 'recon-tftp': 'T1083',
    'recon-snmp': 'T1046', 'recon-finger': 'T1087', 'recon-smtp': 'T1087', 'ssh-user-enum': 'T1087',
    'recon-mail': 'T1046', 'recon-telnet': 'T1046', 'recon-rservices': 'T1021',
    'recon-vnc': 'T1021.005', 'rdp-enum': 'T1021.001', 'recon-ike-vpn': 'T1595.002',
    'recon-x11': 'T1113', 'x11-keylog': 'T1056.001',
    'smtp-open-relay': 'T1595.002', 'ftp-bounce': 'T1090', 'smbv1-vuln-verify': 'T1595.002',
    'git-exposed': 'T1213.003', 'svn-exposed': 'T1213.003',

    // ── Active Directory Discovery, Credential Access & Escalation ────────────────────────────
    'ad-dc-identify': 'T1018', 'ad-anon-ldap-enum': 'T1087.002', 'ldap-deep-enum': 'T1087.002',
    'ad-user-enum': 'T1087.002', 'fix-samr-null-denied': 'T1087.002', 'ad-recycle-bin-enum': 'T1087.002',
    'bloodhound-collect': 'T1087.002', 'ad-path-manual': 'T1069.002',
    'powerview-enum': 'T1087.002', 'ad-legacy-enum': 'T1087.002', 'ad-psdotnet-enum': 'T1087.002',
    'trust-enum': 'T1482', 'nxc-arsenal': 'T1135',
    'asrep-roast': 'T1558.004', 'kerberoast': 'T1558.003', 'timeroasting': 'T1110.002',
    'kerberos-tickets': 'T1558', 'golden-ticket': 'T1558.001', 'silver-ticket': 'T1558.002',
    'diamond-ticket': 'T1558', 'getst-impersonation': 'T1558', 'delegation-abuse': 'T1558',
    'unconstrained-delegation': 'T1558', 'ms14-068': 'T1558',
    'own-domain-pth': 'T1550.002', 'ticket-reuse': 'T1550.003', 'cert-authenticate': 'T1649',
    'adcs-esc': 'T1649', 'shadow-credentials': 'T1649', 'certifried': 'T1649',
    'dcsync': 'T1003.006', 'dump-secrets': 'T1003.003', 'azuread-connect-dump': 'T1003',
    'gpp-passwords': 'T1552.006', 'gmsa-read': 'T1552', 'laps-read': 'T1552',
    'spider-secrets': 'T1039', 'remote-app-creds': 'T1555',
    'ad-acl-abuse': 'T1098', 'bloodyad-acl': 'T1098', 'fix-acl-reauth': 'T1098',
    'gpo-abuse': 'T1484.001', 'dnsadmins-abuse': 'T1574.001', 'sid-history-abuse': 'T1134.005',
    'zerologon-check': 'T1595.002', 'zerologon-exploit': 'T1068', 'nopac': 'T1068',
    'wsus-abuse': 'T1072', 'sccm-enum': 'T1072', 'sccm-exploit': 'T1072',
    'responder-poison': 'T1557.001', 'mitm6-ipv6-takeover': 'T1557.001', 'adidns-abuse': 'T1557.001',
    'coerce-auth': 'T1557.001', 'rpc-endpoint-abuse': 'T1557.001',
    'ntlm-relay-attack': 'T1557.001', 'kerberos-relay': 'T1557.001',

    // ── Cracking, Brute Force & Credential Validation ─────────────────────────────────────────
    'crack-identify': 'T1110.002', 'crack-asrep': 'T1110.002', 'crack-tgs': 'T1110.002',
    'crack-kerberoast': 'T1110.002', 'crack-asrep-offline': 'T1110.002', 'crack-ntlm': 'T1110.002',
    'crack-netntlmv2': 'T1110.002', 'crack-shadow': 'T1110.002', 'crack-archive': 'T1110.002',
    'crack-mscache2': 'T1110.002', 'crack-modular-hash': 'T1110.002', 'gpg-private-key-decrypt': 'T1552.004',
    'vnc-decrypt': 'T1555', 'cisco-decrypt': 'T1552.001', 'keepass-dump-recover': 'T1555.005',
    'ipmi-bmc-cipher0': 'T1110.002', 'snmp-process-cmdline-harvest': 'T1552',
    'password-spray': 'T1110.003', 'web-login-brute': 'T1110.001',
    'online-brute-ssh': 'T1110.001', 'online-brute-ftp': 'T1110.001', 'online-brute-rdp': 'T1110.001',
    'blind-brute-ssh': 'T1110.001',
    'validate-credential': 'T1078', 'cred-reuse-sweep': 'T1078',

    // ── Database Access, Loot & RCE ───────────────────────────────────────────────────────────
    'mysql-login': 'T1078', 'mssql-login': 'T1078', 'postgres-login': 'T1078', 'oracle-tns': 'T1046',
    'mysql-loot': 'T1213', 'redis-enum': 'T1213', 'mongo-enum': 'T1213',
    'elasticsearch-enum': 'T1213', 'memcached-enum': 'T1213',
    'sqlite-table-extract': 'T1005', 'access-db-export': 'T1005', 'ole-macro-analysis': 'T1552.001',
    'adminer-mysql-fileread': 'T1190', 'nosqli-regex-extract': 'T1190',
    'mssql-xp-cmdshell': 'T1505.001', 'mssql-linked-server': 'T1210',
    'mysql-outfile-rce': 'T1210', 'postgres-rce': 'T1210', 'oracle-rce': 'T1210', 'oracle-tns-odat-rce': 'T1190',
    'redis-rogue-server-rce': 'T1190', 'h2-database-console-rce': 'T1190',
    'aerospike-udf': 'T1210', 'aerospike-udf-rce': 'T1190', 'elasticsearch-rce': 'T1210',

    // ── Public-Facing Web Exploitation & Web Shells ───────────────────────────────────────────
    'lfi-probe': 'T1190', 'lfi-secret-harvest': 'T1552.001', 'nginx-log-poisoning-lfi': 'T1190',
    'phpmyadmin-lfi': 'T1190', 'sqli-basics': 'T1190', 'manual-sqli-exploitation': 'T1190',
    'sqlmap-automation': 'T1190', 'nosql-injection': 'T1190', 'command-injection': 'T1190',
    'ssti': 'T1190', 'ssti-to-rce': 'T1190', 'xxe': 'T1190', 'ssrf': 'T1190',
    'deserialization': 'T1190', 'myfaces-viewstate-deserialization-rce': 'T1190',
    'node-serialize-rce': 'T1190', 'jackson-databind-rce': 'T1190', 'ofbiz-deser': 'T1190',
    'idor': 'T1190', 'idor-harvest': 'T1213', 'authz-abuse': 'T1190', 'verb-tampering': 'T1190',
    'jwt-attacks': 'T1190', 'xss-basics': 'T1190', 'pdf-export-xss-fileread': 'T1190',
    'graphql-abuse': 'T1190', 'http-request-smuggling': 'T1190', 'http-request-smuggling-auth': 'T1190',
    'prototype-pollution': 'T1190', 'mass-assignment': 'T1190', 'wordpress': 'T1190',
    'file-upload': 'T1190', 'web-shells': 'T1505.003', 'http-put-webshell': 'T1505.003',
    'ftp-upload-webshell': 'T1505.003', 'ftp-webroot-upload-webshell': 'T1505.003',
    'web-config-upload-bypass': 'T1505.003', 'nibbleblog-myimage-upload-rce': 'T1505.003',
    'gitlab-ci-webshell': 'T1505.003', 'coldfusion-scheduled-task-rce': 'T1505.003',
    'tomcat-deploy': 'T1505.003', 'proftpd-modcopy': 'T1505.003', 'ajp-ghostcat': 'T1505.003',
    'tftp-write-shell': 'T1505.003',
    'azure-imds': 'T1552.005', 'gcp-metadata': 'T1552.005', 'aws-credential-abuse': 'T1078.004',

    // ── Known Network / Application CVEs & Service RCE ────────────────────────────────────────
    'drupalgeddon2': 'T1190', 'zabbix-script-rce': 'T1190', 'zabbix-agent-system-run': 'T1190',
    'pfsense-rrd-rce': 'T1190', 'solr-velocity-template-rce': 'T1190', 'iis6-webdav-scstorage': 'T1190',
    'rejetto-hfs-rce': 'T1190', 'prtg-notification-rce': 'T1190', 'amportal-conf-leak': 'T1552.001',
    'jenkins-cli-fileread': 'T1190', 'jenkins-access': 'T1210', 'activemq-cve-2023-46604': 'T1190',
    'nvms1000-traversal': 'T1190', 'exiftool-cve-2021-22204': 'T1190', 'php-backdoor-useragent': 'T1190',
    'opennetadmin-rce': 'T1190', 'nostromo-rce': 'T1190', 'usermin-auth-rce': 'T1190', 'usermin-rce': 'T1190',
    'webmin-rce': 'T1190', 'cacti-cmdinjection': 'T1190', 'check-log4shell': 'T1190',
    'check-struts2': 'T1190', 'shellshock': 'T1190', 'text4shell': 'T1190',
    'heartbleed': 'T1190', 'heartbleed-memory-leak': 'T1190', 'java-rmi': 'T1190',
    'bluekeep': 'T1210', 'eternalblue': 'T1210', 'printnightmare': 'T1210', 'smbghost': 'T1210',
    'freeswitch-esl': 'T1210', 'jdwp-debug': 'T1210', 'splunk-app-rce': 'T1210', 'wifi-mouse-rce': 'T1210',
    'nfs-to-foothold': 'T1210', 'gdbserver-remote-execution': 'T1190', 'unrealircd-backdoor': 'T1190',
    'vsftpd-backdoor': 'T1190', 'samba-usermap': 'T1210', 'samba-usermap-script-rce': 'T1210',
    'sireprat-iot-exec': 'T1190',

    // ── Shells, Remote Access & Lateral Movement ──────────────────────────────────────────────
    'shell-listener': 'T1059', 'shell-revshell-linux': 'T1059.004', 'shell-revshell-windows': 'T1059.001',
    'win-interactive-shell': 'T1021.002', 'lateral-exec': 'T1021.002',
    'ssh-key-login': 'T1021.004', 'linux-remote-exec': 'T1021.004',
    'telnet-login': 'T1021', 'rservices-login': 'T1021', 'vnc-desktop-shell': 'T1021.005',
    'rsync-write-shell': 'T1098.004',

    // ── Linux Privilege Escalation, Loot & Persistence ────────────────────────────────────────
    'linux-enum': 'T1082', 'pspy-monitor': 'T1057', 'linux-loot-hunt': 'T1552.001',
    'git-repo-forensics': 'T1552.001', 'linux-root-cred-harvest': 'T1003.008',
    'suid-gtfobins': 'T1548.001', 'nfs-squash': 'T1548.001', 'screen-suid-privesc': 'T1548.001',
    'sudo-abuse': 'T1548.003', 'linux-ld-preload': 'T1548.003', 'npm-package-privesc': 'T1548.003',
    'capabilities': 'T1548', 'gnu-screen-root-attach': 'T1548',
    'linux-path-hijack': 'T1574.007', 'python-library-hijack': 'T1574',
    'linux-shared-library-hijack': 'T1574.006',
    'cron-abuse': 'T1053.003', 'wildcard-injection': 'T1053.003', 'wildcard-symlink-privesc': 'T1053.003',
    'chkrootkit-local-privesc': 'T1053.003', 'systemd-timer-abuse': 'T1053.006',
    'docker-socket': 'T1611', 'lxc-lxd-escape': 'T1611', 'lxd-container-privesc': 'T1611',
    'container-escape': 'T1611',
    'linux-kernel-exploit': 'T1068', 'baron-samedit': 'T1068', 'dirtycow': 'T1068',
    'dirtypipe': 'T1068', 'polkit-abuse': 'T1068', 'jdwp-local-privesc': 'T1068',
    'writable-passwd': 'T1136.001', 'writable-etc-shadow-sudoers': 'T1548.003',
    'linux-persistence': 'T1098.004',

    // ── Windows Privilege Escalation, Loot & Persistence ──────────────────────────────────────
    'windows-enum': 'T1082', 'defense-enum': 'T1518.001', 'wesng-patch-gaps': 'T1068',
    'lsass-dump-onbox': 'T1003.001', 'windows-old-hives': 'T1003.002',
    'vhd-mount-sam-extract': 'T1003.002', 'sebackup-serestore-abuse': 'T1003.002',
    'dpapi-secrets': 'T1555.004', 'stored-credentials': 'T1552.001',
    'wsl-bash-enum': 'T1552.001', 'prtg-config-extract': 'T1552.001',
    'runas-savedcred-exec': 'T1555.004', 'chm-payload-exec': 'T1218.001',
    'nsclient-web-privesc': 'T1068', 'windows-patch-exploit': 'T1068',
    'seimpersonate': 'T1134.001', 'windows-namedpipe-impersonation': 'T1134.001',
    'uac-bypass': 'T1548.002', 'alwaysinstallelevated': 'T1548.002',
    'unquoted-service-path': 'T1574.009', 'weak-service-permissions': 'T1574.010',
    'windows-dll-hijack': 'T1574.001', 'windows-service-dacl-abuse': 'T1543.003',
    'windows-schtask-abuse': 'T1053.005', 'com-hijack': 'T1546.015',
    'windows-persistence': 'T1136.001',

    // ── Post-Exploitation Collection, Local Network Discovery & Pivoting ──────────────────────
    'flag-hunt-linux': 'T1005', 'flag-hunt-root-linux': 'T1005',
    'flag-hunt-windows': 'T1005', 'flag-hunt-root-windows': 'T1005',
    'post-proof-loot-sweep': 'T1005',
    'local-linux-interfaces': 'T1016', 'local-linux-routes': 'T1016', 'local-linux-neighbors': 'T1016',
    'local-linux-dns': 'T1016', 'local-windows-interfaces': 'T1016', 'local-windows-routes': 'T1016',
    'local-windows-neighbors': 'T1016', 'local-windows-listeners': 'T1049',
    'ligolo-tunnel-pivot': 'T1090', 'pivot-ligolo': 'T1090', 'pivot-sshuttle': 'T1090',
    'pivot-ssh-portforward': 'T1090', 'pivot-chisel-socks': 'T1090.001', 'pivot-ssh-dynamic': 'T1090.001',
    'dns-tunnel': 'T1071.004',
    'pivot-scan-through': 'T1046', 'pivot-enumerate-neighbors': 'T1046', 'pivot-reach-listener': 'T1090',
    'pivot-internal-dns': 'T1018',
  };

  // Ordered command-line regex fallback for global pastes where `act.action_id` is empty.
  // Specific offensive acts come before general tool names so `nxc ldap --kerberoasting` resolves
  // to T1558.003 rather than falling back to incidental discovery/auth facts.
  var BY_CMD = [
    [/--kerberoast(?:ing)?\b|GetUserSPNs|Invoke-Kerberoast|\brubeus\b.*\bkerberoast/i, 'T1558.003'],
    [/--asreproast\b|GetNPUsers|\brubeus\b.*\basreproast/i, 'T1558.004'],
    [/\bgpp-decrypt\b|\bcpassword\b|Groups\.xml|Services\.xml|ScheduledTasks\.xml|DataSources\.xml/i, 'T1552.006'],
    [/secretsdump\b.*(?:-just-dc|-dc-ip|ntds)|--ntds\b|lsadump::dcsync/i, 'T1003.006'],
    [/\b(?:procdump|comsvcs\.dll|sekurlsa|pypykatz|nanodump)\b|lsass\.dmp|--lsa\b/i, 'T1003.001'],
    [/\breg(?:\.exe)?\s+save\b.*\b(?:sam|system)\b|--sam\b/i, 'T1003.002'],
    [/\bsecretsdump\b/i, 'T1003'],
    [/\b(?:bloodhound-python|bloodhound-ce|sharphound|rusthound)\b/i, 'T1087.002'],
    [/\b(?:certipy|certify|pywhisker)\b/i, 'T1649'],
    [/\b(?:bloodyad|dacledit|owneredit)\b/i, 'T1098'],
    [/\b(?:responder|ntlmrelayx|mitm6|petitpotam|coercer|printerbug)\b/i, 'T1557.001'],
    [/\b(?:hashcat|john)\b/i, 'T1110.002'],
    [/\bkerbrute\b.*\b(?:passwordspray|spray)\b|--no-bruteforce\b.*users\.txt/i, 'T1110.003'],
    [/\b(?:hydra|medusa|ncrack|crowbar)\b/i, 'T1110.001'],
    [/\bkerbrute\b|\brpcclient\b.*enumdomusers|\bldapsearch\b/i, 'T1087.002'],
    [/\b(?:impacket-)?(?:psexec|smbexec)\b/i, 'T1021.002'],
    [/\b(?:impacket-)?(?:wmiexec|dcomexec)\b/i, 'T1047'],
    [/\bevil-winrm\b|\bnxc\s+winrm\b/i, 'T1021.006'],
    [/\b(?:xfreerdp3?|rdesktop|mstsc)\b|\bnxc\s+rdp\b/i, 'T1021.001'],
    [/\b(?:smbclient|smbmap)\b|\bnxc\s+smb\b.*--shares\b/i, 'T1135'],
    [/\bnxc\s+(?:smb|winrm|ldap|mssql|ssh)\b.*(?:-H\s|--hashes\s)/i, 'T1550.002'],
    [/\b(?:ffuf|gobuster|feroxbuster|dirsearch|wfuzz|arjun)\b/i, 'T1595.003'],
    [/\b(?:nikto|nuclei|wpscan)\b|\bnmap\b.*--script[=\s]+[^\s]*vuln/i, 'T1595.002'],
    [/\b(?:nmap|masscan|rustscan|naabu)\b/i, 'T1046'],
    [/\b(?:chisel|sshuttle)\b|\bssh\b.*\s-D\s/i, 'T1090.001'],
    [/\bligolo\b|\bssh\b.*\s-[LR]\s/i, 'T1090'],
    [/\b(?:linpeas|winpeas)\b/i, 'T1082'],
    [/\bsudo\s+-l\b/i, 'T1548.003'],
    [/\bfind\s+\/\s+.*-perm\b/i, 'T1548.001'],
    [/\b(?:ipconfig|ifconfig|ip\s+(?:a|addr|route)|arp\s+-a|route\s+print)\b/i, 'T1016'],
  ];

  OBOL.ATTACK_MOVE = { byKind: BY_KIND, byMove: BY_MOVE, byCmd: BY_CMD };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.ATTACK_MOVE; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
