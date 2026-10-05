/*!
 * obol data — coverage-expected.js — OBOL.COVERAGE_EXPECTED
 *
 * The per-port EXPECTED-COVERAGE oracle: for each by-port Evidence card, the techniques an OSCP operator
 * would expect to find, each mapped to the move id(s) that represent it. This is the ONLY place a human
 * "ideal" is written down, and it is deliberately NOT a drawn tree — just a checklist (see
 * docs/DECISION-MAP.md). The decision map / gap report diffs the derived per-port moves against this
 * list: a technique whose `moves` are all absent is a COVERAGE GAP (a technique we should teach but no
 * move represents). `moves: []` is how you record a known-missing technique on purpose, so it shows up
 * red until someone adds the move — then it clears itself. Keep entries honest: only list a move id here
 * if that move genuinely covers the technique.
 *
 * Keyed by Evidence card key (p21, p80, …). Not every port needs an entry; the ones here are the
 * high-traffic surfaces where coverage matters most. Extend as the curriculum grows.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.COVERAGE_EXPECTED = {
    p21: { label: 'FTP', expect: [
      { name: 'Anonymous login + read', moves: ['recon-ftp'] },
      { name: 'Credential brute-force', moves: ['online-brute-ftp'] },
      { name: 'Write-to-webroot → RCE', moves: ['ftp-upload-webshell'] },
      { name: 'FTP bounce scan (FXP)', moves: ['ftp-bounce'], note: 'nmap -b / bounce-scan an internal host via an open FTP relay' },
    ] },
    p22: { label: 'SSH', expect: [
      { name: 'Key-based login from a looted key', moves: ['ssh-key-login'] },
      { name: 'Password brute-force', moves: ['online-brute-ssh'] },
      { name: 'Pivot (dynamic / sshuttle)', moves: ['pivot-ssh-dynamic', 'pivot-sshuttle'] },
      { name: 'User enum (CVE-2018-15473, old OpenSSH)', moves: ['ssh-user-enum'], note: 'timing-based username enumeration on pre-7.7 OpenSSH' },
    ] },
    p23: { label: 'Telnet', expect: [
      { name: 'Banner + default/weak login', moves: ['recon-telnet'] },
      { name: 'Credential reuse', moves: ['recon-telnet'] },
    ] },
    p25: { label: 'SMTP / mail', expect: [
      { name: 'User enumeration (VRFY/EXPN/RCPT)', moves: ['recon-smtp'] },
      { name: 'Read the mailbox with a credential', moves: ['recon-mail'] },
      { name: 'Open-relay test', moves: ['smtp-open-relay'], note: 'confirm the server relays mail for arbitrary senders' },
    ] },
    p53: { label: 'DNS', expect: [
      { name: 'Zone transfer (AXFR)', moves: ['recon-dns'] },
      { name: 'Subdomain / record enumeration', moves: ['recon-dns'] },
    ] },
    p69: { label: 'TFTP', expect: [
      { name: 'Fetch device config files by name', moves: ['recon-tftp'] },
    ] },
    p80: { label: 'HTTP / HTTPS', expect: [
      { name: 'Stack fingerprint / triage', moves: ['recon-web-triage', 'check-web-components', 'check-cms-version'] },
      { name: 'Virtual-host discovery', moves: ['vhost-discovery'] },
      { name: 'Content / directory discovery', moves: ['content-discovery'] },
      { name: 'Parameter discovery', moves: ['param-discovery'] },
      { name: 'SQL injection (manual + sqlmap)', moves: ['sqli-basics', 'manual-sqli-exploitation', 'sqlmap-automation'] },
      { name: 'File upload → shell', moves: ['file-upload', 'web-shells'] },
      { name: 'LFI / RFI', moves: ['lfi-probe'] },
      { name: 'Command injection', moves: ['command-injection'] },
      { name: 'SSTI', moves: ['ssti'] },
      { name: 'SSRF / XXE / deserialization', moves: ['ssrf', 'xxe', 'deserialization'] },
      { name: 'Auth bypass / IDOR / JWT', moves: ['idor', 'jwt-attacks', 'verb-tampering'] },
      { name: 'Source exposure (.git/.svn)', moves: ['git-exposed', 'svn-exposed'] },
      { name: 'Known app CVEs (Log4Shell/Struts)', moves: ['check-log4shell', 'check-struts2'] },
      { name: 'Local file read → secrets', moves: ['lfi-secret-harvest'], note: 'turn a confirmed LFI into credentials, keys, and source via the filter wrapper' },
    ] },
    p88: { label: 'Kerberos / DC', expect: [
      { name: 'Identify the DC + domain', moves: ['ad-dc-identify'] },
      { name: 'User enumeration', moves: ['ad-user-enum'] },
      { name: 'AS-REP roasting', moves: ['asrep-roast', 'crack-asrep'] },
      { name: 'Kerberoasting', moves: ['kerberoast', 'crack-tgs'] },
      { name: 'Ticket reuse / pass-the-ticket', moves: ['kerberos-tickets', 'ticket-reuse'] },
    ] },
    p135: { label: 'SMB / RPC', expect: [
      { name: 'Anonymous / null-session enum', moves: ['recon-smb-anon'] },
      { name: 'Share inventory + spider', moves: ['smb-share-inventory'] },
      { name: 'GPP cpassword in SYSVOL', moves: ['gpp-passwords'] },
      { name: 'EternalBlue (MS17-010)', moves: ['eternalblue'] },
      { name: 'NTLM poisoning / relay', moves: ['responder-poison', 'ntlm-relay-attack', 'mitm6-ipv6-takeover'] },
      { name: 'Coerce auth (PetitPotam/PrinterBug)', moves: ['coerce-auth'] },
      { name: 'Lateral exec (psexec/wmiexec)', moves: ['lateral-exec'] },
    ] },
    p389: { label: 'LDAP', expect: [
      { name: 'Anonymous bind enumeration', moves: ['ad-anon-ldap-enum'] },
      { name: 'BloodHound collection', moves: ['bloodhound-collect'] },
      { name: 'LAPS / gMSA read', moves: ['laps-read', 'gmsa-read'] },
      { name: 'AD CS template abuse (ESC1-8)', moves: ['adcs-esc', 'cert-authenticate'] },
    ] },
    p1433: { label: 'MSSQL', expect: [
      { name: 'Login (sa / domain / reused)', moves: ['mssql-login'] },
      { name: 'xp_cmdshell OS execution', moves: ['mssql-xp-cmdshell'] },
      { name: 'Linked-server / impersonation hop', moves: ['mssql-linked-server'], note: 'EXECUTE AS / linked-server chaining to another instance' },
    ] },
    p1521: { label: 'Oracle TNS', expect: [
      { name: 'SID brute + default accounts', moves: ['oracle-tns'] },
      { name: 'File read/write + RCE via odat', moves: ['oracle-tns'] },
    ] },
    p3306: { label: 'MySQL', expect: [
      { name: 'Login + schema/user enum', moves: ['mysql-login'] },
      { name: 'Credential-table sweep', moves: ['mysql-loot'] },
      { name: 'UDF / INTO OUTFILE to webroot', moves: ['mysql-outfile-rce'], note: 'write a shell via INTO OUTFILE, or RCE via a UDF when FILE priv is held' },
    ] },
    p9200: { label: 'Elasticsearch', expect: [
      { name: 'Unauthenticated index dump', moves: ['elasticsearch-enum'] },
      { name: 'Scripting-engine RCE (old versions)', moves: ['elasticsearch-enum'] },
    ] },
    p11211: { label: 'Memcached', expect: [
      { name: 'Dump cached keys/values', moves: ['memcached-enum'] },
    ] },
    p8009: { label: 'AJP (Tomcat)', expect: [
      { name: 'Ghostcat file read / inclusion', moves: ['ajp-ghostcat'] },
    ] },
    p1099: { label: 'Java RMI', expect: [
      { name: 'Registry enumeration', moves: ['java-rmi'] },
      { name: 'Deserialization RCE', moves: ['java-rmi'] },
    ] },
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
