/*!
 * obol engine — parsers/_common.js
 * Shared compiled regexes, scoping/validation helpers, and the `_add` dedup primitive.
 * Faithful JS port of obol-local/obol/parsers/_common.py.
 *
 * The "workspace" (ws) in the browser is a plain context object:
 *   { target: "10.10.10.10", domainSeed: "corp.local", seedFacts: [Fact...] }
 * `target` is the host scope, `domainSeed` stands in for a previously-proven AD
 * domain (what the Python read from ws.facts), and `seedFacts` is any committed
 * facts a caller wants association helpers to see (usually empty).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var F = OBOL.facts;
  var ProofState = F.ProofState;

  var C = OBOL._parserCommon = OBOL._parserCommon || {};
  C.ProofState = ProofState;

  // ---- Fact constructor shim: Python Fact(kind, scope, value, state, source) ---- //
  function mkFact(kind, scope, value, state, source) {
    return F.makeFact({ kind: kind, scope: scope, value: value, state: state, source: source });
  }
  C.mkFact = mkFact;

  // ---- regex iteration helpers -------------------------------------------------- //
  function reAll(rx, text) {
    var flags = rx.flags.indexOf('g') >= 0 ? rx.flags : rx.flags + 'g';
    var r = new RegExp(rx.source, flags);
    var out = [], m;
    while ((m = r.exec(text)) !== null) {
      out.push(m);
      if (m.index === r.lastIndex) r.lastIndex++;
    }
    return out;
  }
  function reSearch(rx, text) {
    var r = new RegExp(rx.source, rx.flags.replace('g', ''));
    return r.exec(text);
  }
  C.reAll = reAll;
  C.reSearch = reSearch;

  // ---- regexes (ported from _common.py) ----------------------------------------- //
  C._DOMAIN_RE = /\(domain:([^)]+)\)/i;
  C._NAME_RE = /\(name:([^)]+)\)/i;
  C._NXC_PROTO_REACHABLE_RE = /^(?<proto>LDAP|SMB|WINRM|RDP|SSH|FTP)\s+\S+\s+\d+\s+\S+/im;
  C._SAM_RE = /\bsAMAccountName:\s*([^\s,;]+)/i;
  C._UPN_RE = /\buserPrincipalName:\s*([^\s,;@]+)(?:@[^\s,;]+)?/i;
  C._NXC_USER_ROW_RE = /^(?:LDAP|SMB)\s+\S+\s+\d+\s+\S+\s+(?!\[[^\]]+\])(?<user>[A-Za-z0-9._$-]{2,})\b/im;
  C._NXC_RID_USER_RE = /^(?:SMB|RPC)\s+\S+\s+\d+\s+\S+\s+(?:0x[0-9a-f]+|\d+):\s+(?:[^\\\s]+\\)?(?<user>[A-Za-z0-9._$-]{2,})\s+\(SidTypeUser\)/im;
  C._RPC_USER_RE = /\buser:\[(?<user>[^\]]+)\]\s+rid:\[[^\]]+\]/i;
  C._BASE_DN_RE = /\b(?:namingContexts|defaultNamingContext|rootDomainNamingContext):\s*([A-Za-z0-9_=,.-]+)/i;
  C._ASREP_RE = /(\$krb5asrep\$[^\s]+)/i;
  C._ASREP_USER_RE = /\$krb5asrep\$\d+\$([^:@$]+)(?:@([^:$]+))?:/i;
  C._TGS_RE = /(\$krb5tgs\$[^\s]+)/i;
  C._TGS_USER_RE = /\$krb5tgs\$\d+\$\*?([^$*:]+)/i;
  C._NTDS_HASH_RE = /(?:(?<domain>[^\s\\:]+)\\)?(?<user>[^\s\\:]+):(?<rid>\d+):[0-9a-fA-F]{32}:(?<nt>[0-9a-fA-F]{32}):::/;
  var NXC_ROW_PREFIX = '(?:(?:SMB|WINRM|WMI|RPC|SSH)\\s+\\S+\\s+\\d+\\s+\\S+\\s+)?';
  C._SYSTEM_ID_RE = /\bnt authority\\system\b/i;
  C._WHOAMI_ID_RE = new RegExp('^' + NXC_ROW_PREFIX + '(?<id>nt authority\\\\system|[A-Za-z0-9][A-Za-z0-9.-]*\\\\[A-Za-z0-9._$-]{2,})\\s*$', 'im');
  C._EXEC_SUCCESS_RE = /\bexecuted command\b|\[\+\]\s+executed|Microsoft Windows \[Version|^[A-Za-z]:\\.*>/im;
  C._LINUX_ID_RE = /\buid=(?<uid>\d+)\((?<user>[^)]+)\)\s+gid=\d+/i;
  C._PENELOPE_GOT_RE = /got reverse shell from\s+(?<info>.+)/i;
  C._PENELOPE_UPGRADE_RE = /shell upgraded|spawned a pty|upgrading shell to pty/i;
  C._PENELOPE_SID_RE = /session\s*id\s*[:=]?\s*(?<sid>\w+)/i;
  C._PENELOPE_HOST_RE = /(?<host>[A-Za-z0-9][\w.-]*)~(?<ip>\d{1,3}(?:\.\d{1,3}){3})/;
  C._ESC_RE = /\bESC(\d{1,2})\b/;
  C._AD_CONTROL_RIGHT_RE = /\b(GenericAll|GenericWrite|WriteDACL|WriteDacl|WriteOwner|FullControl|AllExtendedRights|ForceChangePassword|AddMember|WriteMembers|ReadGMSAPassword|msDS-AllowedToActOnBehalfOfOtherIdentity|AllowedToAct|RBCD|DCSync|GetChanges|GetChangesAll)\b/i;
  C._AD_CONTROL_SUCCESS_RE = /\b(?:success(?:fully)?|modified|changed|granted|added|written|set|able to replicate)\b.*\b(?:groupMember|member|owner|GenericAll|FullControl|DACL|delegation|msDS-AllowedToAct|AllowedToAct|RBCD|rights?|DCSync|replicat)\b|\b(?:groupMember|owner|GenericAll|FullControl|DACL|delegation|msDS-AllowedToAct|AllowedToAct|RBCD|rights?|DCSync|replicat)\b.*\b(?:success(?:fully)?|modified|changed|granted|added|written|set|able to replicate)\b/i;
  C._ADD_COMPUTER_SUCCESS_RE = /\b(?:success(?:fully)?\s+)?(?:added|created)\s+(?:machine|computer)\s+(?:account\s+)?['"]?(?<name>[A-Za-z0-9_.-]+\$?)['"]?/i;
  C._TICKET_FILE_RE = /\b(?:Saving|Saved|Wrote|Writing|Ticket written)\b[^\n]*?(?<file>[A-Za-z0-9_./\\-]+\.(?:ccache|kirbi))/i;
  C._IMPERSONATE_RE = /\bimpersonat(?:e|ing)\s+(?:user\s+)?['"]?(?<user>[A-Za-z0-9._$-]+)/i;
  C._GMSA_HASH_RE = /(?:(?<domain>[A-Za-z0-9_.-]+)\\)?(?<user>[A-Za-z0-9._-]+\$)\s*[:\s]+(?:NTLM|NTHASH|RC4_HMAC|rc4_hmac)\s*[:=]\s*(?<nt>[0-9a-fA-F]{32})/i;
  C._GMSA_READ_ERROR_RE = /\b(no\s+object\s+found|noresulterror|does\s+not\s+exist|not\s+found|access[_\s]?denied|insufficient|denied|unauthorized|traceback|exception)\b/i;
  C._LAPS_PASSWORD_RE = /\b(?:ms-Mcs-AdmPwd|msLAPS-Password|LAPS\s+Password|Password)\s*[:=]\s*(?<pw>\S+)/i;
  C._LAPS_COMPUTER_RE = /\b(?:Computer|Name|sAMAccountName)\s*[:=]\s*(?<computer>[A-Za-z0-9_.-]+\$?)/i;
  C._LAPS_USER_RE = /\b(?:User|Username|Account)\s*[:=]\s*(?<user>[A-Za-z0-9._$-]+)/i;
  C._JOHN_SHOW_RE = /^(?<user>[A-Za-z0-9._$-]{2,}):(?<password>[^:\s][^:\r\n]*)(?::.*)?$/;
  C._JOHN_CRACKED_FOOTER_RE = /\b\d+\s+password\s+hash(?:es)?\s+cracked\b/i;
  C._CPASSWORD_RE = /\bcpassword\s*=\s*["']?([^"'\s<>]+)/i;
  C._GPP_FILE_RE = /\b(?:Groups|ScheduledTasks|Services|DataSources|Printers|Drives)\.xml\b/i;
  C._NMAP_OPEN_RE = /^(?<port>\d+)\/(?:tcp|udp)\s+open(?:\|\w+)?\s+(?<service>\S+)?(?:\s+(?<version>.*?))?\s*$/im;
  C._NMAP_DISCOVERED_RE = /Discovered open port (?<port>\d+)\/(?<proto>tcp|udp) on (?<host>\S+)/i;
  C._NMAP_DOMAIN_NAME_RE = /^\|_?\s*(?:Domain name|DNS_Domain_Name|NetBIOS_Domain_Name):\s*(?<domain>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_FQDN_RE = /^\|_?\s*FQDN:\s*(?<fqdn>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_COMPUTER_NAME_RE = /^\|_?\s*(?:Computer name|NetBIOS computer name):\s*(?<name>[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_SMB_SIGNING_RE = /Message signing enabled(?: and (?<required>required)| but not required)?/i;
  C._NMAP_HTTP_TITLE_RE = /^\|\s*_?http-title:\s*(?<title>.+)$/im;
  C._NMAP_HTTP_SERVER_RE = /^\|\s*_?http-server-header:\s*(?<header>.+)$/im;
  C._NMAP_HTTP_GENERATOR_RE = /^\|\s*_?http-generator:\s*(?<generator>.+)$/im;
  C._NMAP_HTTP_REDIRECT_RE = /^\|\s*_?http-title:\s*Did not follow redirect to (?<location>\S+)/im;
  C._NMAP_FTP_ANON_RE = /ftp-anon:\s*Anonymous FTP login allowed|Anonymous FTP login allowed/i;
  C._NMAP_SSH_HOSTKEY_RE = /^\|_?\s+(?<bits>\d{3,5})\s+(?<fingerprint>[0-9a-f:]{16,})\s+\((?<kind>[^)]+)\)/im;
  C._NMAP_SNMP_FIELD_RE = /^\|_?\s*(?<key>enterprise|name|description|location|contact):\s*(?<value>.+)$/im;
  C._NXC_SIGNING_RE = /\(signing:(?<enabled>True|False)\)/i;
  C._NXC_SMBV1_RE = /\(SMBv1:(?<enabled>True|False)\)/i;
  C._WEB_GOBUSTER_RE = /^(?<path>\/\S*)\s+\(Status:\s*(?<code>\d{3})\)/m;
  C._WEB_FEROX_RE = /^\s*(?<code>\d{3})\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(?<url>https?:\/\/\S+)/im;
  C._WEB_FFUF_RE = /^(?<token>\S+)\s+\[Status:\s*(?<code>\d{3})/m;
  C._WEB_WFUZZ_RE = /^\d+:\s+(?:C=)?(?<code>\d{3})\s+\d+\s*L\s+\d+\s*W\s+\d+\s*C[a-z]*\s+"(?<payload>[^"]*)"/m;
  C._WEB_DIRB_RE = /^\+\s+(?<url>https?:\/\/\S+)\s+\(CODE:(?<code>\d{3})/im;
  C._WEB_GOBUSTER_VHOST_RE = /Found:\s*(?<name>\S+)\s+\(Status:\s*(?<code>\d{3})\)/i;
  C._NIKTO_FINDING_RE = /^\+\s+(?<text>\S.+)$/m;
  C._WEB_PATH_IN_TEXT_RE = /\/[A-Za-z0-9_][A-Za-z0-9_./-]{1,}/;
  C._WEB_INTERESTING_RE = /\/admin|\/api|\/upload|\/backup|\/login|\/dashboard|\/config|\/phpmyadmin|\/wp-admin|\.git|\.svn|\.bak|\.old|\.zip|\.tar|\.sql|\.env|\.config/i;
  C._GIT_HEAD_RE = /\bref:\s+refs\/heads\/(?<branch>[A-Za-z0-9_./-]+)/i;
  C._GIT_DUMPER_SUCCESS_RE = /\b(?:fetching|downloading|downloaded|repository|objects|refs\/heads|HEAD)\b/i;
  C._SOURCE_SECRET_RE = /\b(?<key>password|passwd|pwd|secret|api[_-]?key|token|connection(?:string)?|connstr)\b\s*[:=]\s*(?<value>[^\s"']{4,}|"[^"]{4,}"|'[^']{4,}')/i;
  C._LFI_PASSWD_RE = /root:[^:\n]{0,12}:0:0:[^:\n]*:[^:\n]*:/m;
  C._LFI_PASSWD_SECOND_RE = /^\s*(?:daemon|bin|sys|sync|games|nobody|www-data|sshd|mail|proxy):[^:\n]*:\d+:\d+:/m;
  C._LFI_WIN_INI_RE = /\[(?:extensions|fonts|mci extensions|files|mail)\]|;\s*for 16-bit app support|\[boot loader\]/i;
  C._LFI_FILE_PARAM_RE = /(?:resource=|file:\/\/|=)(?<path>\/[A-Za-z0-9_./-]+|[A-Za-z]:\\[^\s'"&]+)/;
  C._B64_TOKEN_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
  C._CMDI_UID_RE = /\buid=\d+\([^)\n]+\)\s+gid=\d+\([^)\n]+\)/;
  C._CMDI_WIN_RE = /\bnt authority\\+system\b|\bMicrosoft Windows \[Version\b/i;
  C._SQL_ERROR_RE = /You have an error in your SQL syntax|Warning:\s*mysqli?_\w+\(\)|supplied argument is not a valid MySQL|SQL syntax.*?(?:MariaDB|MySQL) server|Unclosed quotation mark after the character string|quoted string not properly terminated|Incorrect syntax near|Microsoft OLE DB Provider for (?:ODBC Drivers|SQL Server)|System\.Data\.SqlClient\.SqlException|Unknown column '[^']+' in 'where clause'|ORA-\d{5}|PostgreSQL query failed|pg_query\(\)|pg_exec\(\)|SQLSTATE\[\w+\]|java\.sql\.SQLException|SQLite3?::(?:query|exec)|near ".+?": syntax error/i;
  C._IMDS_MARKER_RE = /\b(?:ami-id|instance-id|instance-action|iam\/security-credentials|meta-data\/|security-credentials|placement\/availability-zone|block-device-mapping|public-keys\/|reservation-id)\b/i;
  C._AWS_KEY_RE = /"AccessKeyId"\s*:\s*"(?<akid>(?:AKIA|ASIA)[A-Z0-9]{8,})"/;
  C._AWS_SECRET_RE = /"SecretAccessKey"\s*:\s*"(?<secret>[^"\n]{8,})"/;
  C._AWS_TOKEN_RE = /"Token"\s*:\s*"(?<token>[^"\n]{16,})"/;
  C._NOSQL_OP_RE = /\[\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)\]|"\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|expr|function)"|%5[Bb]%24(?:ne|gt|gte|lt|lte|regex|in|nin|where)%5[Dd]/i;
  C._NOSQL_SUCCESS_RE = /"(?:success|authenticated|isAdmin|admin|loggedin|logged_in)"\s*:\s*true|"(?:token|jwt|session|auth_token|accessToken)"\s*:\s*"[^"\n]{8,}"|\bLogin successful\b|\bWelcome back\b|\bAuthentication succeeded\b/i;
  C._SET_COOKIE_SESSION_RE = /^Set-Cookie:\s*(?:session|connect\.sid|token|auth|PHPSESSID|jwt|jsessionid)\b/im;
  C._LOGIN_REDIRECT_RE = /^Location:\s*\S*\/(?:admin|dashboard|home|profile|account|portal|welcome)\b/im;
  C._JWT_TOOL_KEY_RE = /(?<secret>\S{1,64})\s+is the CORRECT key|(?:key confirmed|correct key|signing key(?:\s+found)?)\s*[:=]\s*['"]?(?<secret2>\S{1,64})/i;
  C._JWT_HASHCAT_RE = /^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+:(?<secret>\S+)\s*$/m;
  C._JWT_FORGE_RE = /"alg"\s*:\s*"none"|hbGciOiJub25l|-X\s+a\b|--exploit\s+a\b|-I\s+-pc\b/i;
  C._WEB_AUTHZ_SUCCESS_RE = /"(?:isAdmin|is_admin|admin)"\s*:\s*(?:true|"?admin(?:istrator)?"?)|"role"\s*:\s*"admin(?:istrator)?"|\bWelcome,?\s+admin(?:istrator)?\b|\bAdmin(?:istrator)?\s+(?:Dashboard|Panel|Console|Area)\b/i;
  C._NIKTO_NOISE_PREFIXES = ['target ip', 'target hostname', 'target port', 'start time', 'end time', 'server:', 'ssl info', 'root page', 'retrieved', 'no cgi', 'scan terminated', 'host(s) tested', 'requests:', '0 host', '1 host'];
  C._SQLMAP_VULN_RE = /\b(?:parameter\s+['"].+?['"]\s+is vulnerable|is vulnerable to .+sql injection|appears to be .+sql injectable)\b/i;
  C._SQLMAP_DBMS_RE = /\bback-end DBMS:\s*(?<dbms>[^\r\n]+)/i;
  C._SQLMAP_DATABASE_HEADER_RE = /\bavailable databases\s*\[(?<count>\d+)\]/i;
  C._SQLMAP_STAR_ROW_RE = /^\[\*\]\s+(?<name>[A-Za-z0-9_$.-]{1,80})\s*$/m;
  C._SQLMAP_TABLE_RE = /\bDatabase:\s*(?<database>[A-Za-z0-9_$.-]+)\s*\n(?:\[[^\n]+\]\s*)?Table:\s*(?<table>[A-Za-z0-9_$.-]+)/i;
  C._SQLMAP_DUMP_RE = /\b(?:dumped|dumping)\b.+\b(?:entries|CSV file|table)\b/i;
  C._SQLMAP_OS_SHELL_RE = /\bos-shell\b|os-shell\s*>|web backdoor.*(?:uploaded|created|saved)|command shell session/i;
  C._HTTP_STATUS_RE = /^HTTP\/\S+\s+(?<status>\d{3})(?:\s+(?<reason>.*))?$/im;
  C._HTTP_HEADER_RE = /^(?<key>Server|X-Powered-By|Location|Content-Type):\s*(?<value>.+)$/im;
  C._WHATWEB_PLUGIN_RE = /\b(?<name>[A-Za-z][A-Za-z0-9_.+-]{1,30})\[(?<value>[^\]\r\n]{1,120})\]/;
  C._SSH_BANNER_RE = /\bSSH-(?<version>[12]\.\d+)-(?<banner>[^\r\n]+)/i;
  C._FTP_BANNER_RE = /^(?:220[- ](?<banner>.+)|230\s+(?<login>Login successful.*))$/im;
  C._SNMP_SYSDESCR_RE = /SNMPv2-MIB::sysDescr\.0\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSNAME_RE = /SNMPv2-MIB::sysName\.0\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSLOCATION_RE = /SNMPv2-MIB::sysLocation\.0\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSCONTACT_RE = /SNMPv2-MIB::sysContact\.0\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;

  C._OS_SIGNATURES = {
    windows: [
      /\bMicrosoft Windows\b/i, /\bWindows\s+(?:Server|\d|XP|Vista)\b/i,
      /\bOS:\s*Windows\b/i, /\bRunning:\s*(?:Microsoft\s+)?Windows\b/i,
      /cpe:\/o:microsoft:windows/i, /\bMicrosoft-IIS\b/i,
    ],
    linux: [
      /\bLinux\b/i, /\bUbuntu\b/i, /\bDebian\b/i, /\bCentOS\b/i, /\bRed Hat\b/i,
      /\bFedora\b/i, /\bSamba\b/i, /\bUnix\b/i, /cpe:\/o:linux/i,
    ],
  };

  C._PRIVESC_ACTION_IDS = new Set(['linux-enum', 'sudo-abuse', 'writable-passwd', 'nfs-squash', 'lxc-lxd-escape', 'docker-socket', 'suid-gtfobins', 'pspy-monitor', 'cron-abuse', 'capabilities', 'linux-loot-hunt', 'linux-persistence', 'windows-enum', 'seimpersonate', 'unquoted-service-path', 'weak-service-permissions', 'alwaysinstallelevated', 'dpapi-secrets', 'stored-credentials', 'wesng-patch-gaps', 'windows-persistence', 'lsass-dump-onbox']);
  C._LINUX_PRIVESC_ACTION_IDS = new Set(['linux-enum', 'sudo-abuse', 'writable-passwd', 'nfs-squash', 'lxc-lxd-escape', 'docker-socket', 'suid-gtfobins', 'pspy-monitor', 'cron-abuse', 'capabilities', 'linux-loot-hunt', 'linux-persistence']);
  C._WINDOWS_PRIVESC_ACTION_IDS = new Set(Array.from(C._PRIVESC_ACTION_IDS).filter(function (x) { return !C._LINUX_PRIVESC_ACTION_IDS.has(x); }));
  C._WEB_LFI_ACTION_IDS = new Set(['lfi-probe', 'xxe']);
  C._WEB_CMDI_ACTION_IDS = new Set(['command-injection', 'ssti', 'web-shells', 'file-upload', 'verb-tampering', 'deserialization', 'tomcat-deploy', 'jenkins-access', 'check-struts2']);
  C._WEB_SQLI_ACTION_IDS = new Set(['sqli-basics']);
  C._WEB_SSRF_ACTION_IDS = new Set(['ssrf', 'xxe']);
  C._WEB_NOSQLI_ACTION_IDS = new Set(['nosql-injection']);
  C._WEB_JWT_ACTION_IDS = new Set(['jwt-attacks']);
  C._WEB_XSS_ACTION_IDS = new Set(['xss-basics']);
  C._WEB_IDOR_ACTION_IDS = new Set(['idor']);
  C._WEB_EXPLOIT_ACTION_IDS = new Set([].concat(
    Array.from(C._WEB_LFI_ACTION_IDS), Array.from(C._WEB_CMDI_ACTION_IDS),
    Array.from(C._WEB_SQLI_ACTION_IDS), Array.from(C._WEB_SSRF_ACTION_IDS),
    Array.from(C._WEB_NOSQLI_ACTION_IDS), Array.from(C._WEB_JWT_ACTION_IDS),
    Array.from(C._WEB_XSS_ACTION_IDS), Array.from(C._WEB_IDOR_ACTION_IDS)));
  C._AD_ABUSE_ACTION_IDS = new Set(['bloodyad-acl', 'ad-acl-abuse', 'delegation-abuse', 'getst-impersonation', 'gmsa-read', 'laps-read', 'ticket-reuse', 'kerberos-tickets']);

  C._UNAME_RE = /\bLinux\s+(?<host>\S+)\s+(?<kernel>[0-9][^\s]+).*?\b(?<arch>x86_64|i[3-6]86|aarch64|armv\w+)\b/i;
  C._SUID_PATH_RE = /(?<path>\/[A-Za-z0-9_./+-]+)/;
  C._LOCAL_FILE_SECRET_RE = /(?:password|passwd|pwd|api[_-]?key|secret|token|connectionstring)\s*[=:]\s*['"]?\S{3,}|-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----/i;
  C._CAPABILITY_RE = /^(?<path>\/\S+)\s*=\s*(?<caps>[^#\r\n]+cap_[^#\r\n]+)$/im;
  C._PASSWD_MODE_RE = /^(?<mode>-[rwxstST-]{9})\s+.*\s+(?<path>\/etc\/passwd)\b/m;
  C._WIN_PRIV_RE = /^\s*(?<name>Se[A-Za-z0-9]+Privilege)\s+.+?\s+(?<state>Enabled|Disabled)\s*$/im;
  C._SYSTEMINFO_FIELD_RE = /^\s*(?<key>OS Name|OS Version|System Type):\s*(?<value>.+)$/im;
  C._DANGEROUS_WIN_PRIVS = new Set(['seimpersonateprivilege', 'seassignprimarytokenprivilege', 'sedebugprivilege', 'sebackupprivilege', 'serestoreprivilege', 'setakeownershipprivilege', 'seloaddriverprivilege', 'semanagevolumeprivilege', 'setcbprivilege']);
  C._AIE_VALUE_RE = /AlwaysInstallElevated\s+REG_DWORD\s+0x(?<val>[0-9a-fA-F]+)/i;
  C._HKLM_HEADER_RE = /^\s*(?:HKEY_LOCAL_MACHINE|HKLM)\b/i;
  C._HKCU_HEADER_RE = /^\s*(?:HKEY_CURRENT_USER|HKCU)\b/i;
  C._WEAK_SVC_ACCESS_RE = /\b(?:SERVICE_CHANGE_CONFIG|SERVICE_ALL_ACCESS|SERVICE_CHANGE|WRITE_DAC|WRITE_OWNER)\b/;
  C._LOWPRIV_WRITE_ACE_RE = /(?:BUILTIN\\Users|NT AUTHORITY\\(?:Authenticated Users|INTERACTIVE)|Authenticated Users|Everyone|\bUsers)\s*:\s*\([^)]*[FMW][^)]*\)/i;
  C._ANSI_RE = /\x1b\[[0-9;]*m/g;
  C._ID_LINE_RE = /\buid=\d+\(/i;
  C._CVE_RE = /CVE-\d{4}-\d{3,7}/i;
  C._EXPLOIT_PROBABILITY_RE = /\b(?:\d{1,3}\s?%|highly probable|probable|exposure|vulnerable|exploitable)\b/i;
  C._KERNEL_EXPLOIT_NAMES = ['pwnkit', 'dirtycow', 'dirty cow', 'dirtypipe', 'dirty pipe', 'polkit', 'pkexec', 'baron samedit', 'overlayfs', 'af_packet', 'ptrace', 'netfilter', 'sequoia', 'looney tunables', 'gameoverlay', 'nftables', 'sudoedit', 'snapd', 'dirtysock'];
  C._KERNEL_EXPLOIT_NEGATION_RE = /\bnot\s+(?:vulnerable|exploitable|affected|applicable)\b|\bpatched\b|\bnot\s+a\s+match\b|\bn\/a\b/i;
  C._NXC_AUTH_RE = /^\s*(?<proto>SMB|LDAP|WINRM|RDP|SSH|FTP)\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+(?<auth>.+)$/im;
  C._AUTH_MATERIAL_RE = /^(?:(?<domain>[^\\\s:/]+)\\)?(?<user>[A-Za-z0-9._$-]{2,}):(?<secret>[^\s()]+)/;
  C._NT_HASH_RE = /^(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$/;
  C._EW_PROMPT_RE = /\*Evil-WinRM\*\s+PS\s+/i;
  C._BH_ZIP_RE = /\b[^\s/\\]+(?:bloodhound|bhloot|sharphound)?[^\s/\\]*\.zip\b/i;
  C._BH_JSON_RE = /\b(?:users|groups|computers|domains|ous|gpos|containers|sessions|localadmins|trusts|acls)\.json\b/i;
  C._ATTACK_PATH_RE = /\b(?:attack path|shortest paths? to domain admins?|path to da|owned principal)\b/i;
  C._FAILURE_REASONS = {
    status_logon_failure: 'logon_failure',
    status_account_locked_out: 'account_locked_out',
    status_password_expired: 'password_expired',
    status_account_disabled: 'account_disabled',
    status_access_denied: 'access_denied',
  };
  C._NOISE_USERS = new Set(['badpwdcount', 'description', 'distinguishedname', 'dn', 'lastlogon', 'name', 'pwdlastset', 'samaccountname', 'useraccountcontrol', 'username']);
  C._SHARE_HEADER_WORDS = new Set(['share', 'sharename', '-----', '---------', 'name']);
  C._SHARE_PERMISSION_WORDS = new Set(['READ', 'WRITE', 'READ,WRITE', 'WRITE,READ', 'NO ACCESS', 'NONE']);
  C._JOHN_NOISE_PREFIXES = ['loaded ', 'session.', 'cost ', 'will run ', 'press ', 'use the ', 'warning:', 'no password hashes', 'password hash', 'password hashes'];
  C._INTERACTIVE_WIN_TOOLS = new Set(['evil-winrm', 'wmiexec', 'psexec', 'atexec', 'smbexec', 'winrs']);
  C._INTERACTIVE_RE = /\*Evil-WinRM\*\s+PS|semi-interactive shell|Launching semi-interactive|^\[[^\]]+\]:\s*PS[> ]/im;
  C._WPSCAN_USER_SECTION_RE = /User\(s\) Identified[\s\S]*/i;
  C._WPSCAN_USER_RE = /^\s*\[\+\]\s+(?<u>[A-Za-z0-9._@-]{2,64})\s*$/m;
  C._WPSCAN_VULN_RE = /\[!\]\s*Title:\s*(?<t>.+?)\s*$/m;
  C._WPSCAN_VERSION_RE = /WordPress version\s+(?<v>\d[\w.]+)/i;
  C._WPSCAN_LOGIN_RE = /\[SUCCESS\]\s*-\s*(?<u>[^/\r\n]+?)\s*\/\s*(?<p>\S.*?)\s*$/m;
  C._SQL_VERSION_BANNER_RE = /\b\d+\.\d+\.\d+[\w.-]*-?(?:MariaDB|MySQL)\b|\bMySQL\s+\d+\.\d+|Microsoft SQL Server\s+\d{4}|PostgreSQL\s+\d+\.\d+/i;
  C._TRUST_NLTEST_RE = /^\s*\d+:\s+\S+\s+(?<fqdn>[A-Za-z0-9-]+\.[A-Za-z0-9.-]+)/m;
  C._TRUST_DOMAINTRUST_RE = /TargetName\s*[:=]\s*(?<fqdn>[A-Za-z0-9][A-Za-z0-9.-]+)/i;
  C._DOMAIN_SID_RE = /Domain SID (?:is|:)\s*[:=]?\s*(?<sid>S-1-5-21-[0-9-]+)/i;

  // ---- string helpers ----------------------------------------------------------- //
  function stripChars(s, chars) {
    var i = 0, j = s.length;
    while (i < j && chars.indexOf(s[i]) >= 0) i++;
    while (j > i && chars.indexOf(s[j - 1]) >= 0) j--;
    return s.slice(i, j);
  }
  C.stripChars = stripChars;

  function uniqueSortedCI(arr) {
    var seen = {}, out = [];
    for (var i = 0; i < arr.length; i++) {
      var k = String(arr[i]).toLowerCase();
      if (!seen[k]) { seen[k] = true; out.push(arr[i]); }
    }
    out.sort(function (a, b) {
      var la = String(a).toLowerCase(), lb = String(b).toLowerCase();
      return la < lb ? -1 : la > lb ? 1 : 0;
    });
    return out;
  }
  C.uniqueSortedCI = uniqueSortedCI;

  var _B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function _b64_manual(tok) {
    var clean = tok.replace(/=+$/, '');
    var out = '', buffer = 0, bits = 0;
    for (var i = 0; i < clean.length; i++) {
      var idx = _B64_ALPHABET.indexOf(clean[i]);
      if (idx < 0) return '';
      buffer = (buffer << 6) | idx;
      bits += 6;
      if (bits >= 8) { bits -= 8; out += String.fromCharCode((buffer >> bits) & 0xff); }
    }
    return out;
  }
  function b64decode(tok) {
    try {
      if (typeof atob !== 'undefined') return atob(tok);
      if (typeof Buffer !== 'undefined') return Buffer.from(tok, 'base64').toString('binary');
    } catch (e) { /* ignore */ }
    return _b64_manual(tok);
  }
  C.b64decode = b64decode;

  // ---- scoping / validation helpers --------------------------------------------- //
  function _domain_from_facts(ws) {
    // The Python read ws.facts.values("ad.domain_known"); here the committed domain
    // is carried explicitly on the context (opts.domain), simulating a seeded fact.
    if (ws && ws.seedFacts) {
      for (var i = 0; i < ws.seedFacts.length; i++) {
        var f = ws.seedFacts[i];
        if (f.kind === 'ad.domain_known' && f.state === ProofState.SUPPORTED && f.value && f.value.name) return f.value.name;
      }
    }
    return (ws && ws.domainSeed) || '';
  }
  C._domain_from_facts = _domain_from_facts;

  function _scope_for_domain(ws, domain) {
    var name = domain || _domain_from_facts(ws) || 'domain';
    return 'domain:' + name;
  }
  C._scope_for_domain = _scope_for_domain;

  function _add(out, fact) {
    for (var i = 0; i < out.length; i++) {
      var e = out[i];
      if (e.kind === fact.kind && e.state === fact.state && F.valuesEqual(e.value, fact.value)) return;
    }
    out.push(fact);
  }
  C._add = _add;

  function _line_for_match(text, m) {
    var start = text.lastIndexOf('\n', m.index) + 1;
    var end = text.indexOf('\n', m.index + m[0].length);
    if (end === -1) end = text.length;
    return text.slice(start, end).trim().slice(0, 220);
  }
  C._line_for_match = _line_for_match;

  function _add_os_observation(facts, ws, source, family, evidence, confidence, tool, promote) {
    family = (family || '').trim().toLowerCase();
    if (family !== 'windows' && family !== 'linux') return;
    var value = { family: family, confidence: confidence, tool: tool, evidence: (evidence || '').trim().slice(0, 220) };
    _add(facts, mkFact('host.os_hint', 'host:' + ws.target, value, ProofState.SUPPORTED, source));
    if (promote) _add(facts, mkFact('host.os_family', 'host:' + ws.target, value, ProofState.SUPPORTED, source));
  }
  C._add_os_observation = _add_os_observation;

  function _add_os_from_text(text, ws, source, facts, tool, confidence, promote) {
    confidence = confidence || 'high';
    var matches = {};
    Object.keys(C._OS_SIGNATURES).forEach(function (family) {
      var pats = C._OS_SIGNATURES[family];
      for (var i = 0; i < pats.length; i++) {
        var m = reSearch(pats[i], text);
        if (m) { matches[family] = _line_for_match(text, m) || m[0]; break; }
      }
    });
    var keys = Object.keys(matches);
    var promoteSingle = promote && keys.length === 1;
    keys.forEach(function (family) {
      _add_os_observation(facts, ws, source, family, matches[family], confidence, tool, promoteSingle);
    });
  }
  C._add_os_from_text = _add_os_from_text;

  function _clean_username(user) {
    user = stripChars((user || '').trim(), ',;:');
    if (user.indexOf('\\') >= 0) user = user.split('\\').pop();
    if (user.indexOf('@') >= 0) user = user.split('@')[0];
    return user.trim();
  }
  C._clean_username = _clean_username;

  function _valid_username(user, allowMachine) {
    if (allowMachine === undefined) allowMachine = true;
    if (!user) return false;
    if (C._NOISE_USERS.has(user.toLowerCase())) return false;
    if (!allowMachine && user.endsWith('$')) return false;
    return /^[A-Za-z0-9._$-]{2,}$/.test(user);
  }
  C._valid_username = _valid_username;

  function _valid_password(password) {
    password = (password || '').trim();
    if (!password || ['?', '*', '<password>', '{{password}}'].indexOf(password) >= 0) return false;
    var l = password.toLowerCase();
    if (l.indexOf('status') === 0 || l.indexOf('recovered') === 0 || l.indexOf('progress') === 0 || l.indexOf('guess') === 0) return false;
    return true;
  }
  C._valid_password = _valid_password;

  function _domain_from_text(text) {
    var m = reSearch(C._DOMAIN_RE, text);
    if (!m) return '';
    var domain = m[1].trim();
    if (domain === 'None' || domain === '-') return '';
    return domain;
  }
  C._domain_from_text = _domain_from_text;

  function _base_dn_from_domain(domain) {
    return domain.split('.').filter(Boolean).map(function (p) { return 'DC=' + p; }).join(',');
  }
  C._base_dn_from_domain = _base_dn_from_domain;

  function _usernames(text) {
    var users = {};
    [C._SAM_RE, C._UPN_RE, C._NXC_USER_ROW_RE].forEach(function (rx) {
      reAll(rx, text).forEach(function (m) {
        var user = _clean_username(m.groups && m.groups.user !== undefined ? m.groups.user : m[1]);
        if (_valid_username(user)) users[user] = true;
      });
    });
    return uniqueSortedCI(Object.keys(users));
  }
  C._usernames = _usernames;

  function _rid_usernames(text) {
    var users = {};
    [C._NXC_RID_USER_RE, C._RPC_USER_RE].forEach(function (rx) {
      reAll(rx, text).forEach(function (m) {
        var user = _clean_username(m.groups.user);
        if (_valid_username(user, false)) users[user] = true;
      });
    });
    return uniqueSortedCI(Object.keys(users));
  }
  C._rid_usernames = _rid_usernames;

  function _tokenize(command) {
    // Minimal shlex-like split honoring single/double quotes.
    var toks = [], cur = '', quote = '', has = false;
    for (var i = 0; i < command.length; i++) {
      var ch = command[i];
      if (quote) {
        if (ch === quote) quote = '';
        else cur += ch;
      } else if (ch === '"' || ch === "'") { quote = ch; has = true; }
      else if (/\s/.test(ch)) { if (has || cur) { toks.push(cur); cur = ''; has = false; } }
      else { cur += ch; has = true; }
    }
    if (has || cur) toks.push(cur);
    return toks;
  }

  function _command_arg(command, names) {
    if (!Array.isArray(names)) names = Array.prototype.slice.call(arguments, 1);
    var parts = _tokenize(command);
    for (var i = 0; i < parts.length; i++) {
      var token = parts[i];
      if (names.indexOf(token) >= 0 && i + 1 < parts.length) return parts[i + 1];
      for (var j = 0; j < names.length; j++) {
        if (token.indexOf(names[j] + '=') === 0) return token.split('=').slice(1).join('=');
      }
    }
    return '';
  }
  C._command_arg = _command_arg;

  function _is_ldap_command(command) {
    var cmd = ' ' + command.toLowerCase() + ' ';
    return cmd.indexOf(' ldap ') >= 0 || cmd.indexOf('ldapsearch') >= 0;
  }
  C._is_ldap_command = _is_ldap_command;

  function _is_smb_command(command) {
    var cmd = ' ' + command.toLowerCase() + ' ';
    return cmd.indexOf(' smb ') >= 0 || cmd.indexOf('smbclient') >= 0 || cmd.indexOf('rpcclient') >= 0 || cmd.indexOf('enum4linux') >= 0 || cmd.indexOf('smbmap') >= 0;
  }
  C._is_smb_command = _is_smb_command;

  function _is_cracking_command(command) {
    var l = ' ' + command.toLowerCase() + ' ';
    return l.indexOf(' hashcat ') >= 0 || /(^|[\s/])john(\s|$)/.test(l);
  }
  C._is_cracking_command = _is_cracking_command;

  function _is_ssh_command(command) {
    var l = ' ' + command.toLowerCase() + ' ';
    if (l.indexOf('sshuttle') >= 0) return false;
    return l.indexOf('sshpass') >= 0 || l.indexOf(' ssh ') >= 0 || l.indexOf(' nxc ssh ') >= 0;
  }
  C._is_ssh_command = _is_ssh_command;

  function _is_exec_command(command) {
    var l = command.toLowerCase();
    var isNxc = l.indexOf('nxc ') >= 0 || l.indexOf('nxc ') === 0;
    if (isNxc && /\s-x(\s|'|")/.test(l)) return true;
    return ['wmiexec', 'psexec', 'atexec', 'smbexec', 'evil-winrm', 'enter-pssession', 'penelope'].some(function (t) { return l.indexOf(t) >= 0; });
  }
  C._is_exec_command = _is_exec_command;

  function _is_web_vhost_command(command) {
    var c = command.toLowerCase();
    if (c.indexOf('gobuster vhost') >= 0) return true;
    if (c.indexOf('host: fuzz') >= 0 || c.indexOf('host:fuzz') >= 0) return true;
    return c.indexOf('wfuzz') >= 0 && c.indexOf('host:') >= 0 && c.indexOf('fuzz') >= 0;
  }
  C._is_web_vhost_command = _is_web_vhost_command;

  function _is_web_content_command(command) {
    if (_is_web_vhost_command(command)) return false;
    var c = command.toLowerCase();
    if (c.indexOf('feroxbuster') >= 0 || c.indexOf('gobuster dir') >= 0 || c.indexOf('dirb ') >= 0 || c.indexOf('dirsearch') >= 0) return true;
    if (c.indexOf('wfuzz') >= 0) return true;
    return c.indexOf('ffuf') >= 0 && c.indexOf('/fuzz') >= 0;
  }
  C._is_web_content_command = _is_web_content_command;

  function _url_path(url) {
    var m = /^https?:\/\/[^/]+(\/\S*)/.exec(url);
    return m ? m[1] : url;
  }
  C._url_path = _url_path;

  function _looks_anonymous_ldap_command(command, action) {
    var lowered = command.toLowerCase();
    var um = /(?:-u|--username|--user)\s+(?<user>\S+)/.exec(command);
    if (um && stripChars(um.groups.user, "'\"") !== '') return false;
    if (action && action.id === 'ad-anon-ldap-enum') return true;
    return _is_ldap_command(command) && ((' ' + lowered + ' ').indexOf(' -x ') >= 0 || lowered.indexOf("-u ''") >= 0 || lowered.indexOf('-u ""') >= 0);
  }
  C._looks_anonymous_ldap_command = _looks_anonymous_ldap_command;

  function _nt_hash(secret) {
    secret = (secret || '').trim();
    if (!C._NT_HASH_RE.test(secret)) return '';
    return secret.split(':').pop().toLowerCase();
  }
  C._nt_hash = _nt_hash;

})(typeof globalThis !== 'undefined' ? globalThis : this);
