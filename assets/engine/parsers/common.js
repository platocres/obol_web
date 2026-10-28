/*!
 * obol engine - parsers/common.js  (was _common.js - renamed; GitHub Pages/Jekyll drops underscore-prefixed files)
 * Shared compiled regexes, scoping/validation helpers, and the `_add` dedup primitive.
 * Faithful JS port of 
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
    var r = rx._globalRe || (rx._globalRe = new RegExp(rx.source, rx.flags.indexOf('g') >= 0 ? rx.flags : rx.flags + 'g'));
    r.lastIndex = 0;
    var out = [], m;
    while ((m = r.exec(text)) !== null) {
      out.push(m);
      if (m.index === r.lastIndex) r.lastIndex++;
    }
    return out;
  }
  function reSearch(rx, text) {
    var r = rx.flags.indexOf('g') < 0 ? rx : (rx._searchRe || (rx._searchRe = new RegExp(rx.source, rx.flags.replace('g', ''))));
    return r.exec(text);
  }
  C.reAll = reAll;
  C.reSearch = reSearch;

  // ---- regexes ----------------------------------------- //
  C._IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  C._DOMAIN_RE = /\(domain:([^)]+)\)/i;
  C._NAME_RE = /\(name:([^)]+)\)/i;
  C._NXC_PROTO_REACHABLE_RE = /^(?<proto>LDAP|LDAPS|SMB|WINRM|RDP|SSH|FTP|MSSQL|WMI|VNC|NFS)\s+(?<host>\S+)\s+\d+\s+\S+/im;
  C._SAM_RE = /\bsAMAccountName:\s*([^\s,;]+)/i;
  C._UPN_RE = /\buserPrincipalName:\s*([^\s,;@]+)(?:@[^\s,;]+)?/i;
  // Column 5 is the sAMAccountName. Require an alnum/$ first char so the '-Username-' header row and
  // other dash-led artifacts never match as a user (a real account never starts with '-' or '.').
  C._NXC_USER_ROW_RE = /^(?:LDAP|SMB)\s+\S+\s+\d+\s+\S+\s+(?!\[[^\]]+\]|GROUP-MEM\b|Share\b|Permissions\b|---+)(?:[^\\\s]+\\)?(?<user>[A-Za-z0-9$][A-Za-z0-9._$-]+)\b/im;
  C._NXC_RID_USER_RE = /^(?:(?:SMB|RPC)\s+\S+\s+\d+\s+\S+\s+)?(?:0x[0-9a-f]+|\d+):\s+(?:[^\\\s]+\\)?(?<user>[A-Za-z0-9._$-]{2,})\s+\(SidTypeUser\)/im;
  C._RPC_USER_RE = /\buser:\[(?<user>[^\]]+)\]\s+rid:\[[^\]]+\]|\bAccount:\s*(?:[^\\\s]+\\)?(?<user2>[A-Za-z0-9._$-]{2,})\s+Name:|\bFound user:\s*(?<user3>[A-Za-z0-9._$-]+),\s*uid\s*=\s*\d+|^\s+username:\s*['"]?(?<user4>[A-Za-z0-9._$-]{2,})['"]?\s*$/im;
  C._BASE_DN_RE = /\b(?:namingContexts|defaultNamingContext|rootDomainNamingContext):\s*([A-Za-z0-9_=,.-]+)/i;
  C._ASREP_RE = /(\$krb5asrep\$[^\s]+)/i;
  C._ASREP_USER_RE = /\$krb5asrep\$(?:\d+\$)?(?![0-9a-fA-F]{32}\$[0-9a-fA-F]{32})(?!\d+\$[0-9a-fA-F]{32})(?<user>[^:@$\s)]+)(?:[@$](?![0-9a-fA-F]{32}\b)(?<domain>[A-Za-z0-9_.-]+))?(?=[:$)\s]|$)/i;
  C._TGS_RE = /(\$krb5tgs\$[^\s]+)/i;
  C._TGS_USER_RE = /\$krb5tgs\$(?:\d+\$)?(?![0-9a-fA-F]{32}\$[0-9a-fA-F]{32})(?!\d+\$[0-9a-fA-F]{32})\*?(?<user>[^$*:\s)]+)(?:\$(?![0-9a-fA-F]{32}\b)(?<domain>[A-Za-z0-9_.-]+))?/i;
  C._NTDS_HASH_RE = /(?<![^\s\\:])(?:(?<domain>[^\s\\:]{1,128})\\)?(?<user>[^\s\\:]{1,128}):(?<rid>\d+):[0-9a-fA-F]{32}:(?<nt>[0-9a-fA-F]{32}):::/;
  var NXC_ROW_PREFIX = '(?:(?:SMB|WINRM|WMI|RPC|SSH)\\s+\\S+\\s+\\d+\\s+\\S+\\s+)?';
  C._SYSTEM_ID_RE = /\bnt authority\\system\b/i;
  C._WHOAMI_ID_RE = new RegExp('^' + NXC_ROW_PREFIX + '(?<id>nt authority\\\\system|[A-Za-z0-9][A-Za-z0-9.-]*\\\\[A-Za-z0-9._$-]{2,})\\s*$', 'im');
  C._EXEC_SUCCESS_RE = /\bexecuted command\b|\[\+\]\s+executed|Microsoft Windows \[Version|^[A-Za-z]:\\.*>/im;
  C._LINUX_ID_RE = /\buid=(?<uid>\d+)\((?<user>[^)]+)\)\s+gid=\d+(?:\([^)]*\))?(?:\s+euid=(?<euid>\d+)\((?<euser>[^)]+)\))?(?:\s+egid=\d+(?:\([^)]*\))?)?(?:\s+groups=(?<groups>[^\r\n]+))?/i;
  C._LINUX_ROOT_RE = /\b(?:e?uid)=0\(root\)/i;
  C._PENELOPE_GOT_RE = /got reverse shell from\s+(?<info>.+)/i;
  C._PENELOPE_UPGRADE_RE = /shell upgraded|spawned a pty|upgrading shell to pty/i;
  C._PENELOPE_SID_RE = /session\s*id\s*[:=]?\s*(?<sid>\w+)/i;
  C._PENELOPE_HOST_RE = /\b(?<host>[A-Za-z0-9][\w.-]{0,63})~(?<ip>\d{1,3}(?:\.\d{1,3}){3})/;
  C._ESC_RE = /\bESC(\d{1,2})\b/;
  C._AD_CONTROL_RIGHT_RE = /\b(GenericAll|GenericWrite|WriteDACL|WriteDacl|WriteOwner|FullControl|AllExtendedRights|ForceChangePassword|AddMember|WriteMembers|ReadGMSAPassword|msDS-AllowedToActOnBehalfOfOtherIdentity|AllowedToAct|RBCD|DCSync|GetChanges|GetChangesAll)\b/i;
  C._AD_CONTROL_SUCCESS_RE = /\b(?:success(?:fully)?|modified|changed|granted|added|written|set|able to replicate)\b[^\r\n]{0,200}?\b(?:groupMember|member|owner(?:sid)?|GenericAll|FullControl|DACL|delegation|msDS-AllowedToAct|AllowedToAct|RBCD|rights?|DCSync|replicat)\b|\b(?:groupMember|owner(?:sid)?|GenericAll|FullControl|DACL|delegation|msDS-AllowedToAct|AllowedToAct|RBCD|rights?|DCSync|replicat)\b[^\r\n]{0,200}?\b(?:success(?:fully)?|modified|changed|granted|added|written|set|able to replicate)\b/i;
  C._ADD_COMPUTER_SUCCESS_RE = /\b(?:success(?:fully)?\s+)?(?:added|created)\s+(?:machine|computer)\s+(?:account\s+)?['"]?(?<name>[A-Za-z0-9_.-]+\$?)['"]?/i;
  C._TICKET_FILE_RE = /\b(?:Saving|Saved|Wrote|Writing|Ticket written)\b[^\n]*?(?<file>[A-Za-z0-9_./\\@$+-]+\.(?:ccache|kirbi))/i;
  C._IMPERSONATE_RE = /\bimpersonat(?:e|ing)\s+(?:user\s+)?['"]?(?<user>[A-Za-z0-9._$-]+)/i;
  C._GMSA_HASH_RE = /(?:^|[\s"'])(?:(?<domain>[A-Za-z0-9_.-]{1,64})\\)?(?<user>[A-Za-z0-9._-]{1,64}\$)\s*[:\s]+(?:NTLM|NTHASH|RC4_HMAC|rc4_hmac)\s*[:=]\s*(?<nt>[0-9a-fA-F]{32})/i;
  C._GMSA_READ_ERROR_RE = /\b(no\s+object\s+found|noresulterror|does\s+not\s+exist|not\s+found|access[_\s]?denied|insufficient|denied|unauthorized|traceback|exception)\b/i;
  C._LAPS_PASSWORD_RE = /\b(?:ms-Mcs-AdmPwd|msLAPS-Password|LAPS\s+Password|Password)\s*[:=]\s*(?<pw>\S+)/i;
  C._LAPS_COMPUTER_RE = /\b(?:Computer|Name|sAMAccountName)\s*[:=]\s*(?<computer>[A-Za-z0-9_.-]+\$?)/i;
  C._LAPS_USER_RE = /\b(?:User|Username|Account)\s*[:=]\s*(?<user>[A-Za-z0-9._$-]+)/i;
  C._JOHN_SHOW_RE = /^(?<user>[A-Za-z0-9._$\\/-]{2,}):(?<password>[^:\s][^:\r\n]*)(?::.*)?$/;
  C._JOHN_CRACKED_FOOTER_RE = /\b\d+\s+password\s+hash(?:es)?\s+cracked\b/i;
  // "Loaded N password hash" preamble - gates the LIVE-cracked-line parser so an ordinary
  // `text  (aside)` line elsewhere never trips it.
  C._JOHN_LOADED_RE = /Loaded\s+\d+\s+password\s+hash/i;
  // john's LIVE cracking output (a normal run, not --show) prints each recovered secret as
  // `<plaintext>        (<label>)` - e.g. an archive password `codeblue        (backup.zip)`.
  C._JOHN_CRACKED_LIVE_RE = /^(?<pw>\S[^\r\n]{0,120}?)\s{2,}\((?<label>[^)\r\n]+)\)\s*$/;
  C._CPASSWORD_RE = /\bcpassword\s*=\s*["']?([^"'\s<>]+)/i;
  C._GPP_FILE_RE = /\b(?:Groups|ScheduledTasks|Services|DataSources|Printers|Drives)\.xml\b/i;
  // Whitespace is restricted to [ \t] (not \s) so a greedy trailing match cannot eat the line's own
  // newline and skip the next port row when iterated globally (reAll). A port row is always one line.
  C._NMAP_OPEN_RE = /^(?<port>\d+)\/(?:tcp|udp)[ \t]+open(?![|\w])(?:[ \t]+(?<service>\S+))?(?:[ \t]+(?<version>[^\r\n]*?))?[ \t]*$/im;
  C._NMAP_DISCOVERED_RE = /Discovered open port (?<port>\d+)\/(?<proto>tcp|udp) on (?<host>\S+)/i;
  // The leading "| "/"|_" pipe is nmap's TEXT formatter; the -oX XML carries the same smb-os-discovery
  // lines WITHOUT it (just indentation) inside the <script output="..."> attribute, so the pipe is optional.
  C._NMAP_DOMAIN_NAME_RE = /^\s*\|?_?\s*(?:Domain name|DNS_Domain_Name|NetBIOS_Domain_Name):\s*(?<domain>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_FQDN_RE = /^\s*\|?_?\s*FQDN:\s*(?<fqdn>[A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_COMPUTER_NAME_RE = /^\s*\|?_?\s*(?:Computer name|NetBIOS computer name):\s*(?<name>[A-Za-z0-9_.-]+)\s*$/im;
  C._NMAP_SMB_SIGNING_RE = /Message signing enabled(?: and (?<required>required)| but not required)?|message_signing:\s*(?<mode>disabled|required|supported)/i;
  C._NMAP_HTTP_TITLE_RE = /^\|\s*_?http-title:\s*(?<title>.+)$/im;
  C._NMAP_HTTP_SERVER_RE = /^\|\s*_?http-server-header:\s*(?<header>.+)$/im;
  // "Microsoft-HTTPAPI/2.0" is the Windows HTTP Server API behind WinRM (5985/47001), WSUS and SSDP/UPnP,
  // NOT a browsable web app. A server header that is ONLY this must never mint web.server, or it unlocks the
  // whole web-exploit lane (exposed-files, CMS, Log4Shell...) on a plain AD box and buries the real next move.
  C._isNonWebServerHeader = function (hdr) { return /^microsoft-httpapi\b/i.test(String(hdr || '').trim()); };
  C._NMAP_HTTP_GENERATOR_RE = /^\|\s*_?http-generator:\s*(?<generator>.+)$/im;
  C._NMAP_HTTP_REDIRECT_RE = /^\|\s*_?http-title:\s*Did not follow redirect to (?<location>\S+)/im;
  C._NMAP_FTP_ANON_RE = /ftp-anon:\s*Anonymous FTP login allowed|Anonymous FTP login allowed/i;
  C._NMAP_SSH_HOSTKEY_RE = /^\|_?\s+(?<bits>\d{3,5})\s+(?<fingerprint>[0-9a-f:]{16,})\s+\((?<kind>[^)]+)\)/im;
  C._NMAP_SNMP_FIELD_RE = /^\|_?\s*(?<key>enterprise|name|description|location|contact):\s*(?<value>.+)$/im;
  C._NXC_SIGNING_RE = /\(signing:(?<enabled>True|False)\)/i;
  C._NXC_SMBV1_RE = /\(SMBv1:(?<enabled>True|False)\)/i;
  C._WEB_GOBUSTER_RE = /^\s*(?:Found:\s*)?(?:https?:\/\/[^/\s]+)?(?<path>\/\S*)\s+\(?Status:\s*(?<code>\d{3})\)?/im;
  // feroxbuster result rows: newer builds print a method column ("200  GET  6l  77w  3351c  http://..."),
  // older/default output omits it ("301  9l  28w  313c  http://..."), so the method is optional. Using
  // [A-Za-z]+ (not \w+) for the method keeps it from swallowing the leading line-count ("9l") when absent.
  C._WEB_FEROX_RE = /^\s*(?<code>\d{3})\s+(?:[A-Za-z]+\s+)?\d+l\s+\d+w(?:\s+\d+c)?\s+(?<url>https?:\/\/\S+|\/\S*)/im;
  C._WEB_FFUF_RE = /^\s*(?<token>\S+)\s+\[Status:\s*(?<code>\d{3})/m;
  C._WEB_DIRSEARCH_RE = /^\s*(?:\[\d{2}:\d{2}:\d{2}\]\s+)?(?<code>\d{3})\s+-\s+\S+(?:\s+[KMGT]?B)?\s+-\s+(?:https?:\/\/[^/\s]+)?(?<path>\/\S*)/im;
  C._WEB_WFUZZ_RE = /^\d+:\s+(?:C=)?(?<code>\d{3})\s+\d+\s*L\s+\d+\s*W\s+\d+\s*C[a-z]*\s+"(?<payload>[^"]*)"/m;
  C._WEB_DIRB_RE = /^\+\s+(?<url>https?:\/\/\S+)\s+\(CODE:(?<code>\d{3})/im;
  C._WEB_GOBUSTER_VHOST_RE = /Found:\s*(?<name>\S+)\s+\(?Status:\s*(?<code>\d{3})\)?/i;
  C._NIKTO_FINDING_RE = /^\+\s+(?:OSVDB-\d+:\s+)?(?:(?<path>\/[^\s:]*):\s*)?(?<text>\S.+)$/m;
  C._WEB_PATH_IN_TEXT_RE = /\/[A-Za-z0-9_][A-Za-z0-9_./-]{1,}/;
  C._WEB_INTERESTING_RE = /\/admin|\/api|\/upload|\/backup|\/login|\/dashboard|\/config|\/phpmyadmin|\/wp-admin|\.git|\.svn|\.bak|\.old|\.zip|\.tar|\.sql|\.env|\.config/i;
  C._GIT_HEAD_RE = /\bref:\s+refs\/heads\/(?<branch>[A-Za-z0-9_./-]+)/i;
  C._GIT_DUMPER_SUCCESS_RE = /\b(?:fetching|downloading|downloaded|repository|objects|refs\/heads|HEAD)\b/i;
  C._SOURCE_SECRET_RE = /(?:^|[\s"'`$_])(?<key>password|passwd|pwd|secret|api[_-]?key|token|connection(?:string)?|connstr)\b\s*[:=]\s*(?<value>[^\s"']{4,}|"[^"]{4,}"|'[^']{4,}')/i;
  C._LFI_PASSWD_RE = /root:[^:\n]{0,12}:0:0:[^:\n]*:[^:\n]*:/m;
  C._LFI_PASSWD_SECOND_RE = /^\s*(?:daemon|bin|sys|sync|games|nobody|www-data|sshd|mail|proxy):[^:\n]*:\d+:\d+:/m;
  C._LFI_WIN_INI_RE = /\[(?:extensions|fonts|mci extensions|files|mail)\]|;\s*for 16-bit app support|\[boot loader\]/i;
  C._LFI_FILE_PARAM_RE = /(?:resource=|file:\/\/|=)(?<path>\/[A-Za-z0-9_./-]+|[A-Za-z]:\\[^\s'"&]+)/;
  C._B64_TOKEN_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
  C._CMDI_UID_RE = /\buid=\d+\([^)\n]+\)\s+gid=\d+\([^)\n]+\)/;
  C._CMDI_WIN_RE = /\bnt authority\\+(?:system|network service|local service|iusr)\b|\biis apppool\\[a-z0-9_.-]+|\bMicrosoft Windows \[Version\b/i;
  C._SQL_ERROR_RE = /You have an error in your SQL syntax|Warning:\s*mysqli?_\w+\(\)|supplied argument is not a valid MySQL|SQL syntax[^\r\n]{0,160}?(?:MariaDB|MySQL) server|Unclosed quotation mark after the character string|quoted string not properly terminated|Incorrect syntax near|Microsoft OLE DB Provider for (?:ODBC Drivers|SQL Server)|System\.Data\.SqlClient\.SqlException|Unknown column '[^']+' in 'where clause'|ORA-\d{5}|PostgreSQL query failed|pg_query\(\)|pg_exec\(\)|SQLSTATE\[\w+\]|java\.sql\.SQLException|SQLite3?::(?:query|exec)|near "[^"\r\n]{1,120}": syntax error/i;
  C._IMDS_MARKER_RE = /\b(?:ami-id|instance-id|instance-action|iam\/security-credentials|meta-data\/|security-credentials|placement\/availability-zone|block-device-mapping|public-keys\/|reservation-id|compute\.azEnvironment|Metadata-Flavor:\s*Google)\b/i;
  C._AWS_KEY_RE = /"AccessKeyId"\s*:\s*"(?<akid>(?:AKIA|ASIA)[A-Z0-9]{8,})"/;
  C._AWS_SECRET_RE = /"SecretAccessKey"\s*:\s*"(?<secret>[^"\n]{8,})"/;
  C._AWS_TOKEN_RE = /"Token"\s*:\s*"(?<token>[^"\n]{16,})"/;
  C._NOSQL_OP_RE = /\[\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)\]|"\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|expr|function)"|%5[Bb]%24(?:ne|gt|gte|lt|lte|regex|in|nin|where)%5[Dd]/i;
  C._NOSQL_SUCCESS_RE = /"(?:success|authenticated|isAdmin|admin|loggedin|logged_in)"\s*:\s*true|"(?:token|jwt|session|auth_token|accessToken)"\s*:\s*"[^"\n]{8,}"|\bLogin successful\b|\bWelcome back\b|\bAuthentication succeeded\b/i;
  C._SET_COOKIE_SESSION_RE = /^\s*(?:<\s*)?Set-Cookie:\s*(?:session|connect\.sid|token|auth|PHPSESSID|jwt|jsessionid)\b/im;
  C._LOGIN_REDIRECT_RE = /^\s*(?:<\s*)?Location:\s*\S*\/(?:admin|dashboard|home|profile|account|portal|welcome)\b/im;
  C._JWT_TOOL_KEY_RE = /(?<secret>\S{1,64})\s+is the CORRECT key|(?:key confirmed|correct key|signing key(?:\s+found)?)\s*[:=]\s*['"]?(?<secret2>\S{1,64})/i;
  C._JWT_HASHCAT_RE = /^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+:(?<secret>\S+)\s*$/m;
  C._JWT_FORGE_RE = /"alg"\s*:\s*"none"|hbGciOiJub25l|-X\s+a\b|--exploit\s+a\b|-I\s+-pc\b/i;
  C._WEB_AUTHZ_SUCCESS_RE = /"(?:isAdmin|is_admin|admin)"\s*:\s*(?:true|"?admin(?:istrator)?"?)|"role"\s*:\s*"admin(?:istrator)?"|\bWelcome,?\s+admin(?:istrator)?\b|\bAdmin(?:istrator)?\s+(?:Dashboard|Panel|Console|Area)\b/i;
  C._NIKTO_NOISE_PREFIXES = ['target ip', 'target hostname', 'target port', 'start time', 'end time', 'server:', 'ssl info', 'root page', 'retrieved', 'no cgi', 'scan terminated', 'host(s) tested', 'requests:', '0 host', '1 host'];
  C._SQLMAP_VULN_RE = /\b(?:parameter\s+['"][^'"\r\n]{1,120}['"]\s+is vulnerable|is vulnerable to [^\r\n]{1,80}?sql injection|appears to be [^\r\n]{1,80}?sql injectable|sqlmap identified the following injection point|Parameter:\s*\S+\s+\((?:GET|POST|URI|Cookie|HEADER)\))/i;
  C._SQLMAP_DBMS_RE = /\bback-end DBMS:\s*(?<dbms>[^\r\n]+)/i;
  C._SQLMAP_DATABASE_HEADER_RE = /\bavailable databases\s*\[(?<count>\d+)\]/i;
  C._SQLMAP_STAR_ROW_RE = /^\[\*\]\s+(?<name>[A-Za-z0-9_$.-]{1,80})\s*$/m;
  C._SQLMAP_TABLE_RE = /\bDatabase:\s*(?<database>[A-Za-z0-9_$.-]+)\s*\n(?:\[[^\n]+\]\s*)?Table:\s*(?<table>[A-Za-z0-9_$.-]+)/i;
  C._SQLMAP_DUMP_RE = /\b(?:dumped|dumping)\b[^\r\n]{1,120}?\b(?:entries|CSV file|table)\b/i;
  C._SQLMAP_OS_SHELL_RE = /(?:^|\s)os-shell\s*>|going to use a web backdoor|web backdoor[^\r\n]{0,80}?(?:uploaded|created|saved)|command shell session/i;
  C._HTTP_STATUS_RE = /^\s*(?:<\s*)?HTTP\/\S+\s+(?<status>\d{3})(?:\s+(?<reason>.*))?$/im;
  C._HTTP_HEADER_RE = /^\s*(?:<\s*)?(?<key>Server|X-Powered-By|Location|Content-Type):\s*(?<value>.+)$/im;
  C._WHATWEB_PLUGIN_RE = /\b(?<name>[A-Za-z][A-Za-z0-9_.+-]{1,30})\[(?<value>[^\]\r\n]{1,120})\]/;
  C._SSH_BANNER_RE = /\bSSH-(?<version>[12]\.\d+)-(?<banner>[^\r\n]+)/i;
  C._FTP_BANNER_RE = /^(?:220[- ](?<banner>.+)|230[- ](?<login>(?:Login successful|User logged in|Anonymous access granted|Anonymous user logged in|Guest login ok).*))$/im;
  C._SNMP_SYSDESCR_RE = /(?:SNMPv2-MIB::sysDescr\.0|(?:iso|\.?1)\.3\.6\.1\.2\.1\.1\.1\.0)\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSNAME_RE = /(?:SNMPv2-MIB::sysName\.0|(?:iso|\.?1)\.3\.6\.1\.2\.1\.1\.5\.0)\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSLOCATION_RE = /(?:SNMPv2-MIB::sysLocation\.0|(?:iso|\.?1)\.3\.6\.1\.2\.1\.1\.6\.0)\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;
  C._SNMP_SYSCONTACT_RE = /(?:SNMPv2-MIB::sysContact\.0|(?:iso|\.?1)\.3\.6\.1\.2\.1\.1\.4\.0)\s*=\s*(?:STRING:\s*)?(?<value>.+)/i;

  C._OS_SIGNATURES = {
    windows: [
      /\bMicrosoft Windows\b/i, /\bWindows\s+(?:Server|\d|XP|Vista)\b/i,
      /\bOS:\s*Windows\b/i, /\bRunning:\s*(?:Microsoft\s+)?Windows\b/i,
      /cpe:\/o:microsoft:windows/i, /\bMicrosoft-IIS\b/i,
      /\bASP\.NET\b/i, /\bWin(?:32|64)\b/i, /\bMicrosoft FTP Service\b/i,
      /\bMicrosoft-HTTPAPI\b/i, /\bWindows NT\b/i, /\bActive Directory\b/i,
      /\bms-wbt-server\b/i,
    ],
    linux: [
      /\bLinux\b/i, /\bUbuntu\b/i, /\bDebian\b/i, /\bCentOS\b/i, /\bRed Hat\b/i,
      /\bFedora\b/i, /\bSamba\b/i, /\bUnix\b/i, /cpe:\/o:linux/i,
      /\bKali\b/i, /\bAlpine\b/i, /\bArch Linux\b/i, /\bGentoo\b/i,
      /\bRocky Linux\b/i, /\bAlmaLinux\b/i, /\bopenSUSE\b/i, /\bSUSE\b/i,
      /\bOracle Linux\b/i, /\bFreeBSD\b/i,
    ],
  };

  C._LINUX_PRIVESC_ACTION_IDS = new Set([
    'linux-enum', 'sudo-abuse', 'writable-passwd', 'nfs-squash', 'lxc-lxd-escape',
    'docker-socket', 'suid-gtfobins', 'pspy-monitor', 'cron-abuse', 'capabilities',
    'linux-loot-hunt', 'linux-persistence', 'dirtycow', 'dirtypipe', 'baron-samedit',
    'polkit-abuse', 'linux-kernel-exploit', 'screen-suid-privesc', 'chkrootkit-local-privesc',
    'Shared-object-injection', 'shared-obj-hijack', 'wildcards-tar-rsync', 'wildcard-injection',
    'systemd-service-abuse', 'systemd-timer-abuse', 'env-path-hijack', 'linux-path-hijack',
    'python-library-hijack', 'npm-package-privesc', 'doas-privesc', 'doas-conf-abuse',
    'logrotate-exploitation', 'logrotate-race', 'container-escape',
    'ansible-playbook-injection', 'consul-service-rce', 'couchdb-admin-party-privesc',
    'privesc-shell-upgrade'
  ]);
  C._WINDOWS_PRIVESC_ACTION_IDS = new Set([
    'windows-enum', 'win-privesc-triage', 'seimpersonate', 'win-token-impersonation',
    'unquoted-service-path', 'weak-service-permissions', 'win-service-abuse',
    'windows-service-dacl-abuse', 'alwaysinstallelevated', 'win-registry-alwaysinstall',
    'dpapi-secrets', 'stored-credentials', 'wesng-patch-gaps',
    'windows-persistence', 'lsass-dump-onbox', 'printspoofer-namedpipe',
    'windows-namedpipe-impersonation', 'potato-family', 'dll-hijacking', 'win-dll-hijack',
    'scheduled-tasks', 'win-scheduled-tasks', 'uac-bypass', 'wifi-passwords',
    'sebackup-serestore', 'print-operators-privesc', 'server-operators-privesc',
    'autorun-binary-hijack', 'wsl-local-privesc', 'com-hijack'
  ]);
  C._PRIVESC_ACTION_IDS = new Set([].concat(
    Array.from(C._LINUX_PRIVESC_ACTION_IDS),
    Array.from(C._WINDOWS_PRIVESC_ACTION_IDS)
  ));
  C._WEB_LFI_ACTION_IDS = new Set(['lfi-probe', 'lfi-secret-harvest', 'xxe', 'php-filter-chain', 'zip-slip', 'phpmyadmin-lfi', 'file-read-lfi']);
  C._WEB_CMDI_ACTION_IDS = new Set(['command-injection', 'ssti', 'ssti-rce', 'web-shells', 'file-upload', 'verb-tampering', 'deserialization', 'tomcat-deploy', 'jenkins-access', 'check-struts2', 'ssti-to-rce', 'http-put-webshell', 'authz-abuse', 'mssql-xp-cmdshell', 'mysql-outfile-rce', 'postgres-copy-rce', 'cacti-cmdinjection', 'text4shell', 'check-log4shell']);
  // The web-exploit moves whose whole point IS landing code execution: when their paste shows command
  // output (uid=/whoami/nt authority), that IS a web foothold, so _parse_web_cmdi mints foothold.webshell
  // for these (not for the confirm-only probes, whose foothold is a separate follow-up move).
  C._WEB_RCE_FOOTHOLD_IDS = new Set(['ssti-to-rce', 'ssti-rce', 'http-put-webshell', 'authz-abuse', 'mysql-outfile-rce', 'file-upload']);
  // Service moves that land a *nix shell but whose command tool is not one the command-keyed dispatch
  // recognises (curl to the Elasticsearch API, rsync, an NFS mount + ssh): keyed by actionId so a pasted
  // `uid=` proof still mints foothold.linux through the shared ssh-exec reader.
  C._LINUX_SHELL_ACTION_IDS = new Set(['rsync-write-shell', 'nfs-to-foothold', 'elasticsearch-rce', 'tftp-write-shell', 'vnc-desktop-shell']);
  C._WEB_SQLI_ACTION_IDS = new Set(['sqli-basics', 'manual-sqli-exploitation', 'second-order-sqli']);
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
  C._AD_ABUSE_ACTION_IDS = new Set(['bloodyad-acl', 'ad-acl-abuse', 'delegation-abuse', 'getst-impersonation', 'gmsa-read', 'laps-read', 'ticket-reuse', 'kerberos-tickets', 'golden-ticket', 'silver-ticket', 'diamond-ticket']);

  C._UNAME_RE = /\bLinux\s+(?<host>\S+)\s+(?<kernel>[0-9][^\s]+)[^\r\n]{0,200}?\b(?<arch>x86_64|i[3-6]86|aarch64|armv\w+)\b/i;
  C._SUID_PATH_RE = /(?<path>\/[A-Za-z0-9_./+-]+)/;
  C._SUID_INTERESTING = /^(?:bash|sh|dash|zsh|ksh|csh|tcsh|ash|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|nodejs|lua[0-9.]*|find|vim|vi|nvim|nano|emacs|ed|less|more|man|awk|gawk|mawk|nawk|sed|tar|zip|unzip|gzip|bzip2|xz|7z|cp|mv|dd|cat|head|tail|tee|cut|sort|uniq|base64|xxd|od|strings|readelf|file|grep|egrep|fgrep|rsync|scp|sftp|ftp|curl|wget|nc|netcat|ncat|socat|openssl|ssh-keygen|git|gdb|strace|ltrace|tcpdump|nmap|docker|lxc|lxd|kubectl|systemctl|journalctl|service|env|time|timeout|watch|xargs|stdbuf|setarch|ionice|nice|taskset|flock|chroot|unshare|nsenter|capsh|pkexec|doas|screen(?:-[0-9.]+)?|tmux|exim4?|sendmail|aria2c|restic|borg|kopia|rclone)$/i;
  C._DANGEROUS_CAPS = /\bcap_(?:setuid|setgid|dac_override|dac_read_search|chown|fowner|sys_admin|sys_ptrace|sys_module|sys_rawio|sys_chroot|net_admin|bpf|perfmon)\b/i;
  C._LOCAL_FILE_SECRET_RE = /(?:^|[\s"'`$_])(?:password|passwd|pwd|api[_-]?key|secret|token|connectionstring)\s*[=:]\s*['"]?\S{3,}|-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----/i;
  C._CAPABILITY_RE = /^\s*(?<path>\/\S+)\s*(?:=\s*|\s+)(?<caps>cap_[a-z0-9_,]+?[+=][eip]+[^\r\n#]*)$/im;
  C._PASSWD_MODE_RE = /^\s*(?<mode>-[rwxstST-]{9}[.+]?)\s+[^\r\n]{1,120}?\s+(?<path>\/etc\/(?:passwd|shadow))\b/m;
  C._WIN_PRIV_RE = /^\s*(?<name>Se[A-Za-z0-9]+Privilege)\b[^\r\n]{1,120}?\b(?<state>Enabled|Disabled|Habilitada?|Deshabilitada?)\s*$/im;
  C._SYSTEMINFO_FIELD_RE = /^\s*(?<key>OS Name|OS Version|System Type):\s*(?<value>.+)$/im;
  C._DANGEROUS_WIN_PRIVS = new Set(['seimpersonateprivilege', 'seassignprimarytokenprivilege', 'sedebugprivilege', 'sebackupprivilege', 'serestoreprivilege', 'setakeownershipprivilege', 'seloaddriverprivilege', 'semanagevolumeprivilege', 'setcbprivilege']);
  C._AIE_VALUE_RE = /AlwaysInstallElevated\s+REG_DWORD\s+0x(?<val>[0-9a-fA-F]+)/i;
  C._HKLM_HEADER_RE = /^\s*(?:HKEY_LOCAL_MACHINE|HKLM)\b/i;
  C._HKCU_HEADER_RE = /^\s*(?:HKEY_CURRENT_USER|HKCU)\b/i;
  C._WEAK_SVC_ACCESS_RE = /\b(?:SERVICE_CHANGE_CONFIG|SERVICE_ALL_ACCESS|SERVICE_CHANGE|CHANGE_CONFIG|WRITE_DAC|WRITE_OWNER|AllAccess)\b/i;
  C._WEAK_SERVICE_PERM_RE = /Service\s+"?([^"\r\n]+)"?\s+has\s+weak\s+permissions|\b(?:SERVICE_CHANGE_CONFIG|SERVICE_ALL_ACCESS|SERVICE_CHANGE|CHANGE_CONFIG|WRITE_DAC|WRITE_OWNER)\b|\bAllAccess\b.*\b(?:Everyone|Users|Authenticated Users|INTERACTIVE)\b/i;
  C._LOWPRIV_WRITE_ACE_RE = /(?:BUILTIN\\Users|NT AUTHORITY\\(?:Authenticated Users|INTERACTIVE)|Authenticated Users|Everyone|INTERACTIVE|\bUsers)\s*:\s*\([^)]*[FMW][^)]*\)|\bAllAccess\b.*\b(?:Everyone|Users|Authenticated Users|INTERACTIVE)\b/i;
  C._ANSI_RE = /\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][AB012])/g;
  C._ID_LINE_RE = /\b(?:e?uid)=\d+\(/i;
  C._CVE_RE = /CVE-\d{4}-\d{3,7}/i;
  C._EXPLOIT_PROBABILITY_RE = /\b(?:\d{1,3}\s?%|highly probable|probable|exposure|vulnerable|exploitable)\b/i;
  C._KERNEL_EXPLOIT_NAMES = ['pwnkit', 'dirtycow', 'dirty cow', 'dirtypipe', 'dirty pipe', 'polkit', 'pkexec', 'baron samedit', 'overlayfs', 'af_packet', 'ptrace', 'netfilter', 'sequoia', 'looney tunables', 'gameoverlay', 'nftables', 'sudoedit', 'snapd', 'dirtysock'];
  C._KERNEL_EXPLOIT_NEGATION_RE = /\bnot\s+(?:vulnerable|exploitable|affected|applicable)\b|\bpatched\b|\bnot\s+a\s+match\b|\bn\/a\b/i;
  C._NXC_AUTH_RE = /^\s*(?<proto>SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+(?<host>\S+)\s+\d+\s+\S+\s+\[\+\]\s+(?<auth>.+)$/im;
  C._AUTH_MATERIAL_RE = /^(?:(?<domain>[^\\\s:/]+)\\)?(?<user>[A-Za-z0-9._$-]{2,}):(?<secret>[^\s()]+)/;
  C._NT_HASH_RE = /^(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$/;
  C._EW_PROMPT_RE = /\*Evil-WinRM\*\s+PS\s+/i;
  C._BH_ZIP_RE = /(?<![\w.-])[\w.-]{1,120}\.zip\b/i;
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
  C._WPSCAN_VULN_RE = /\[!\]\s*Title:\s*(?<t>[^\r\n]+?)\s*$/m;
  C._WPSCAN_VERSION_RE = /WordPress version\s+(?<v>\d[\w.]+)/i;
  C._WPSCAN_LOGIN_RE = /\[SUCCESS\]\s*-\s*(?<u>[^/\r\n]{1,80}?)\s*\/\s*(?<p>\S[^\r\n]{0,120}?)\s*$/m;
  C._SQL_VERSION_BANNER_RE = /\b\d+\.\d+\.\d+[\w.-]*-?(?:MariaDB|MySQL)\b|\bMySQL\s+\d+\.\d+|Microsoft SQL Server\s+\d{4}|PostgreSQL\s+\d+\.\d+/i;
  C._TRUST_NLTEST_RE = /^\s*\d+:\s+\S+\s+(?<fqdn>[A-Za-z0-9-]+\.[A-Za-z0-9.-]+)/m;
  C._TRUST_DOMAINTRUST_RE = /TargetName\s*[:=]\s*(?<fqdn>[A-Za-z0-9][A-Za-z0-9.-]+)/i;
  C._DOMAIN_SID_RE = /Domain SID(?:\s+is|\s*:)\s*[:=]?\s*(?<sid>S-1-5-21-[0-9-]+)/i;

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
      if (e.kind === fact.kind && e.scope === fact.scope && e.state === fact.state && F.valuesEqual(e.value, fact.value)) return;
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

  function _clean_os_string(str) {
    if (!str) return '';
    str = String(str).trim();
    var cpeM = str.match(/cpe:\/o:([a-z0-9_-]+):([a-z0-9_.:-]+)/i);
    if (cpeM) {
      var vendor = cpeM[1].toLowerCase();
      var prodParts = cpeM[2].split(':');
      var decoded = prodParts.join(' ')
        .replace(/_/g, ' ')
        .replace(/\bwindows\b/gi, 'Windows')
        .replace(/\bserver\b/gi, 'Server')
        .replace(/\br2\b/gi, 'R2')
        .replace(/\bsp(\d+)\b/gi, 'SP$1')
        .replace(/\bsp\b/gi, 'SP')
        .replace(/\s{2,}/g, ' ')
        .trim();
      if (/windows/i.test(decoded)) return decoded.indexOf('Windows') === 0 ? decoded : ('Windows ' + decoded);
      if (/ubuntu/i.test(decoded)) return decoded.indexOf('Ubuntu') === 0 ? decoded : ('Ubuntu ' + decoded);
      if (/debian/i.test(decoded)) return decoded.indexOf('Debian') === 0 ? decoded : ('Debian ' + decoded);
    }
    return str.replace(/;\s*CPE:.*$/i, '').trim();
  }
  C._clean_os_string = _clean_os_string;

  // Pull a SPECIFIC OS product ("Windows Server 2016 Standard 14393", "Ubuntu 20.04") out of an
  // authoritative LABELLED line: smb-os-discovery / nmap OS detection / systeminfo (OS: / OS
  // details: / Running:), or NetExec SMB banner ([*] Windows 7 / Server 2008 R2...).
  function _os_matches_family(str, family) {
    var s = String(str || '');
    if (family === 'windows') {
      if (/\bSamba\b|Windows 6\.1 Build 0\b/i.test(s)) return false;
      return /\b(?:Windows|Microsoft|Win32|Win64)\b/i.test(s);
    }
    if (family === 'linux') {
      return /\b(?:Linux|Ubuntu|Debian|CentOS|Red Hat|Fedora|Samba|Unix|Kali|Alpine|Arch|Gentoo|Rocky|AlmaLinux|openSUSE|SUSE|Oracle Linux|FreeBSD)\b/i.test(s);
    }
    return s.toLowerCase().indexOf(family) >= 0;
  }

  function _os_product_from_label(text, family) {
    text = text || '';
    if (family === 'windows' && (/Windows 6\.1 Build 0\b/i.test(text) || /\bSamba\b/i.test(text))) {
      return '';
    }
    // 1) NetExec banner: [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC)...
    var nxcRe = /\[\*\]\s+((?:Windows|Linux|Unix|Samba|Ubuntu|Debian|FreeBSD)[^\(\r\n]+?)(?:\s*\((?:name|domain|signing|SMBv1|Null Auth)|$)/im;
    var nm = nxcRe.exec(text);
    if (nm && nm[1]) {
      var np = nm[1].trim();
      if (np && _os_matches_family(np, family)) return _clean_os_string(np).slice(0, 80);
    }

    // 2) OS: / OS details: / Running:
    var re = /\b(?:OS(?:\s*details)?|Running)\s*:\s*([^\n|]+)/gi;
    var m;
    while ((m = re.exec(text))) {
      var raw = m[1].trim()
        .replace(/[ \t]+(microsoft-ds|netbios-ssn|msrpc|microsoft-rpc|workgroup)\b[^\r\n]*$/i, '')
        .replace(/[.,;]+\s*$/, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
      var p = _clean_os_string(raw);
      if (p && _os_matches_family(p, family)) return p.slice(0, 80);
    }

    // 3) Additional OS product labels (/etc/os-release, lsb_release, ver, systeminfo, service banners)
    if (family === 'linux') {
      var pm = /PRETTY_NAME\s*=\s*["']?([^"'\r\n]+)["']?/i.exec(text);
      if (pm && pm[1]) return pm[1].trim().slice(0, 80);
      var dm = /Description:\s*([^\r\n]+)/i.exec(text);
      if (dm && dm[1] && _os_matches_family(dm[1], 'linux')) return dm[1].trim().slice(0, 80);
      var lm = /\b(Ubuntu[\s0-9.]*|Debian[^\s);,]*|CentOS[\s0-9.]*|Red Hat[^\r\n,;)]*|Fedora[\s0-9.]*|FreeBSD[\s0-9.]*|Alpine[\s0-9.]*)/i.exec(text);
      if (lm && lm[1]) return lm[1].trim().slice(0, 80);
    } else if (family === 'windows') {
      var vm = /Microsoft Windows \[Version\s+([0-9.]+)\]/i.exec(text);
      if (vm && vm[1]) return ('Windows (Build ' + vm[1].trim() + ')').slice(0, 80);
      var sm = /^\s*OS Name:\s*(Microsoft Windows[^\r\n]+)/im.exec(text);
      if (sm && sm[1]) return sm[1].trim().slice(0, 80);
      var wm = /\b(Windows Server 20\d\d(?:\s+R2)?[^\r\n,;()]*|Windows (?:10|11|7|8(?:\.1)?|XP)[^\r\n,;()]*)/i.exec(text);
      if (wm && wm[1] && !/Windows 6\.1 Build 0\b/i.test(wm[1])) return wm[1].trim().slice(0, 80);
    }
    return '';
  }
  C._os_product_from_label = _os_product_from_label;

  function _add_os_observation(facts, ws, source, family, evidence, confidence, tool, promote, product) {
    family = (family || '').trim().toLowerCase();
    if (family !== 'windows' && family !== 'linux') return;
    var value = { family: family, confidence: confidence, tool: tool, evidence: (evidence || '').trim().slice(0, 220) };
    var prod = (product || '').trim();
    // only keep a product that is richer than the bare family word (a real version string)
    if (prod && prod.toLowerCase() !== family) value.os = prod.slice(0, 80);
    _add(facts, mkFact('host.os_hint', 'host:' + ws.target, value, ProofState.SUPPORTED, source));
    if (promote) _add(facts, mkFact('host.os_family', 'host:' + ws.target, value, ProofState.SUPPORTED, source));
  }
  C._add_os_observation = _add_os_observation;

  function _strip_proxychains(text) {
    if (!text) return '';
    var s = String(text);
    if (s.indexOf('[proxychains]') < 0 && s.indexOf('-chain|-<>-') < 0 && s.indexOf('|DNS-') < 0) return s;
    return s
      .replace(/^\s*\[proxychains\][^\r\n]*?\b(?:OK|timeout|closed|denied)[ \t]*(?=\S)/gim, '')
      .replace(/^\s*\[proxychains\][^\r\n]*$/gim, '')
      .replace(/\[proxychains\][^\r\n]*/gi, '')
      .replace(/^\s*\|(?:[SDR]-chain\|-<>-|DNS-request\||DNS-response\|)[^\r\n]*$/gim, '');
  }
  C._strip_proxychains = _strip_proxychains;

  var _CR_PROGRESS_RE = /^\s*(?:::?\s*Progress\b|\[\s*\d+(?:\.\d+)?%\s*\]|\d{1,3}(?:\.\d+)?%\s*\[|(?:Progress|Speed|Time\.+|Status\.+|Restore\.+|Rejected\.+)\s*:|\[\s*[+#=>-]{3,}\s*\])/i;
  function _normalize_cr(text) {
    if (!text) return '';
    var s = String(text);
    if (s.indexOf('\r') < 0) return s;
    s = s.replace(/\r+\n/g, '\n');
    if (s.indexOf('\r') < 0) return s;
    return s.split('\n').map(function (line) {
      if (line.indexOf('\r') < 0) return line;
      var parts = line.split('\r').filter(function (p) { return p.trim().length > 0; });
      if (!parts.length) return '';
      for (var i = parts.length - 1; i >= 0; i--) {
        if (!_CR_PROGRESS_RE.test(parts[i])) return parts[i];
      }
      return parts[parts.length - 1];
    }).join('\n');
  }
  C._normalize_cr = _normalize_cr;

  function _strip_tmux_split(text) {
    if (!text) return '';
    var s = String(text);
    if (s.indexOf('\u2502') >= 0 || s.indexOf('\u2503') >= 0 || s.indexOf('\u2551') >= 0) {
      s = s.replace(/^([^\r\n\u2500-\u257f]+?)[ \t]+[\u2502\u2503\u2551](?:[ \t][^\r\n]*)?$/gm, '$1');
    }
    if (s.indexOf('|') >= 0) {
      s = s.replace(/^([^\r\n|]+?)[ \t]+\|[ \t]+(?:(?:kali|parrot|root|htb-[a-z0-9_-]+)@[a-z0-9_.-]+|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[~\/][^\r\n]*[$#]|┌──\(|└─[$#]|PS [A-Za-z]:\\)[^\r\n]*$/gim, '$1');
    }
    return s;
  }
  C._strip_tmux_split = _strip_tmux_split;

  function _unwrap_kerberos_hashes(text) {
    if (!text) return '';
    var s = String(text);
    if (s.indexOf('$krb5tgs$') < 0 && s.indexOf('$krb5asrep$') < 0 && s.indexOf('$DCC2$') < 0) return s;
    var lines = s.split('\n');
    var out = [];
    var inKrb = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      if (inKrb && trimmed && !/^\$(?:krb5|DCC2)/i.test(trimmed)
        && !/^\[[-+*!]\]|^(?:SMB|LDAP|WINRM|MSSQL|SSH|FTP|RDP)\s+|^(?:Session|Status|Hash|Time|Speed|Recovered|Progress|Restore|Rejected|Candidates|Started|Stopped)\.*:|^(?:Loaded\s+\d+|ServicePrincipalName\b|---)/i.test(trimmed)
        && !/^(?:ok|no|on|in|to|of|is|it|at|by|or|as|up|if|be|do)$/i.test(trimmed)
        && (/^(?:[0-9a-fA-F*$]+(?::[^\s:]+)?|:[^\s:]+|[A-Za-z0-9_./:@$-]*\*\$[0-9a-fA-F*$]+)$/.test(trimmed))) {
        out[out.length - 1] = out[out.length - 1].replace(/[ \t]+$/, '') + trimmed;
      } else {
        out.push(line);
        inKrb = /\$krb5(?:tgs|asrep)\$|\$DCC2\$/i.test(line);
      }
    }
    return out.join('\n');
  }
  C._unwrap_kerberos_hashes = _unwrap_kerberos_hashes;

  function _add_os_from_text(text, ws, source, facts, tool, confidence, promote) {
    confidence = confidence || 'high';
    text = text || '';
    // Strip proxychains wrapper lines, tmux split-pane bleed, and attacker Kali/Parrot prompt header lines so they never match Linux OS signatures
    var cleanText = _strip_tmux_split(_strip_proxychains(text))
      .replace(/^\s*(?:┌──\([^\r\n]*|└─[$#]\s*[^\r\n]*|(?:kali|parrot|root)@(?:kali|parrot)[^\r\n]*[$#]\s*[^\r\n]*)$/gim, '')
      .replace(/[ \t]*(?:┌──\([^\r\n]*|└─[$#]\s*[^\r\n]*|\b(?:kali|parrot|root)@(?:kali|parrot)[^\r\n]*)/gi, '');
    var matches = {};
    Object.keys(C._OS_SIGNATURES).forEach(function (family) {
      var pats = C._OS_SIGNATURES[family];
      for (var i = 0; i < pats.length; i++) {
        var m = reSearch(pats[i], cleanText);
        if (m) { matches[family] = _line_for_match(cleanText, m) || m[0]; break; }
      }
    });
    if (/Windows 6\.1 Build 0\b/i.test(cleanText) || /\bSamba\b/i.test(cleanText)) {
      var win61 = reSearch(/Windows 6\.1 Build 0\b|\bSamba\b/i, cleanText);
      if (win61 && !matches.linux) matches.linux = _line_for_match(cleanText, win61) || win61[0];
      delete matches.windows;
    }
    if (matches.windows && matches.linux) {
      var sambaCollision = /(?:Windows[^\r\n]{0,200}(?:Samba|Debian|Ubuntu)|(?:Samba|Debian|Ubuntu)[^\r\n]{0,200}Windows)/i.test(cleanText) || /Windows 6\.1 Build 0\b/i.test(cleanText);
      if (sambaCollision) {
        delete matches.windows;
      } else if ((/OS(?:\s*details)?:\s*(?:Microsoft\s+)?Windows\b/i.test(cleanText) || /Service Info:[^\r\n]{0,160}?\bOS:\s*Windows\b/i.test(cleanText) || /Running:\s*(?:Microsoft\s+)?Windows\b/i.test(cleanText) || /Microsoft Windows \[Version/i.test(cleanText) || /\[\*\]\s*Windows\b/i.test(cleanText)) && !/\bSamba\b/i.test(cleanText)) {
        delete matches.linux;
      }
    }
    var keys = Object.keys(matches);
    var promoteSingle = promote && keys.length === 1;
    keys.forEach(function (family) {
      _add_os_observation(facts, ws, source, family, matches[family], confidence, tool, promoteSingle, _os_product_from_label(cleanText, family));
    });
  }
  C._add_os_from_text = _add_os_from_text;

  function _check_linux_kernel_vulns(kernelStr, ws, source, facts, leadKinds) {
    var ks = String(kernelStr || '').trim();
    var m = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(ks);
    if (!m) return;
    var major = parseInt(m[1], 10), minor = parseInt(m[2], 10), patch = m[3] !== undefined ? parseInt(m[3], 10) : 0;
    var h = 'host:' + ws.target;
    if ((major === 2 && minor === 6 && patch >= 22) || (major === 2 && minor > 6) || major === 3 || (major === 4 && (minor < 8 || (minor === 8 && patch < 3)))) {
      _add(facts, mkFact('vuln.dirtycow', h, { cve: 'CVE-2016-5195', kernel: ks, via: 'kernel-version', lead: true }, ProofState.SUPPORTED, source));
      _add(facts, mkFact('privesc.kernel_exploit', h, { cves: ['CVE-2016-5195'], names: ['dirtycow'], kernel: ks, via: 'kernel-version' }, ProofState.SUPPORTED, source));
      if (leadKinds) leadKinds['privesc.kernel_exploit'] = true;
    }
    if (major === 5 && (minor > 8 || (minor === 8 && patch >= 0)) && (minor < 16 || (minor === 16 && patch < 11))) {
      if (!(major === 5 && minor === 10 && patch >= 102) && !(major === 5 && minor === 15 && patch >= 25)) {
        _add(facts, mkFact('vuln.dirtypipe', h, { cve: 'CVE-2022-0847', kernel: ks, via: 'kernel-version', lead: true }, ProofState.SUPPORTED, source));
        _add(facts, mkFact('privesc.kernel_exploit', h, { cves: ['CVE-2022-0847'], names: ['dirtypipe'], kernel: ks, via: 'kernel-version' }, ProofState.SUPPORTED, source));
        if (leadKinds) leadKinds['privesc.kernel_exploit'] = true;
      }
    }
  }
  C._check_linux_kernel_vulns = _check_linux_kernel_vulns;

  function _clean_username(user) {
    user = stripChars((user || '').trim(), ';:');
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
    // A real sAMAccountName never starts with '-' or '.'. A leading dash is the tell of a column
    // header ('-Username-') or a flag token that leaked out of tabular tool output, never an account.
    if (/^[-.]/.test(user)) return false;
    return /^[A-Za-z0-9._$-]{2,}$/.test(user);
  }
  C._valid_username = _valid_username;

  function _valid_password(password) {
    password = (password || '').trim();
    if (!password || ['?', '*', '!', '!!', 'x', 'NP', '<password>', '{{password}}', '(null)', 'null', 'none'].indexOf(password) >= 0) return false;
    if (/^(?:\*+|!+|no\s+password\*+)$/i.test(password)) return false;
    var l = password.toLowerCase();
    if (l === '(null)' || l === 'null' || l.indexOf('status') === 0 || l.indexOf('recovered') === 0 || l.indexOf('progress') === 0 || l.indexOf('guess') === 0 || l.indexOf('no password') === 0) return false;
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
        var raw = (m.groups && (m.groups.user || m.groups.user2 || m.groups.user3 || m.groups.user4)) || '';
        var user = _clean_username(raw);
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
    return cmd.indexOf(' smb ') >= 0 || cmd.indexOf('smbclient') >= 0 || cmd.indexOf('rpcclient') >= 0 || cmd.indexOf('enum4linux') >= 0 || cmd.indexOf('smbmap') >= 0 || cmd.indexOf('lookupsid') >= 0 || cmd.indexOf('samrdump') >= 0;
  }
  C._is_smb_command = _is_smb_command;

  function _is_cracking_command(command) {
    var l = ' ' + command.toLowerCase() + ' ';
    return /(?:^|[\s/\\])hashcat(?:\.bin|\.exe)?(?:\s|$)/i.test(l) || /(^|[\s/\\])john(?:\.exe)?(\s|$)/.test(l);
  }
  C._is_cracking_command = _is_cracking_command;

  function _is_ssh_command(command) {
    var l = ' ' + command.toLowerCase() + ' ';
    if (l.indexOf('sshuttle') >= 0) return false;
    return l.indexOf('sshpass') >= 0 || l.indexOf(' ssh ') >= 0 || l.indexOf(' nxc ssh ') >= 0 || l.indexOf(' netexec ssh ') >= 0 || l.indexOf(' cme ssh ') >= 0;
  }
  C._is_ssh_command = _is_ssh_command;

  function _is_exec_command(command) {
    var l = command.toLowerCase();
    var isNxc = /\b(?:nxc|netexec|crackmapexec|cme)\s+/.test(l);
    if (isNxc && /\s-[xX](\s|'|")/.test(l)) return true;
    return ['wmiexec', 'psexec', 'atexec', 'smbexec', 'dcomexec', 'evil-winrm', 'enter-pssession', 'penelope'].some(function (t) { return l.indexOf(t) >= 0; });
  }
  C._is_exec_command = _is_exec_command;

  function _is_web_vhost_command(command) {
    var c = command.toLowerCase();
    if (c.indexOf('gobuster vhost') >= 0 || /\bgobuster\b.*\b(?:vhost|dns)\b/.test(c)) return true;
    if (c.indexOf('host: fuzz') >= 0 || c.indexOf('host:fuzz') >= 0) return true;
    return c.indexOf('wfuzz') >= 0 && c.indexOf('host:') >= 0 && c.indexOf('fuzz') >= 0;
  }
  C._is_web_vhost_command = _is_web_vhost_command;

  function _is_web_content_command(command) {
    if (_is_web_vhost_command(command)) return false;
    var c = command.toLowerCase();
    if (c.indexOf('feroxbuster') >= 0 || c.indexOf('gobuster dir') >= 0 || /\bgobuster\b.*\bdir\b/.test(c) || c.indexOf('dirb ') >= 0 || c.indexOf('dirsearch') >= 0 || c.indexOf('katana') >= 0 || c.indexOf('hakrawler') >= 0) return true;
    if (c.indexOf('wfuzz') >= 0) return true;
    return c.indexOf('ffuf') >= 0 && c.indexOf('fuzz') >= 0;
  }
  C._is_web_content_command = _is_web_content_command;

  function _url_path(url) {
    var s = String(url || '').trim().replace(/^\/+(?=https?:\/\/)/i, '');
    var m = /^https?:\/\/[^/\s]+(\/\S*)?/i.exec(s);
    if (m) return m[1] || '/';
    return s;
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
