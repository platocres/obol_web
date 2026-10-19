/*!
 * obol engine - parsers/index.js
 * The command-keyed dispatcher: OBOL.parsers.parseActionOutput(...) routes one action's raw
 * output to every parser its command/action-id matches, returning the narrow facts they prove.
 * 
 *
 * Output matching no parser yields NO facts (facts are never invented). Every emitted fact
 * carries `source` (lineage) and an explicit ProofState.
 *
 * SCOPE handling: there is no workspace in the browser. Callers pass an explicit target scope
 * (e.g. "host:10.10.10.10" or a bare "10.10.10.10") and an optional `domain`; these stand in for
 * the Python ws.target / ws.facts("ad.domain_known"). `domain` is the previously-proven AD domain
 * a caller commits, exactly as the Python fixture harness seeds ws.facts from the manifest.
 *
 * DOCUMENTED GAPS (parsers deliberately left unported - none are exercised by the fixture corpus;
 * each is content/command-gated in the Python and simply won't run here, so it can only ever fail
 * to ADD an optional fact, never emit a forbidden one):
 *   - AD extras: PowerView object/user queries, ldap descriptions, gpp-decrypt, domain trusts,
 *     zerologon scan, ADCS/certipy, rubeus asktgt, sccm, smb-user oracle, pass-policy.
 *   - Structured web JSON (ffuf/feroxbuster/httpx/nuclei -json), vhost fuzzing, nikto, findings
 *     checks (headers/tls/methods/cors/dns/body/exposed/redirect/takeover/components), responder.
 *   - net_extra (dns zone / ike psk / tunnels), forensics (hydra/exiftool/steghide/binwalk/git
 *     history/strings/spring actuator), wireless (airodump/hcx/aircrack), output-shape fallback.
 *   - OSWE websource content parsers other than product-signature + sqli-oracle (verbose error,
 *     source secret, pem key, js framework, graphql, phpinfo, dependency manifest, git-exposed,
 *     xmlrpc, cracked/weak hashing).
 * All calls below are guarded (`C.fn && ...`), so re-porting any of these is drop-in.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  OBOL.parsers = OBOL.parsers || {};

  function has(name) { return typeof C[name] === 'function'; }

  function _stripAnsi(s) {
    if (C && typeof C.stripAnsi === 'function') return C.stripAnsi(s);
    return String(s || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g, '');
  }

  function makeWs(scope, domain) {
    var s = String(scope || '').trim();
    var target = (s.indexOf('host:') === 0 ? s.slice(5) : (C && C._IPV4_RE && C._IPV4_RE.test(s) ? s : '')) || 'target';
    var seed = [];
    if (root.OBOL && root.OBOL.store && typeof root.OBOL.store.active === 'function') {
      var activeEng = root.OBOL.store.active();
      if (activeEng && activeEng.facts) seed = activeEng.facts;
    }
    return { target: target, domainSeed: domain || '', seedFacts: seed, facts: seed };
  }

  function parseActionOutput(opts) {
    opts = opts || {};
    var actionId = opts.actionId || '';
    var command = _stripAnsi(opts.command || '').trim();
    var stdout = opts.stdout || '';
    var stderr = opts.stderr || '';
    var source = (opts.source !== undefined && opts.source !== null) ? _stripAnsi(opts.source) : command;
    var ws = makeWs(opts.scope, opts.domain);
    var text = _stripAnsi([stdout, stderr].filter(Boolean).join('\n'));
    // Normalize CRLF and mid-line carriage-return progress spinner overwrites
    text = text.replace(/\r\n/g, '\n').replace(/^[^\n]*\r(?!\n)/gm, '');
    var facts = [];

    // The dispatch fans one paste out to many independent sub-parsers. A single fragile parser - or a
    // helper missing because a stale/partial asset load left the parser bundle inconsistent - must
    // never lose the whole paste (and the facts already collected). So the run is wrapped: on any
    // throw we log the culprit and return the facts gathered so far. Facts are never invented, only
    // possibly under-collected. nmap runs first, so a scan paste still yields ports.
    var lc = command.toLowerCase();
    var domainHint = '';
    var actObj = { id: actionId };
    try {

    domainHint = has('_domain_from_text') ? C._domain_from_text(text) : '';

    var looksLikeNmapContent = /<nmaprun\b|Nmap scan report for\b|Starting Nmap\b|Discovered open port \d+\/(?:tcp|udp) on \d|^Open \d{1,3}(?:\.\d{1,3}){3}:\d+/im.test(text)
      || (C._NMAP_PORT_RE && C._NMAP_PORT_RE.test(text) && (/Service Info:|Host script results:|^\|[_ ]|MAC Address:|OS details:/im.test(text)));
    if (/\b(?:nmap|masscan|rustscan)\b/.test(lc) || looksLikeNmapContent) {
      if (has('_parse_nmap')) C._parse_nmap(text, ws, source, facts, actionId, command);
    }

    var isNxc = /\b(?:nxc|netexec|crackmapexec|cme)\b/.test(lc)
      || /^(?:SMB|LDAP|WINRM|MSSQL|FTP|SSH|RDP|WMI|VNC|NFS)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+/im.test(text)
      || /^(?:GPP_PASS(?:WORD)?|GPP_AUTOLOGIN|LSASSY|NANODUMP|HANDLEKATZ|PROCDUMP|MASKY|SPIDER_PLUS|WDIGEST|COERCE_PLUS|PETITPOTAM|DFSCOERCE|SHADOWCOERCE|PRINTERBUG|BACKUP_OPERATOR|REG-WINLOGON|REG-QUERY|VEEAM|MREMOTENG|WINSCP|PUTTY|KEEPASS_TRIGGER|INSTALL_ELEVATED|PRE2K|NTLMV1|ENUM_AV|MS17-010|ZEROLOGON|SMBGHOST|RDCMAN|IIS|FIREFOX|POWERSHELL_HISTORY|MET_INJECT|SLINKY|SCUFFY|DACLREAD|GROUP-MEM|ADCS|USER-DESC|GET-DESC-USERS|ENUM_TRUSTS|LDAP-CHECKER|MSSQL_COERCE|WIFI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+/im.test(text);
    if (isNxc) {
      C._parse_nxc_common(text, ws, source, facts);
      // Data-driven capability catalog (nxc-catalog.js): fills the switches the hand-written parsers below
      // don't cover (--users on smb, --lsa cleartext, -M gpp_password/lsassy/...). Facts dedupe, so running it
      // alongside the existing parsers is safe. See docs + tests/engine/nxc-switch-parsers.js.
      if (has('_parse_nxc_capability')) C._parse_nxc_capability(text, command, ws, source, facts);
      if ((C._is_ldap_command(command) || /^LDAP\s+\d+\.\d+\.\d+\.\d+/im.test(text)) && (actionId === 'ad-anon-ldap-enum' || lc.indexOf('--users') >= 0 || /-description-/i.test(text))) {
        C._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
        if ((lc.indexOf('--users') >= 0 || /-description-/i.test(text)) && has('_parse_ldap_descriptions')) C._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
      }
      if (C._is_smb_command(command) || /^SMB\s+\d+\.\d+\.\d+\.\d+/im.test(text)) {
        C._parse_nxc_smb_session(text, ws, command, source, facts);
        C._parse_smb_shares(text, ws, source, facts);
        if (actionId === 'ad-user-enum' || lc.indexOf('--rid-brute') >= 0 || /\(SidTypeUser\)/i.test(text)) C._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint });
      }
      if (lc.indexOf('--asreproast') >= 0 || text.indexOf('$krb5asrep$') >= 0) C._parse_asrep_hashes(text, ws, source, facts);
      C._parse_nxc_auth_validation(text, ws, source, facts);
      C._parse_auth_failures(text, ws, source, facts);
      if (lc.indexOf('--kerberoast') >= 0 || lc.indexOf('--kerberoasting') >= 0 || text.indexOf('$krb5tgs$') >= 0) C._parse_tgs_hashes(text, ws, source, facts);
      if (lc.indexOf('--bloodhound') >= 0 || /Compromised|\b\d{8,14}_bloodhound\.zip\b/i.test(text)) C._parse_bloodhound_collection(text, ws, source, facts);
    }

    if (lc.indexOf('ldapsearch') >= 0 || /^dn:\s*(?:CN|DC|OU|uid)=/im.test(text) || /^namingContexts:/im.test(text)) {
      C._parse_ldapsearch(text, ws, source, facts);
      if (actionId === 'ad-anon-ldap-enum' || lc.indexOf('(objectclass=user)') >= 0 || /sAMAccountName:/i.test(text)) C._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
      if (/^\s*description\s*:/im.test(text) && has('_parse_ldap_descriptions')) C._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
    }

    var isSmbEnum = lc.indexOf('smbclient') >= 0 || lc.indexOf('smbmap') >= 0 || lc.indexOf('rpcclient') >= 0 || lc.indexOf('enum4linux') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('samrdump') >= 0
      || /^\s*Sharename\s+Type\s+Comment/im.test(text) || /^\s*Disk\s+Permissions\s+Comment/im.test(text) || /user:\[[^\]]+\]\s+rid:\[/i.test(text) || /\(SidTypeUser\)/i.test(text) || /\bindex:\s*0x[0-9a-f]+\s+RID:\s*0x/i.test(text);
    if (isSmbEnum) {
      C._parse_smb_shares(text, ws, source, facts);
      C._parse_gpp_artifacts(text, ws, source, facts);
      if (actionId === 'ad-user-enum' || lc.indexOf('enumdomusers') >= 0 || lc.indexOf('enum4linux') >= 0 || lc.indexOf('rpcclient') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('samrdump') >= 0 || /user:\[[^\]]+\]\s+rid:\[|\(SidTypeUser\)|\bindex:\s*0x[0-9a-f]+\s+RID:\s*0x/i.test(text)) {
        C._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint });
      }
    }

    if (lc.indexOf('spider_plus') >= 0 || (lc.indexOf('smbmap') >= 0 && (' ' + lc).indexOf(' -r') >= 0) || lc.indexOf('smbclient') >= 0 || text.indexOf('getting file ') >= 0 || (isSmbEnum && /\b(?:unattend|sysprep|groups|services|scheduledtasks)\.xml\b|\bweb\.config\b|\b[A-Za-z0-9_.-]+\.(?:kdbx|ppk|ovpn|pfx|vmdk)\b/i.test(text))) {
      C._parse_share_inventory(text, ws, command, source, facts);
    }

    if (lc.indexOf('grep') >= 0 || lc.indexOf('find') >= 0 || lc.indexOf('lootgrep') >= 0 || text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) {
      C._parse_gpp_artifacts(text, ws, source, facts);
    }

    if (!isNxc && (lc.indexOf('gpp-decrypt') >= 0 || actionId === 'gpp-passwords' || actionId === 'gpp-decrypt' || /gpp-decrypt|ciphertext/i.test(text)) && has('_parse_gpp_decrypted')) {
      C._parse_gpp_decrypted(text, ws, source, facts);
    }
    if (lc.indexOf('wpscan') >= 0 || actionId === 'wordpress' || /WordPress version\s+\d|\[\+\]\s*User\(s\)\s+Identified/i.test(text)) C._parse_wpscan(text, ws, source, facts);
    if ((actionId === 'trust-enum' || lc.indexOf('domain_trusts') >= 0 || lc.indexOf('domaintrust') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('nltest') >= 0 || /Domain Trusts|SourceName\s*:\s*\S+[\s\S]{1,160}?TargetName\s*:\s*\S+|TrustDirection\s*:/i.test(text)) && has('_parse_domain_trusts')) C._parse_domain_trusts(text, ws, source, facts);
    if ((actionId === 'zerologon-check' || lc.indexOf('zerologon') >= 0 || /CVE-2020-1472|Success!\s+DC can be fully compromised by a Zerologon attack/i.test(text)) && has('_parse_zerologon_scan')) C._parse_zerologon_scan(text, ws, source, facts);

    if ((actionId === 'powerview-enum' || lc.indexOf('get-netuser') >= 0 || lc.indexOf('get-domainuser') >= 0 || lc.indexOf('get-aduser') >= 0 || /samaccountname\s*:\s*\S+[\s\S]{1,300}?(?:serviceprincipalname|useraccountcontrol|admincount|description)\s*:/i.test(text)) && has('_parse_powerview')) C._parse_powerview(text, ws, command, source, facts, { domain_hint: domainHint });
    if ((['get-netgroup', 'get-domaingroup', 'get-netcomputer', 'get-domaincomputer', 'objectacl', 'get-acl', 'find-interestingdomainacl'].some(function (k) { return lc.indexOf(k) >= 0; }) || /(?:ObjectDN|ObjectSID)\s*:\s*\S+[\s\S]{1,250}?ActiveDirectoryRights\s*:/i.test(text)) && has('_parse_powerview_objects')) C._parse_powerview_objects(text, ws, command, source, facts, { domain_hint: domainHint });

    if (lc.indexOf('kerbrute') >= 0 || /VALID USERNAME:\s*\S+@\S+|VALID LOGIN:\s*\S+@\S+/i.test(text)) C._parse_kerbrute(text, ws, source, facts, { domain_hint: domainHint });

    if (lc.indexOf('getnpusers') >= 0 || lc.indexOf('asreproast') >= 0 || text.indexOf('$krb5asrep$') >= 0 || (/^Name\s+MemberOf\s+PasswordLastSet/im.test(text) && /UF_DONT_REQUIRE_PREAUTH|DONT_REQ_PREAUTH/i.test(text))) C._parse_asrep_hashes(text, ws, source, facts);
    if (lc.indexOf('getuserspns') >= 0 || lc.indexOf('kerberoast') >= 0 || text.indexOf('$krb5tgs$') >= 0 || /^ServicePrincipalName\s+Name\s+MemberOf/im.test(text)) C._parse_tgs_hashes(text, ws, source, facts);

    if (lc.indexOf('secretsdump') >= 0 || lc.indexOf('hashdump') >= 0 || lc.indexOf('samdump2') >= 0 || actionId === 'vhd-mount-sam-extract' || (lc.indexOf('volatility') >= 0 && lc.indexOf('dump') >= 0) || (isNxc && ['--ntds', '--sam', '--lsa'].some(function (f) { return lc.indexOf(f) >= 0; })) || (C._looks_like_sam_dump && C._looks_like_sam_dump(text)) || /Dumping (?:local )?SAM hashes|Dumping LSA Secrets|Dumping Domain Credentials|_SC_[A-Za-z0-9_.-]+/i.test(text)) {
      C._parse_ntlm_dump(text, ws, command, source, facts);
    }

    // mimikatz / pypykatz credential dumps: sekurlsa::logonpasswords -> hash.ntlm (+ credential.plaintext
    // when a cleartext is present), lsadump::sam/lsa -> hash.ntlm (+ loot.ntds for a full dump). Routed on
    // the command OR a content signature so an attached dump file with no command line still mints.
    if ((lc.indexOf('mimikatz') >= 0 || lc.indexOf('sekurlsa') >= 0 || lc.indexOf('lsadump') >= 0 || lc.indexOf('pypykatz') >= 0 || (has('_looks_like_mimikatz') && C._looks_like_mimikatz(text))) && has('_parse_mimikatz')) C._parse_mimikatz(text, ws, command, source, facts);

    // MSCache2/DCC2 cached domain hashes ($DCC2$...) from secretsdump cached output or lsadump::cache.
    // Routed on the content token so a pasted cache dump mints even without a recognizable command line.
    if (has('_looks_like_mscache') && C._looks_like_mscache(text)) C._parse_mscache(text, ws, command, source, facts);

    // Timeroasting ($sntp-ms$...) hashes from NetExec -M timeroast or raw SNTP tool dumps.
    if (has('_looks_like_timeroast') && C._looks_like_timeroast(text)) C._parse_timeroast(text, ws, command, source, facts);

    // Structured cleartext credential blocks (Domain: ... Username: ... Password: ...) and process leaks.
    if (has('_looks_like_generic_dumped_credentials') && C._looks_like_generic_dumped_credentials(text)) C._parse_generic_dumped_credentials(text, ws, command, source, facts);

    if (lc.indexOf('bloodhound-python') >= 0 || lc.indexOf('sharphound') >= 0 || /\b\d{8,14}_(?:bloodhound|computers|users|groups|domains)\.zip\b|Done in \d+M \d+S/i.test(text)) C._parse_bloodhound_collection(text, ws, source, facts);
    if (lc.indexOf('bloodhound') >= 0 || /Compromised-Owned-Principal|Shortest Paths to Domain Admins/i.test(text)) C._parse_bloodhound_analysis(text, ws, source, facts);

    if ((' ' + lc + ' ').indexOf(' winrm ') >= 0 || lc.indexOf('evil-winrm') >= 0 || /\*Evil-WinRM\*\s+PS\s+[A-Za-z]:\\/i.test(text)) C._parse_evil_winrm(text, ws, command, source, facts);

    var isSsh = C._is_ssh_command(command);
    if (isSsh) C._parse_ssh_exec(text, ws, command, source, facts);
    // An SSH key login that FAILED (any client, any cause) -> mint ssh.key_rejected so the troubleshooter
    // surfaces the fix. Keyed on the output, so it also catches a bare pasted error with no command.
    if ((isSsh || /\bssh\b/.test(lc) || /Permission denied \(publickey|UNPROTECTED PRIVATE KEY|no mutual signature/i.test(text)) && C._parse_ssh_key_diagnostics)
      C._parse_ssh_key_diagnostics(text, ws, source, facts);
    // Auth blockers (a valid credential refused for a fixable reason) can come from any auth tool -
    // nxc, impacket, smbclient, ssh - so recognize them content-first, not tool-gated.
    if (C._parse_auth_blockers && /STATUS_PASSWORD_(?:MUST_CHANGE|EXPIRED)|must change .*password|password has expired|KRB_AP_ERR_SKEW|clock skew too great|time difference too large|STATUS_NOT_SUPPORTED|STATUS_ACCOUNT_(?:LOCKED_OUT|DISABLED|RESTRICTION|EXPIRED)|STATUS_LOGON_TYPE_NOT_GRANTED|STATUS_INVALID_LOGON_HOURS|locked out|insufficientAccessRights|insufficient access rights/i.test(text))
      C._parse_auth_blockers(text, ws, source, facts);
    // Operational blockers (recon/exec/privesc/web traps) - all content-first, any tool.
    if (C._parse_op_blockers) C._parse_op_blockers(text, ws, command, source, facts);

    var isWebExploitCmd = (C._WEB_EXPLOIT_ACTION_IDS && C._WEB_EXPLOIT_ACTION_IDS.has(actionId))
      || (/\b(?:curl|wget|httpie|python3?)\b/.test(lc) && (/cmd=|exec=|shell\.php|cmd\.jsp|cmd\.asp|evil\.|reverse|payload|\.\.\/|%2e%2e|php:\/\/filter|expect:\/\/|data:\/\//i.test(command) || (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) && ((C._LINUX_ID_RE && C._LINUX_ID_RE.test(text)) || /root:x:0:0:/i.test(text)))))
      || (!command && (/^root:x:0:0:/im.test(text) || (C._LFI_WIN_INI_RE && C._LFI_WIN_INI_RE.test(text)) || (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) && C._LINUX_ID_RE && C._LINUX_ID_RE.test(text))));

    // Service login / DB-RCE / bare `id` output that lands a *nix shell (telnet, rlogin/rsh, psql/odat/sqlplus
    // COPY..PROGRAM and friends, or a bare uid=... gid=... paste): reuse the ssh-exec reader to mint the
    // foothold from a pasted uid=... line.
    if (!isSsh && !isWebExploitCmd && (/\b(telnet|rlogin|rsh|rexec|psql|sqlplus|odat)\b/.test(lc) || (C._LINUX_ID_RE && C._LINUX_ID_RE.test(text) && !/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) && !/\b(?:curl|wget|sqlmap|ffuf|gobuster|feroxbuster|nikto)\b/.test(lc)))) C._parse_ssh_exec(text, ws, command, source, facts);
    if (!isSsh && C._LINUX_SHELL_ACTION_IDS && C._LINUX_SHELL_ACTION_IDS.has(actionId)) C._parse_ssh_exec(text, ws, command, source, facts);

    if (isNxc && ((' ' + lc + ' ').indexOf(' rdp ') >= 0 || /^RDP\s+\d+\.\d+\.\d+\.\d+/im.test(text))) C._parse_nxc_rdp(text, ws, command, source, facts);

    var looksLikeCracked = C._is_cracking_command(command) || text.indexOf('$keepass$*') >= 0
      || (C._JOHN_LOADED_RE && C._JOHN_LOADED_RE.test(text))
      || /Session\.+:\s*hashcat|Status\.+:\s*Cracked|\b\d+\s+password\s+hash(?:es)?\s+cracked,\s+\d+\s+left\b/i.test(text)
      || /^(?:\$krb5(?:tgs|asrep)\$[^\r\n:]+|\$DCC2\$\d+#[^#\r\n]+#[0-9a-fA-F]{32}|\$(?:1|2[abxy]|5|6|y|apr1|sha1|NT)\$[^\s:]+):[^\r\n]+$/im.test(text);
    if (looksLikeCracked) C._parse_cracked_credentials(text, ws, command, source, facts);

    if ((C._is_exec_command(command) || (!command && (/^\s*nt authority\\system\s*$/im.test(text) || /^Directory of [A-Za-z]:\\/im.test(text)))) && !isSsh && has('_parse_command_execution')) C._parse_command_execution(text, ws, command, source, facts);

    if (lc.indexOf('penelope') >= 0 || (C._PENELOPE_GOT_RE && C._PENELOPE_GOT_RE.test(text)) || (C._PENELOPE_UPGRADE_RE && C._PENELOPE_UPGRADE_RE.test(text))) C._parse_penelope(text, ws, source, facts);

    if (C._PRIVESC_ACTION_IDS && C._PRIVESC_ACTION_IDS.has(actionId)) {
      C._parse_privesc_output(actionId, text, ws, command, source, facts);
    } else if (has('_parse_privesc_output')) {
      var isRemoteScanner = /\b(?:snmpwalk|snmpbulkwalk|snmp-check|onesixtyone|nmap|masscan|rustscan)\b/i.test(lc);
      if (!isRemoteScanner && has('_looks_like_linux_enum') && C._looks_like_linux_enum(text)) {
        C._parse_privesc_output('linux-enum', text, ws, command, source, facts);
      }
      if (!isRemoteScanner && has('_looks_like_windows_enum') && C._looks_like_windows_enum(text)) {
        C._parse_privesc_output('windows-enum', text, ws, command, source, facts);
      }
    }
    // A bare `whoami /priv` / `whoami /all` or `sudo -l` / `sudo --list` paste carries no privesc
    // action-id, so the gate above skips it. Route on the command OR a conservative content signature
    // (a dangerous Enabled Se*Privilege line; a sudo rights listing) so an attached paste with no
    // command line still mints its lead, while unrelated output (an ls, a config dump) never does.
    if ((lc.indexOf('whoami /priv') >= 0 || lc.indexOf('whoami /all') >= 0 || (has('_looks_like_whoami_priv') && C._looks_like_whoami_priv(text))) && has('_parse_whoami_priv')) C._parse_whoami_priv(text, ws, command, source, facts);
    if ((lc.indexOf('sudo -l') >= 0 || lc.indexOf('sudo --list') >= 0 || /\bdoas\b/.test(lc) || (has('_looks_like_sudo_l') && C._looks_like_sudo_l(text))) && has('_parse_sudo_l')) C._parse_sudo_l(text, ws, command, source, facts);
    // net user / net localgroup / net group account enumeration, and winPEAS/PrivescCheck privesc dumps -
    // both arrive as operator-ingest with no action-id, so route on the command OR a conservative content
    // signature. The parsers are content-gated (a domain-group membership -> ad.user_list, a local-admin
    // members list -> config.review; a dangerous Enabled privilege -> privesc.windows_privilege), so an
    // unrelated paste mints nothing.
    if ((lc.indexOf('net user') >= 0 || lc.indexOf('net localgroup') >= 0 || lc.indexOf('net group') >= 0 || (has('_looks_like_net_output') && C._looks_like_net_output(text))) && has('_parse_net_accounts')) C._parse_net_accounts(text, ws, command, source, facts);
    if ((lc.indexOf('winpeas') >= 0 || lc.indexOf('privesccheck') >= 0 || (has('_looks_like_winpeas') && C._looks_like_winpeas(text))) && has('_parse_winpeas')) C._parse_winpeas(text, ws, command, source, facts);
    // schtasks /query /v -> scheduled-task privesc lead (SYSTEM/admin run-as pointing at a path);
    // reg query -> Winlogon autologon + stored creds (VNC/PuTTY/SNMP); icacls/accesschk -> a writable
    // service/path ACE for a low-priv principal. All arrive as operator-ingest with no action-id, so
    // route on the command OR a conservative content signature; each parser is content-gated (only a
    // privileged task with a path, a credential-ish reg value, or a writable program-path ACE mints),
    // so an unrelated paste - an ls, a harmless reg dump, a read-only ACE - mints nothing.
    if ((lc.indexOf('schtasks') >= 0 || (has('_looks_like_schtasks') && C._looks_like_schtasks(text))) && has('_parse_schtasks')) C._parse_schtasks(text, ws, command, source, facts);
    if ((lc.indexOf('reg query') >= 0 || (has('_looks_like_reg_query') && C._looks_like_reg_query(text))) && has('_parse_reg_query')) C._parse_reg_query(text, ws, command, source, facts);
    if ((lc.indexOf('klist') >= 0 || (has('_looks_like_klist') && C._looks_like_klist(text))) && has('_parse_klist')) C._parse_klist(text, ws, command, source, facts);
    if ((lc.indexOf('icacls') >= 0 || lc.indexOf('accesschk') >= 0 || (has('_looks_like_icacls_accesschk') && C._looks_like_icacls_accesschk(text))) && has('_parse_icacls_accesschk')) C._parse_icacls_accesschk(text, ws, command, source, facts);

    // endpoint defensive posture (read-only): languagemode / Get-MpComputerStatus / Get-MpPreference /
    // Get-AppLockerPolicy -> defense.control, so the coach can prefer remote-first and warn before on-host runs.
    if ((lc.indexOf('get-mpcomputerstatus') >= 0 || lc.indexOf('get-applockerpolicy') >= 0 || lc.indexOf('languagemode') >= 0 || lc.indexOf('get-mppreference') >= 0 || (has('_looks_like_defense_enum') && C._looks_like_defense_enum(text))) && has('_parse_defense_enum')) C._parse_defense_enum(text, ws, command, source, facts);
    if (has('_parse_script_sinks')) C._parse_script_sinks(text, command, ws, source, facts);
    if (has('_parse_shadow_file')) C._parse_shadow_file(text, command, ws, source, facts);

    if (lc.indexOf('certipy') >= 0 || lc.indexOf('certify') >= 0 || lc.indexOf('pywhisker') >= 0 || /(?:CA Name|Template Name|msPKI-Certificate-Name-Flag|Certipy)[\s\S]{1,600}?(?:ESC\d+|ENROLLEE_SUPPLIES_SUBJECT|Vulnerabilities)/i.test(text)) {
      if (has('_parse_adcs')) C._parse_adcs(text, ws, command, source, facts);
    }
    if ((lc.indexOf('certipy auth') >= 0 || lc.indexOf('certipy shadow') >= 0 || lc.indexOf('shadow auto') >= 0 || actionId === 'cert-authenticate' || /Got hash for\s+['"]?[^\s'"]+['"]?\s*:\s*(?:[a-f0-9]{32}:)?[a-f0-9]{32}|Saved credential cache to/i.test(text)) && has('_parse_certipy_auth')) {
      C._parse_certipy_auth(text, ws, command, source, facts);
    }
    if (has('_is_ad_abuse_command') && (C._is_ad_abuse_command(command) || (C._AD_ABUSE_ACTION_IDS && C._AD_ABUSE_ACTION_IDS.has(actionId)) || /DACL modified successfully|OwnerSid modified successfully|Password changed successfully!|\[\+\]\s+\S+\s+added to\s+\S+|\[\*\]\s+Action:\s*Ask\s+TGT|TGT request successful!|Service ticket successfully requested|Saving ticket in\s+\S+\.ccache|DeviceKey\s*:|KeyCredential\s+added/i.test(text))) {
      if (has('_parse_ad_abuse_output')) C._parse_ad_abuse_output(actionId, text, ws, command, source, facts);
    }
    // Content-sniff fallback: a bloodyAD `get writable` dump is often ATTACHED as a file with no command
    // set, so the ad-abuse gate above never fires. Recognize it from the output itself (the ad-abuse path
    // already covered the command/action case; facts dedupe, so a double hit is harmless).
    else if (has('_parse_bloodyad_writable') && C._looks_like_bloodyad_writable(text)) C._parse_bloodyad_writable(text, ws, command, source, facts);
    if (has('_parse_ad_delegation_surface') && (isNxc || ['ldapsearch', 'bloodyad', 'get-adcomputer', 'get-adserviceaccount', 'getaduser', 'finddelegation', ' ldap '].some(function (k) { return lc.indexOf(k) >= 0; }) || /\b(?:Delegation\s+RightsTo|msDS-AllowedToDelegateTo|msDS-AllowedToActOnBehalfOfOtherIdentity|TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION)\b/i.test(text))) C._parse_ad_delegation_surface(text, ws, command, source, facts);

    if ((lc.indexOf('ffuf') >= 0 || /"commandline"\s*:\s*"[^"]*ffuf/i.test(text)) && has('_parse_ffuf_json')) C._parse_ffuf_json(text, ws, source, facts);
    if ((lc.indexOf('feroxbuster') >= 0 || /"type"\s*:\s*"response"[\s\S]{1,200}?"status"\s*:/i.test(text)) && has('_parse_feroxbuster_json')) C._parse_feroxbuster_json(text, ws, source, facts);
    if ((lc.indexOf('httpx') >= 0 || /"status_code"\s*:\s*\d{3}[\s\S]{1,300}?"(?:webserver|tech)"\s*:/i.test(text)) && has('_parse_httpx_json')) C._parse_httpx_json(text, ws, source, facts);
    if ((lc.indexOf('nuclei') >= 0 || /"template-id"\s*:\s*"[^"]+"[\s\S]{1,400}?"matched-at"\s*:/i.test(text)) && has('_parse_nuclei_json')) C._parse_nuclei_json(text, ws, source, facts);
    if (has('_is_web_vhost_command') && C._is_web_vhost_command(command)) { if (has('_parse_web_vhosts')) C._parse_web_vhosts(text, ws, source, facts); }
    else if (C._is_web_content_command(command) || /\[Status:\s*\d{3},\s*Size:\s*\d+/i.test(text) || /^\s*\d{3}\s+(?:GET|POST|HEAD)\s+\d+l\s+\d+w\s+\d+c\s+https?:\/\//im.test(text) || /^\/\S+\s+\(Status:\s*\d{3}\)\s*\[Size:\s*\d+\]/im.test(text)) C._parse_web_content(text, ws, source, facts, command);
    if ((lc.indexOf('arjun') >= 0 || /Parameters found(?:\s+for\s+\S+)?\s*:\s*[a-zA-Z0-9_,\s-]+|\[\+\]\s+Heuristic scanner found\s+\d+\s+parameters/i.test(text)) && has('_parse_arjun')) C._parse_arjun(text, ws, command, source, facts);
    if (lc.indexOf('sqlmap') >= 0 || /sqlmap identified the following injection point|---\nParameter:\s*\S+\s*\((?:GET|POST|URI|Cookie|Header)\)/i.test(text)) C._parse_sqlmap(text, ws, source, facts);
    if (lc.indexOf('git-dumper') >= 0 || lc.indexOf('/.git/') >= 0 || C._GIT_HEAD_RE.test(text)) C._parse_git_source(text, ws, command, source, facts);
    if ((lc.indexOf('nikto') >= 0 || /^- Nikto v\d+\.\d+/im.test(text)) && has('_parse_nikto')) C._parse_nikto(text, ws, source, facts);
    if (isWebExploitCmd) C._parse_web_exploit_output(actionId || 'operator-ingest', text, ws, command, source, facts);
    if (lc.indexOf('whatweb') >= 0 || lc.indexOf('curl') >= 0 || /HTTPServer\[|Country\[[^\]]+\]\[[^\]]+\]/i.test(text)) C._parse_http_metadata(text, ws, source, facts);
    // Product fingerprints (Jenkins, NVMS-1000) run content-first on any web-ish
    // paste (nmap http-* scripts, curl -I, whatweb, a pasted page/headers). The
    // parser self-gates on a definitive signature, so an unrelated paste mints
    // nothing; a hit lights the precise exploit move instead of a bare port gate.
    if (has('_parse_web_fingerprint')) C._parse_web_fingerprint(text, ws, source, facts);
    // LAPS read (nxc -M laps / --laps, ldapsearch/Get-ADComputer ms-MCS-AdmPwd):
    // content-gated on a LAPS signature, and self-gated to require a real
    // Password:/attribute value so the "No result found" failure mints nothing.
    if (has('_parse_laps') && /ms-?MCS-AdmPwd|msLAPS-Password|Getting LAPS Passwords|Computer:\S+\s+User:.*Password:/i.test(text)) C._parse_laps(text, ws, source, facts);
    // NSClient++ nsclient.ini password (web-API privesc on 8443).
    if (has('_parse_nsclient_ini') && (lc.indexOf('nsclient') >= 0 || /nsclient|\[\/settings\//i.test(text))) C._parse_nsclient_ini(text, ws, command, source, facts);
    // KeePass database/dump in hand (.kdbx, $keepass$ hash, master-key dump).
    if (has('_parse_keepass_dump') && (/keepass|\.kdbx/i.test(lc) || /\$keepass\$|\.kdbx/i.test(text))) C._parse_keepass_dump(text, ws, command, source, facts);
    if (['curl', 'whatweb', 'wget', 'gobuster', 'ffuf', 'feroxbuster', 'nikto', 'dirb', 'dirsearch', 'katana', 'hakrawler'].some(function (w) { return lc.indexOf(w) >= 0; }) || /^<(?:!DOCTYPE|html|head|body|form|input|script)\b/im.test(text)) C._parse_web_surface(text, ws, command, source, facts);
    if (['snmpwalk', 'snmpbulkwalk', 'snmp-check', 'onesixtyone'].some(function (t) { return lc.indexOf(t) >= 0; }) || /(?:SNMPv2-MIB|iso\.3\.6\.1\.2\.1|HOST-RESOURCES-MIB|NET-SNMP-EXTEND-MIB)::/i.test(text)) C._parse_snmp_output(text, ws, command, source, facts);
    if (['mysql', 'mssqlclient', 'psql', 'mongosh', 'mongo ', 'pymongo', 'mongoclient', 'redis-cli', 'sqlplus', 'odat', 'sqlite3', 'sqlite'].some(function (t) { return lc.indexOf(t) >= 0; }) || /\b(?:nxc|netexec|crackmapexec|cme)\s+mssql\b/.test(lc) || /^redis_version:|^SQL>\s|^mysql>\s|^postgres=#\s|^\s*\d+\|[^|\r\n]+\|\$(?:2[aby]|1|5|6|y|P|H|apr1)\$/im.test(text)) C._parse_database_output(text, ws, command, source, facts);
    if ((lc.indexOf('sqlite3') >= 0 || /CREATE TABLE\s+|^\s*\d+\|[^|\r\n]+\|[^|\r\n]+/im.test(text)) && has('_parse_sqlite_dump')) C._parse_sqlite_dump(text, ws, source, facts);
    if (has('_has_notable_programs') && !/\b(?:bloodyad|nxc|netexec|crackmapexec|cme|certipy|ldapsearch|impacket|getnpusers|getuserspns|secretsdump|nmap)\b/i.test(lc) && C._has_notable_programs(text)) C._parse_notable_programs(text, ws, source, facts);
    if ((' ' + lc + ' ').indexOf('ftp ') >= 0 || lc.indexOf('lftp') >= 0) C._parse_ftp_output(text, ws, command, source, facts);
    if (C._SSH_BANNER_RE.test(text)) C._parse_ssh_banner(text, ws, source, facts);
    if (((' ' + lc + ' ').indexOf(' 21') >= 0 || lc.indexOf('ftp') >= 0 || C._FTP_BANNER_RE.test(text)) && C._FTP_BANNER_RE.test(text)) C._parse_ftp_output(text, ws, command, source, facts);

    if (((lc.indexOf('rubeus') >= 0 && (lc.indexOf('asktgt') >= 0 || lc.indexOf('tgtdeleg') >= 0)) || /ServiceName\s*:\s*krbtgt\/[\s\S]{1,400}?Base64EncodedTicket/i.test(text)) && has('_parse_rubeus_asktgt')) C._parse_rubeus_asktgt(text, ws, source, facts);
    if ((lc.indexOf('sharpsccm') >= 0 || lc.indexOf('sccmhunter') >= 0 || /Network Access Account|SMS_Site|MP_LocationManager|CCM_NetworkAccessAccount/i.test(text)) && has('_parse_sccm')) C._parse_sccm(text, ws, source, facts);

    if (lc.indexOf('dig') >= 0 && lc.indexOf('axfr') >= 0 && has('_parse_dns_zone')) C._parse_dns_zone(text, ws, source, facts);
    if ((lc.indexOf('ike-scan') >= 0 || /IKE PSK parameters|^[0-9a-fA-F]+(?::[0-9a-fA-F]+){8}$/im.test(text)) && has('_parse_ike_psk')) C._parse_ike_psk(text, ws, source, facts);
    if ((lc.indexOf('ipmitool') >= 0 || lc.indexOf('ipmi') >= 0 || /\$rakp\$|RAKP-(?:HMAC-SHA1|Hash)|^[A-Za-z0-9_.-]+:[0-9a-fA-F]{40,}:[0-9a-fA-F]{40}$/im.test(text)) && has('_parse_ipmi_rakp')) C._parse_ipmi_rakp(text, ws, source, facts);
    if ((/\b(?:hashid|hash-identifier|nth|haiti|name-that-hash)\b/.test(lc) || actionId === 'crack-identify' || /\[Hashcat Mode:\s*\d+\]|Most Likely\s*:/i.test(text)) && has('_parse_hash_identify')) C._parse_hash_identify(text, ws, command, source, facts);

    // findings-check actions
    if (actionId === 'responder-poison' || lc.indexOf('responder') >= 0 || /\[(?:SMB|HTTP|LDAP|MSSQL|DCE-RPC|WinRM)\]\s+NTLMv[12](?:-SSP)?\s+Client\s*:/i.test(text)) { if (has('_parse_responder')) C._parse_responder(text, ws, source, facts); }

    if ((/\b(?:hydra|medusa|ncrack|crowbar|patator)\b/.test(lc) || /\[\d+\]\[[a-z0-9_-]+\]\s+host:\s*\S+\s+login:\s*\S+\s+password:/i.test(text)) && has('_parse_hydra')) C._parse_hydra(text, ws, command, source, facts);

    // Flag capture (content-gated inside): a `===FLAG:path::value` marker from the flag-hunt move, or a
    // direct `type/cat ...proof.txt` read, mints objective.<slot>_flag so the read flag reaches the report.
    if (has('_parse_flags')) C._parse_flags(text, ws, command, source, facts);

    // Section 33 content-gated OSWE parsers (only the ported ones run)
    if (has('_has_source_secret') && C._has_source_secret(text)) C._parse_source_secret(text, ws, command, source, facts);
    if (has('_has_windows_creds') && C._has_windows_creds(text)) C._parse_windows_creds(text, ws, command, source, facts);
    if (has('_has_product_signature') && C._has_product_signature(text)) C._parse_product_signature(text, ws, command, source, facts);
    if (has('_has_sqli_oracle') && C._has_sqli_oracle(text)) C._parse_sqli_oracle(text, ws, command, source, facts);

    // findings-lens checks (the "checks" lane + a couple of recon observations): route on the move's
    // action-id, each parser is content-gated so an unrelated paste mints nothing.
    if ((actionId === 'check-web-headers' || (/\bcurl\b/.test(lc) && /\s-(?:I|-head|[a-zA-Z]*i)\b/.test(' ' + command))) && has('_parse_http_headers')) C._parse_http_headers(text, ws, source, facts);
    if ((actionId === 'check-http-methods' || /^\s*(allow|public):/im.test(text)) && has('_parse_http_methods')) C._parse_http_methods(text, ws, source, facts);
    if ((actionId === 'check-cors' || /access-control-allow-origin:/i.test(text)) && has('_parse_http_cors')) C._parse_http_cors(text, ws, source, facts);
    if (actionId === 'check-web-body' && has('_parse_http_body')) C._parse_http_body(text, ws, source, facts);
    if ((actionId === 'check-tls-config' || lc.indexOf('sslscan') >= 0 || lc.indexOf('testssl') >= 0 || lc.indexOf('ssl-enum-ciphers') >= 0 || /TLSv1\.[01]\s+enabled|Heartbleed\s+vulnerable/i.test(text)) && has('_parse_tls_info')) C._parse_tls_info(text, ws, source, facts);
    if ((actionId === 'check-exposed-files' || /(?:Index of \/\s*<\/title>|\[To Parent Directory\]|^User-agent:\s*\*[\s\S]{1,200}?Disallow:\s*\/)/im.test(text)) && has('_parse_http_exposed')) C._parse_http_exposed(text, ws, source, facts);
    if ((actionId === 'recon-dns' || lc.indexOf('axfr') >= 0) && has('_parse_dns_zone')) C._parse_dns_zone(text, ws, source, facts);
    if ((actionId === 'check-dns-email' || /v=spf1\s|v=DMARC1\s/i.test(text)) && has('_parse_dns_email')) C._parse_dns_email(text, ws, source, facts);
    if ((actionId === 'check-subdomain-takeover' || (/is\s+an\s+alias\s+for|\bIN\s+CNAME\b/i.test(text) && /github\.io|herokuapp\.com|s3\.amazonaws\.com|azurewebsites\.net|cloudfront\.net|pantheonsite\.io|zendesk\.com|fastly\.net|ghost\.io|myshopify\.com|surge\.sh|bitbucket\.io|unbouncepages\.com|wordpress\.com|tumblr\.com/i.test(text))) && has('_parse_dns_takeover')) C._parse_dns_takeover(text, ws, source, facts);
    if ((actionId === 'vhost-discovery' || (lc.indexOf('host:') >= 0 && lc.indexOf('fuzz') >= 0) || /\b(?:gobuster\s+vhost|feroxbuster[^\n]*--extract-links)\b/i.test(lc) || /^Found:\s+[a-zA-Z0-9_.-]+\s+\(Status:\s*\d{3}\)/im.test(text)) && has('_parse_vhost')) C._parse_vhost(text, ws, source, facts);
    // late-game AD recording facts (the access is already landed; these record the specific primitive)
    if ((actionId === 'ticket-reuse' || actionId === 'lateral-exec') && has('_parse_lateral_movement')) C._parse_lateral_movement(text, ws, source, facts);
    if (actionId === 'coerce-auth' && has('_parse_coerced_auth')) C._parse_coerced_auth(text, ws, source, facts);
    if ((actionId === 'gpo-abuse' || /\b(?:sharpGPOAbuse|pyGPOAbuse)\b/i.test(command)) && has('_parse_gpo_control')) C._parse_gpo_control(text, ws, source, facts);
    if ((actionId === 'sid-history-abuse' || /sidhistory/i.test(command)) && has('_parse_sid_history')) C._parse_sid_history(text, ws, source, facts);

    // Known-exploit fingerprint recognizer: when pasted service/version output names a product+version
    // (or a CVE / nmap vuln verdict) that a promoted known-exploit module targets, mint a vuln.<name>
    // lead so the coach lights that exact module. Anchored and additive; unrelated output mints nothing.
    if (has('_parse_vulnmatch')) C._parse_vulnmatch(text, ws, source, facts);

    // Connectivity: a foothold's own interface/route dump -> the subnets it reaches (and multihomed);
    // a pivot tool's setup output -> the live tunnel. Powers the hub connectivity view.
    if (has('_parse_local_net') && (/\bip\s+(?:-\d+\s+)?a(?:ddr)?\b|\bifconfig\b|\bip\s+route\b|\bipconfig\b|\broute\s+print\b|\bnetstat\s+-r/.test(lc) || /\binet\s+\d|IPv4 Address|Network Destination|\bGenmask\b/i.test(text)))
      C._parse_local_net(text, ws, source, facts);
    if (has('_parse_tunnel') && (/\bchisel\b|\bligolo\b|\bsshuttle\b|\bdnscat|ssh\s+[^\n]*-[a-z]*d\b|\bagent(?:\.exe)?\s+-connect\b/.test(lc) || /\bchisel\b|ligolo|sshuttle|dnscat|Agent joined|\[Tunnel\] Interface ligolo|obol:fact:pivot_active/i.test(text)))
      C._parse_tunnel(text, ws, source, facts, command);
    // Adjacent hosts (ARP/neighbour cache), listening services, and internal resolvers from the foothold
    // - the leads that tell the operator what to aim the pivot at. Command-keyed, with a shape fallback.
    if (has('_parse_local_neighbors') && (/\bip\s+neigh|\barp\s+-a\b/.test(lc) || /\blladdr\b|\bdynamic\b/i.test(text)))
      C._parse_local_neighbors(text, ws, source, facts);
    if (has('_parse_local_listeners') && (/\bnetstat\s+-[a-z]*[alno]|\bss\s+-[a-z]*l/.test(lc) || /\bLISTEN(?:ING)?\b/.test(text)))
      C._parse_local_listeners(text, ws, source, facts);
    if (has('_parse_local_dns') && (/\bresolv\.conf\b|\bresolvectl\b|ipconfig\s+\/all/.test(lc) || /^\s*nameserver\s+\d|DNS Servers[^\n:]*:/im.test(text)))
      C._parse_local_dns(text, ws, source, facts);
    // Internal-resolver interrogation: a dig/nslookup/host query or an AXFR zone transfer against the
    // foothold's resolver -> the domain and its DCs (unlocking the AD lane), plus a zone receipt.
    if (has('_parse_dns') && (/\b(?:dig|nslookup|host|dnsrecon|dnsenum)\b/.test(lc) || /\bIN\s+(?:SOA|SRV|NS)\b|_ldap\._tcp|service\s*=\s*\d+\s+\d+\s+\d+|has address/i.test(text)))
      C._parse_dns(text, ws, source, facts);

    // Output-shape fallback (runs last): recognize common output by its shape when the command-keyed
    // dispatch above did not key on it. Strictly additive and guarded, so it only fills gaps (a bare
    // port table, a raw HTTP response, a pasted AS-REP/TGS hash) and never alters a parsed result.
    if (has('_parse_shape')) C._parse_shape(text, ws, source, facts);

    // Ensure twin facts required by packs are always co-minted
    if (C._add && C.mkFact) {
      for (var fi = 0; fi < facts.length; fi++) {
        var fk = facts[fi].kind;
        if (fk === 'vuln.sqli_confirmed') {
          C._add(facts, C.mkFact('web.sqli_confirmed', facts[fi].scope, facts[fi].value, facts[fi].state, facts[fi].source));
        }
      }
    }

    } catch (e) {
      try { if (typeof console !== 'undefined' && console.warn) console.warn('obol parser: a sub-parser failed, keeping the ' + facts.length + ' fact(s) already recognized. Command: ' + command + ' | ' + (e && e.message)); } catch (_e) {}
      return { facts: facts, unmatched: facts.length === 0, error: (e && e.message) || String(e) };
    }

    return { facts: facts, unmatched: facts.length === 0 };
  }

  OBOL.parsers.parseActionOutput = parseActionOutput;
  OBOL.parsers.parse_action_output = parseActionOutput; // python-name alias

  var _PROMPT_PREFIX_RE = /^\s*(?:\([^)]+\)\s*)?(?:\[?[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+[:\s][^\r\n$#%>\]]*\]?[$#%>]|(?:PS\s+)?[A-Za-z]:\\[^\r\n>]*>|(?:sh|bash|zsh|dash)-[\d.]+[$#]|[$#>])\s+/;
  var _KNOWN_CMD_LINE_RE = /^\s*(?:sudo\s+|proxychains4?\s+)?(?:nmap|masscan|rustscan|nxc|netexec|crackmapexec|cme|impacket-[a-z0-9_-]+|[A-Za-z0-9_-]+\.py|ldapsearch|smbclient|smbmap|rpcclient|enum4linux(?:-ng)?|kerbrute|bloodhound(?:-python)?|sharphound|bloodyad|certipy(?:-ad)?|certify(?:\.exe)?|rubeus(?:\.exe)?|mimikatz(?:\.exe)?|pypykatz|evil-winrm|ssh|sshpass|hashcat|john|hydra|medusa|ncrack|crowbar|ffuf|feroxbuster|gobuster|dirb|dirsearch|wfuzz|httpx|nuclei|nikto|whatweb|wpscan|arjun|sqlmap|git-dumper|curl|wget|snmpwalk|snmpbulkwalk|snmp-check|onesixtyone|mysql|psql|redis-cli|mongosh|sqlite3|sqlplus|odat|dig|nslookup|host|dnsrecon|chisel|ligolo[a-z_-]*|sshuttle|responder|ike-scan|ipmitool|nth|hashid|hash-identifier|haiti|searchsploit|linpeas|winpeas|whoami|id|uname|find|getcap|ps|netstat|ss|ip|ifconfig|ipconfig|arp|route|systeminfo|schtasks|reg|cmdkey|icacls|accesschk|klist|nltest|powerview|get-net\w+|get-domain\w+|get-ad\w+|invoke-\w+|cat|type)\b/i;

  // Convenience for pasted terminal output without a specific action card.
  OBOL.parsers.analyzeTerminal = function (text, opts) {
    opts = opts || {};
    var cleanText = _stripAnsi(text || '');
    var lines = cleanText.split(/\r?\n/);
    var inferredCmd = _stripAnsi(opts.command || '');
    if (!inferredCmd && lines.length) {
      var l0 = lines[0].trim();
      if (/^[┌╭─]+/.test(l0) && lines.length > 1 && /^\s*[└╰─]+\s*[$#%>]/.test(lines[1])) {
        inferredCmd = lines[1].replace(/^\s*[└╰─]+\s*[$#%>]\s*/, '').trim();
      } else if (_PROMPT_PREFIX_RE.test(l0)) {
        inferredCmd = l0.replace(_PROMPT_PREFIX_RE, '').trim();
      } else if (_KNOWN_CMD_LINE_RE.test(l0) && !/^(?:Host|User-Agent|Server|Location|Set-Cookie|Allow|Public)\s*:/i.test(l0)) {
        inferredCmd = l0;
      }
    }
    return parseActionOutput({
      actionId: opts.actionId || 'operator-ingest',
      command: inferredCmd,
      stdout: cleanText,
      stderr: '',
      source: opts.source !== undefined ? opts.source : (opts.command || inferredCmd),
      scope: opts.scope,
      domain: opts.domain,
    });
  };

})(typeof globalThis !== 'undefined' ? globalThis : this);
