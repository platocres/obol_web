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
  if (C && !C._parse_searchsploit && typeof require === 'function') {
    try { require('./edb.js'); } catch (_e) {}
  }
  OBOL.parsers = OBOL.parsers || {};

  function has(name) { return typeof C[name] === 'function'; }

  var _PUBLIC_REF_HOST_RE = /(?:^|\.)(?:google\.[a-z.]{2,6}|stackoverflow\.com|stackexchange\.com|github\.com|githubusercontent\.com|microsoft\.com|learn\.microsoft\.com|exploit-db\.com)$/i;
  function _is_public_reference_http_cmd(command, ws) {
    var cmd = String(command || '').trim();
    if (!/^(?:sudo\s+|proxychains4?\s+)?(?:GET|POST|HEAD|curl|wget)\b/i.test(cmd)) return false;
    var urlMatches = cmd.match(/https?:\/\/([^/\s:'"?#]+)/gi);
    if (!urlMatches || !urlMatches.length) return false;
    var targetLow = String((ws && ws.target) || '').trim().toLowerCase().replace(/\.$/, '');
    var domLow = String((ws && ws.domainSeed) || '').trim().toLowerCase().replace(/\.$/, '');
    for (var i = 0; i < urlMatches.length; i++) {
      var hm = /^https?:\/\/([^/\s:'"?#]+)/i.exec(urlMatches[i]);
      var host = hm ? hm[1].trim().toLowerCase().replace(/\.$/, '') : '';
      if (!host) continue;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host === 'localhost') return false;
      if (targetLow && (host === targetLow || host.slice(-(targetLow.length + 1)) === '.' + targetLow)) return false;
      if (domLow && (host === domLow || host.slice(-(domLow.length + 1)) === '.' + domLow)) return false;
      if (!_PUBLIC_REF_HOST_RE.test(host)) return false;
    }
    return true;
  }
  if (C) C._is_public_reference_http_cmd = _is_public_reference_http_cmd;

  function _is_dos_emulator_ctx(command, text, promptLine) {
    if (C && typeof C.isDosEmulatorContext === 'function') {
      return !!C.isDosEmulatorContext(command, text, promptLine);
    }
    var combined = String(command || '') + '\n' + String(text || '');
    if (/\bdosbox\b|Drive [A-Z] is mounted as (?:local directory|internal Virtual Drive)|\bMOUNT\s+[A-Za-z]\s+\/(?:\s|$)/i.test(combined)) {
      return true;
    }
    var promptCtx = String(promptLine || '') + '\n' + String(text || '');
    if (/^\s*[A-Za-z]:\\>/m.test(promptCtx) && /(?:^|\s|[><|"'=])\/(?:etc|usr|bin|sbin|var|home|root|tmp|opt)\//.test(combined)) {
      return true;
    }
    return false;
  }

  function _stripAnsi(s) {
    if (C && typeof C.stripAnsi === 'function') return C.stripAnsi(s);
    return String(s || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g, '');
  }

  function makeWs(scope, domain, context, opts) {
    var s = String(scope || '').trim();
    var target = (s.indexOf('host:') === 0 ? s.slice(5) : (C && C._IPV4_RE && C._IPV4_RE.test(s) ? s : '')) || 'target';
    var seed = [];
    var infFs = opts && opts._inferenceContext && (opts._inferenceContext.factSet || opts._inferenceContext.globalFacts);
    if (context && context.facts) {
      seed = context.facts.facts || context.facts;
    } else if (opts && (opts.seedFacts || opts.facts)) {
      var of = opts.seedFacts || opts.facts;
      seed = of.facts || of;
    } else if (infFs) {
      seed = infFs.facts || infFs;
    } else if (root.OBOL && root.OBOL.store && typeof root.OBOL.store.active === 'function') {
      var activeEng = root.OBOL.store.active();
      if (activeEng && activeEng.facts) {
        seed = root.OBOL.store.factSetForTarget ? root.OBOL.store.factSetForTarget(target).facts : activeEng.facts.filter(function (f) {
          return f.scope === 'host:' + target || (domain && f.scope === 'domain:' + domain);
        });
      }
    }
    if (!Array.isArray(seed)) seed = [];
    return { target: target, domainSeed: domain || '', seedFacts: seed, facts: seed, context: context || {} };
  }

  function parseActionOutput(opts) {
    opts = opts || {};
    var rawCmd = _stripAnsi(opts.command || '').trim();
    var att = (!rawCmd && ((opts.context && opts.context.attentionFrame && opts.context.attentionFrame.matchedCopy)
      || (opts._inferenceContext && opts._inferenceContext.attention))) || null;
    var actionId = (opts.actionId && opts.actionId !== 'operator-ingest') ? opts.actionId : ((att && att.actionId) || opts.actionId || '');
    var command = rawCmd || _stripAnsi((att && att.command) || '').trim();
    var stdout = opts.stdout || '';
    var stderr = opts.stderr || '';
    var source = (opts.source !== undefined && opts.source !== null) ? _stripAnsi(opts.source) : command;
    var ws = makeWs(opts.scope, opts.domain, opts.context, opts);
    var rawCombined = [stdout, stderr].filter(Boolean).join('\n');
    var text = rawCombined.indexOf('\x1b') >= 0 ? _stripAnsi(rawCombined) : rawCombined;
    // Normalize CRLF, mid-line carriage-return progress spinner overwrites, tmux vertical split bleed, and wrapped Kerberos hashes
    if (text.indexOf('\r') >= 0) {
      text = (C && C._normalize_cr) ? C._normalize_cr(text) : text.replace(/\r+\n/g, '\n').replace(/^[^\n]*\r(?!\n)/gm, '');
    }
    if (C && C._strip_tmux_split && (text.indexOf('\u2502') >= 0 || text.indexOf('\u2503') >= 0)) text = C._strip_tmux_split(text);
    if (C && C._unwrap_kerberos_hashes && (text.indexOf('$krb5') >= 0 || text.indexOf('$KRB5') >= 0)) text = C._unwrap_kerberos_hashes(text);
    if (/\[proxychains\]|-chain\|-<>-/i.test(text)) {
      ws._hasProxychains = true;
      if (C && C._strip_proxychains) text = C._strip_proxychains(text);
    }
    if (text.length > 10485760 && !/<nmaprun\b/i.test(text.slice(0, 2048)) && !/distinguishedName:/i.test(text.slice(0, 4096))) {
      text = text.slice(0, 10485760);
    }
    var facts = [];

    // Isolate independent parsers so one failure cannot discard later observations.
    var diagnostics = [], guarded = Object.create(C);
    Object.keys(C).forEach(function (name) {
      if (typeof C[name] !== 'function' || !/^_(?:parse_|looks_like_|domain_from_text)/.test(name)) return;
      guarded[name] = function () {
        try { return C[name].apply(C, arguments); }
        catch (err) {
          diagnostics.push({ parser: name, message: (err && err.message) || String(err) });
          try { if (typeof console !== 'undefined' && console.warn) console.warn('obol parser: ' + name + ' failed: ' + diagnostics[diagnostics.length - 1].message); } catch (ignored) {}
        }
      };
    });
    var lc = command.toLowerCase();
    var bigProbeSample = text.length > 65536 ? (text.slice(0, 32768) + '\n' + text.slice(-32768)) : text;
    var isPublicRefHttp = _is_public_reference_http_cmd(command, ws);
    var hasFtpUri = /\bftp:\/\/[^\s'"]+/i.test(command);
    var isFtpOnlyUriCmd = hasFtpUri && !/\bhttps?:\/\/[^\s'"]+/i.test(command) && !/^(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(bigProbeSample);
    var hasFtpOwnerListing = (bigProbeSample.match(/^\s*[-d][rwxstST-]{9}\s+\d+\s+ftp\s+ftp\s+\d+\s+/gim) || []).length >= 2;
    var domainHint = '';
    var actObj = { id: actionId };
    try {

    domainHint = has('_domain_from_text') ? guarded._domain_from_text(bigProbeSample) : '';

    var _nmapOpenRe = C._NMAP_OPEN_RE || C._NMAP_PORT_RE;
    var looksLikeNmapContent = /<nmaprun\b|Nmap scan report for\b|Starting Nmap\b|Discovered open port \d+\/(?:tcp|udp) on \d|^[ \t]*Open \d{1,3}(?:\.\d{1,3}){3}:\d+/im.test(bigProbeSample)
      || ((bigProbeSample.indexOf('/tcp') >= 0 || bigProbeSample.indexOf('/udp') >= 0) && _nmapOpenRe && _nmapOpenRe.test(bigProbeSample)
        && (/Service Info:|Host script results:|^[ \t]*\|[_ ][a-z0-9-]+:|^[ \t]*\|[_ ]|MAC Address:|OS details:|^[ \t]*PORT[ \t]+STATE[ \t]+SERVICE\b/im.test(bigProbeSample)
          || (C.reAll && C.reAll(_nmapOpenRe, bigProbeSample).length >= 2)));
    if (/\b(?:nmap|masscan|rustscan)\b/.test(lc) || looksLikeNmapContent) {
      if (has('_parse_nmap')) guarded._parse_nmap(text, ws, source, facts, actionId, command);
    }

    var isNxc = /\b(?:nxc|netexec|crackmapexec|cme)\b/.test(lc)
      || /^(?:SMB|LDAP|WINRM|MSSQL|FTP|SSH|RDP|WMI|VNC|NFS)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+/im.test(bigProbeSample)
      || /^(?:GPP_PASS(?:WORD)?|GPP_AUTOLOGIN|LSASSY|NANODUMP|HANDLEKATZ|PROCDUMP|MASKY|SPIDER_PLUS|WDIGEST|COERCE_PLUS|PETITPOTAM|DFSCOERCE|SHADOWCOERCE|PRINTERBUG|BACKUP_OPERATOR|REG-WINLOGON|REG-QUERY|VEEAM|MREMOTENG|WINSCP|PUTTY|KEEPASS_DISCOVER|KEEPASS_TRIGGER|INSTALL_ELEVATED|PRE2K|NTLMV1|ENUM_AV|SPOOLER|WEBDAV|RUNASPPL|MS17-010|ZEROLOGON|SMBGHOST|NOPAC|PRINTNIGHTMARE|ENUM_CVE|RDCMAN|IIS|FIREFOX|POWERSHELL_HISTORY|MET_INJECT|SLINKY|SCUFFY|DACLREAD|GROUP-MEM|ADCS|USER-DESC|GET-DESC-USERS|ENUM_TRUSTS|LDAP-CHECKER|MAQ|MSSQL_PRIV|MSSQL_COERCE|WIFI)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+/im.test(bigProbeSample);
    if (isNxc) {
      guarded._parse_nxc_common(text, ws, source, facts);
      // Data-driven capability catalog (nxc-catalog.js): fills the switches the hand-written parsers below
      // don't cover (--users on smb, --lsa cleartext, -M gpp_password/lsassy/...). Facts dedupe, so running it
      // alongside the existing parsers is safe. See docs + tests/engine/nxc-switch-parsers.js.
      if (has('_parse_nxc_capability')) guarded._parse_nxc_capability(text, command, ws, source, facts);
      if ((C._is_ldap_command(command) || /^LDAP\s+\d+\.\d+\.\d+\.\d+/im.test(text)) && (actionId === 'ad-anon-ldap-enum' || lc.indexOf('--users') >= 0 || lc.indexOf('--active-users') >= 0 || /-description-/i.test(text))) {
        guarded._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
        if ((lc.indexOf('--users') >= 0 || lc.indexOf('--active-users') >= 0 || /-description-/i.test(text)) && has('_parse_ldap_descriptions')) guarded._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
      }
      if (C._is_smb_command(command) || /^SMB\s+\d+\.\d+\.\d+\.\d+/im.test(text)) {
        guarded._parse_nxc_smb_session(text, ws, command, source, facts);
        guarded._parse_smb_shares(text, ws, source, facts);
        if (actionId === 'ad-user-enum' || lc.indexOf('--rid-brute') >= 0 || lc.indexOf('--users') >= 0 || /\(SidTypeUser\)/i.test(text)) guarded._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint, command: command });
      }
      if (lc.indexOf('--asreproast') >= 0 || text.indexOf('$krb5asrep$') >= 0) guarded._parse_asrep_hashes(text, ws, source, facts);
      guarded._parse_nxc_auth_validation(text, ws, source, facts);
      guarded._parse_auth_failures(text, ws, source, facts);
      if (lc.indexOf('--kerberoast') >= 0 || lc.indexOf('--kerberoasting') >= 0 || text.indexOf('$krb5tgs$') >= 0) guarded._parse_tgs_hashes(text, ws, source, facts);
      if (lc.indexOf('--bloodhound') >= 0 || /Compromised|\b\d{8,14}_bloodhound\.zip\b/i.test(text)) guarded._parse_bloodhound_collection(text, ws, source, facts);
    }

    if (lc.indexOf('ldapsearch') >= 0 || /^dn:\s*(?:CN|DC|OU|uid)=/im.test(text) || /^namingContexts:/im.test(text) || /^\s*distinguishedName\s*:\s*CN=/im.test(text)) {
      guarded._parse_ldapsearch(text, ws, source, facts);
      if (actionId === 'ad-anon-ldap-enum' || lc.indexOf('(objectclass=user)') >= 0 || /sAMAccountName:/i.test(text)) guarded._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
      if (/^\s*description\s*:/im.test(text) && has('_parse_ldap_descriptions')) guarded._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
    }

    var _bareSmbAnchors = (bigProbeSample.match(/^[ \t]*(?:ADMIN\$|C\$|IPC\$|SYSVOL|NETLOGON|PRINT\$)[ \t]*$/gim) || []).length >= 2;
    var isSmbEnum = lc.indexOf('smbclient') >= 0 || lc.indexOf('smbmap') >= 0 || lc.indexOf('rpcclient') >= 0 || lc.indexOf('enum4linux') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('samrdump') >= 0
      || /^\s*#?\s*shares\s*$/i.test(command || '')
      || (_bareSmbAnchors && (/^\s*#?\s*shares\s*$/im.test(bigProbeSample) || bigProbeSample.trim().split(/\r?\n/).length <= 32))
      || /^\s*Sharename\s+Type\s+Comment/im.test(bigProbeSample) || /^\s*Disk\s+Permissions\s+Comment/im.test(bigProbeSample) || /user:\[[^\]]+\]\s+rid:\[/i.test(bigProbeSample) || /\(SidTypeUser\)/i.test(bigProbeSample) || /\bindex:\s*0x[0-9a-f]+\s+RID:\s*0x/i.test(bigProbeSample);
    if (isSmbEnum) {
      guarded._parse_smb_shares(text, ws, source, facts);
      guarded._parse_gpp_artifacts(text, ws, source, facts);
      if (actionId === 'ad-user-enum' || lc.indexOf('enumdomusers') >= 0 || lc.indexOf('enum4linux') >= 0 || lc.indexOf('rpcclient') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('samrdump') >= 0 || /user:\[[^\]]+\]\s+rid:\[|\(SidTypeUser\)|\bindex:\s*0x[0-9a-f]+\s+RID:\s*0x/i.test(bigProbeSample)) {
        guarded._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint, command: command });
        if (/description\s*:\s*\[/i.test(bigProbeSample) && has('_parse_ldap_descriptions')) guarded._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
      }
    }
    if ((lc.indexOf('rpcdump') >= 0 || /Protocol:\s*\[MS-[A-Z0-9-]+\]:[\s\S]{1,200}?Bindings:/i.test(bigProbeSample)) && has('_parse_rpcdump')) {
      guarded._parse_rpcdump(text, ws, command, source, facts);
    }

    // Interactive smbclient "smb: \>" ls/dir listings carry no tool token on the unit command
    // (the command is just "ls"/"dir"), so sniff the output: the blocks-of-size footer, or at
    // least two "name ATTR size Day Mon DD HH:MM:SS YYYY" listing rows.
    var _smbLsFooter = bigProbeSample.indexOf('blocks available') >= 0 && /\d+\s+blocks of size\s+\d+\.\s+\d+\s+blocks available/i.test(bigProbeSample);
    var _smbLsRows = (!_smbLsFooter && /(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}/i.test(bigProbeSample) && /^[ \t]+\S(?:[^\r\n]*?\S)?[ \t]+[DAHSRNCETI]+\s+\d+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s*$/im.test(bigProbeSample)) ? 1 : 0;
    if (lc.indexOf('spider_plus') >= 0 || (lc.indexOf('smbmap') >= 0 && (' ' + lc).indexOf(' -r') >= 0) || lc.indexOf('smbclient') >= 0 || bigProbeSample.indexOf('getting file ') >= 0 || bigProbeSample.indexOf('putting file ') >= 0 || _smbLsFooter || _smbLsRows >= 1 || /stream:\s*\[:[^\]]+:\$DATA\]/i.test(bigProbeSample) || (isSmbEnum && /\b(?:unattend|sysprep|groups|services|scheduledtasks)\.xml\b|\bweb\.config\b|(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{1,120}\.(?:kdbx|ppk|ovpn|pfx|vmdk)\b/i.test(bigProbeSample))) {
      guarded._parse_share_inventory(text, ws, command, source, facts);
    }

    // Native on-host directory listings carry no tool token on the unit command (just "dir"/"ls"/
    // "gci"), so sniff the output anchors: cmd "Directory of <path>" or the PowerShell Get-ChildItem
    // "Mode  LastWriteTime  Length Name" table header (also emitted by Invoke-Command { ls }). The
    // parser only takes rows under a matching header, so a stray date or "-a---" line never mints.
    if ((/^\s*Directory of\s+\S/im.test(bigProbeSample) || /^\s*Mode\s+LastWriteTime\s+Length\s+Name/im.test(bigProbeSample) || /^\s*(?:Directory|[^\s:\\/0-9]{2,24})\s*:\s+(?:[A-Za-z]:\\|\\\\[^\\\s]+\\)/im.test(bigProbeSample)) && has('_parse_fs_listing')) {
      guarded._parse_fs_listing(text, ws, command, source, facts);
    }

    if (lc.indexOf('grep') >= 0 || lc.indexOf('find') >= 0 || lc.indexOf('lootgrep') >= 0 || text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) {
      guarded._parse_gpp_artifacts(text, ws, source, facts);
    }

    if (!isNxc && (lc.indexOf('gpp-decrypt') >= 0 || actionId === 'gpp-passwords' || actionId === 'gpp-decrypt' || /gpp-decrypt|ciphertext/i.test(bigProbeSample)) && has('_parse_gpp_decrypted')) {
      guarded._parse_gpp_decrypted(text, ws, source, facts);
    }
    if (lc.indexOf('wpscan') >= 0 || actionId === 'wordpress' || /WordPress version\s+\d|\[\+\]\s*User\(s\)\s+Identified/i.test(bigProbeSample)) guarded._parse_wpscan(text, ws, source, facts);
    if ((actionId === 'trust-enum' || lc.indexOf('domain_trusts') >= 0 || lc.indexOf('domaintrust') >= 0 || lc.indexOf('lookupsid') >= 0 || lc.indexOf('nltest') >= 0 || /Domain Trusts|SourceName\s*:\s*\S+[\s\S]{1,160}?TargetName\s*:\s*\S+|TrustDirection\s*:/i.test(bigProbeSample)) && has('_parse_domain_trusts')) guarded._parse_domain_trusts(text, ws, source, facts);
    if ((actionId === 'zerologon-check' || lc.indexOf('zerologon') >= 0 || /CVE-2020-1472|Success!\s+DC can be fully compromised by a Zerologon attack/i.test(bigProbeSample)) && has('_parse_zerologon_scan')) guarded._parse_zerologon_scan(text, ws, source, facts);
    var looksLikePowerViewContent = /samaccountname\s*:\s*\S+[\s\S]{1,300}?(?:serviceprincipalname|useraccountcontrol|admincount|description)\s*:|Forest\s*:\s*\S+[\s\S]{1,240}?DomainControllers\s*:/i.test(bigProbeSample)
      || (/samaccountname|userprincipalname|dnshostname|membername/i.test(bigProbeSample) && /^[^\r\n]*\b(?:samaccountname|userprincipalname|dnshostname|membername)\b[^\r\n]*\r?\n[ \t]*-+(?:[ \t]+-+)*[ \t]*$/im.test(bigProbeSample))
      || /^[ \t]*Name[ \t]+Type[ \t]+Remark[ \t]+ComputerName[ \t]*$/im.test(bigProbeSample)
      || (bigProbeSample.indexOf('\\\\') >= 0 && (/^[ \t]*\\\\[A-Za-z0-9_.-]+\\[^\s\\]+[ \t]+-[ \t]*[^\r\n]*$/im.test(bigProbeSample)
        || (!command && /^[ \t]*\\\\[A-Za-z0-9_.-]+\\[^\s\\]+[ \t]*$/im.test(bigProbeSample))));
    if ((actionId === 'powerview-enum' || /\b(?:get-(?:net|domain|ad)user|get-(?:net)?domain(?:controller)?|get-(?:net|domain)groupmember|get-(?:net|domain)computer|invoke-sharefinder)\b/i.test(lc) || looksLikePowerViewContent) && has('_parse_powerview')) guarded._parse_powerview(text, ws, command, source, facts, { domain_hint: domainHint });
    if ((['get-netgroup', 'get-domaingroup', 'get-netcomputer', 'get-domaincomputer', 'objectacl', 'get-acl', 'find-interestingdomainacl'].some(function (k) { return lc.indexOf(k) >= 0; }) || /(?:ObjectDN|ObjectSID)\s*:\s*\S+[\s\S]{1,250}?ActiveDirectoryRights\s*:/i.test(text)) && has('_parse_powerview_objects')) guarded._parse_powerview_objects(text, ws, command, source, facts, { domain_hint: domainHint });
    if (/\bget-gppermission\b/i.test(lc) || (has('_looks_like_gp_permission') && guarded._looks_like_gp_permission(text)) || /Trustee\s*:\s*\S+[\s\S]{1,160}?TrusteeType\s*:\s*\S+[\s\S]{1,160}?Permission\s*:/i.test(text)) {
      if (has('_parse_gp_permission')) guarded._parse_gp_permission(text, ws, command, source, facts, { domain_hint: domainHint });
      else if (OBOL._directoryParsers && typeof OBOL._directoryParsers._parse_gp_permission === 'function') {
        try { OBOL._directoryParsers._parse_gp_permission(text, ws, command, source, facts, { domain_hint: domainHint }); }
        catch (gpErr) { diagnostics.push({ parser: '_parse_gp_permission', message: (gpErr && gpErr.message) || String(gpErr) }); }
      }
    }

    if (lc.indexOf('kerbrute') >= 0 || /VALID USERNAME:\s*\S+@\S+|VALID LOGIN:\s*\S+@\S+/i.test(text)) guarded._parse_kerbrute(text, ws, source, facts, { domain_hint: domainHint });

    if (lc.indexOf('getnpusers') >= 0 || lc.indexOf('asreproast') >= 0 || text.indexOf('$krb5asrep$') >= 0 || (/^Name\s+MemberOf\s+PasswordLastSet/im.test(text) && /UF_DONT_REQUIRE_PREAUTH|DONT_REQ_PREAUTH/i.test(text))) guarded._parse_asrep_hashes(text, ws, source, facts);
    if (lc.indexOf('getuserspns') >= 0 || lc.indexOf('kerberoast') >= 0 || text.indexOf('$krb5tgs$') >= 0 || /^ServicePrincipalName\s+Name\s+MemberOf/im.test(text)) guarded._parse_tgs_hashes(text, ws, source, facts);

    if (lc.indexOf('secretsdump') >= 0 || /\bsecretsdump\b/i.test(text) || lc.indexOf('hashdump') >= 0 || lc.indexOf('samdump2') >= 0 || lc.indexOf('pwdump') >= 0 || lc.indexOf('fgdump') >= 0 || actionId === 'vhd-mount-sam-extract' || (lc.indexOf('volatility') >= 0 && lc.indexOf('dump') >= 0) || (isNxc && ['--ntds', '--sam', '--lsa'].some(function (f) { return lc.indexOf(f) >= 0; })) || (C._looks_like_sam_dump && guarded._looks_like_sam_dump(text)) || (text.indexOf(':::') >= 0 && /^(?:[A-Za-z0-9._-]+\\)?[A-Za-z0-9._$-]+:\d{3,6}:NO PASSWORD\*+:[0-9a-fA-F]{32}:::/im.test(text)) || /Dumping (?:local )?SAM hashes|Dumping LSA Secrets|Dumping Domain Credentials|_SC_[A-Za-z0-9_.-]+/i.test(text)) {
      guarded._parse_ntlm_dump(text, ws, command, source, facts);
    }

    // mimikatz / pypykatz credential dumps: sekurlsa::logonpasswords -> hash.ntlm (+ credential.plaintext
    // when a cleartext is present), lsadump::sam/lsa -> hash.ntlm (+ loot.ntds for a full dump). Routed on
    // the command OR a content signature so an attached dump file with no command line still mints.
    if ((lc.indexOf('mimikatz') >= 0 || lc.indexOf('sekurlsa') >= 0 || lc.indexOf('lsadump') >= 0 || lc.indexOf('pypykatz') >= 0 || /\b(?:creds_all|creds_msv|creds_wdigest|creds_kerberos|lsa_dump_sam|lsa_dump_secrets)\b/.test(lc) || (has('_looks_like_mimikatz') && guarded._looks_like_mimikatz(bigProbeSample))) && has('_parse_mimikatz')) guarded._parse_mimikatz(text, ws, command, source, facts);

    // MSCache2/DCC2 cached domain hashes ($DCC2$...) from secretsdump cached output or lsadump::cache.
    // Routed on the content token so a pasted cache dump mints even without a recognizable command line.
    if (has('_looks_like_mscache') && guarded._looks_like_mscache(text)) guarded._parse_mscache(text, ws, command, source, facts);

    // Timeroasting ($sntp-ms$...) hashes from NetExec -M timeroast or raw SNTP tool dumps.
    if (has('_looks_like_timeroast') && guarded._looks_like_timeroast(text)) guarded._parse_timeroast(text, ws, command, source, facts);

    var _IS_PAYLOAD_BUILDER_CMD_RE = /^\s*(?:sudo\s+)?msfvenom\b/i;
    var isPayloadBuilderCmd = _IS_PAYLOAD_BUILDER_CMD_RE.test(command || '');

    // Structured cleartext credential blocks (Domain: ... Username: ... Password: ...) and process leaks.
    if (!isPayloadBuilderCmd && !isPublicRefHttp && has('_looks_like_generic_dumped_credentials') && guarded._looks_like_generic_dumped_credentials(bigProbeSample, command, ws)) guarded._parse_generic_dumped_credentials(text, ws, command, source, facts);
    if (has('_looks_like_tshark_http') && guarded._looks_like_tshark_http(bigProbeSample, command) && has('_parse_tshark_http_creds')) guarded._parse_tshark_http_creds(text, ws, command, source, facts);

    if (lc.indexOf('bloodhound-python') >= 0 || lc.indexOf('sharphound') >= 0 || /\b\d{8,14}_(?:bloodhound|computers|users|groups|domains)\.zip\b|Done in \d+M \d+S/i.test(text)) guarded._parse_bloodhound_collection(text, ws, source, facts);
    if (lc.indexOf('bloodhound') >= 0 || /Compromised-Owned-Principal|Shortest Paths to Domain Admins|-\[\s*MemberOf\s*\]->/i.test(text)) guarded._parse_bloodhound_analysis(text, ws, source, facts);

    if ((' ' + lc + ' ').indexOf(' winrm ') >= 0 || lc.indexOf('evil-winrm') >= 0 || /\*Evil-WinRM\*\s+PS\s+[A-Za-z]:\\/i.test([text, ws && ws.context && ws.context.promptLine, ws && ws.context && ws.context.followPrompt].filter(Boolean).join('\n'))) guarded._parse_evil_winrm(text, ws, command, source, facts);
    if ((lc.indexOf('xfreerdp') >= 0 || lc.indexOf('freerdp') >= 0 || text.indexOf('[com.freerdp.') >= 0 || text.indexOf('Logon Info V') >= 0 || text.indexOf('Authentication only, exit status 0') >= 0 || /Remote framebuffer format PIXEL_FORMAT_|Loading Dynamic Virtual Channel rdpgfx/i.test(text)) && has('_parse_xfreerdp')) guarded._parse_xfreerdp(text, ws, command, source, facts);

    var isSsh = C._is_ssh_command(command);
    if (isSsh) guarded._parse_ssh_exec(text, ws, command, source, facts);
    // An SSH key login that FAILED (any client, any cause) -> mint ssh.key_rejected so the troubleshooter
    // surfaces the fix. Keyed on the output, so it also catches a bare pasted error with no command.
    if ((isSsh || /\bssh\b/.test(lc) || /Permission denied \(publickey|UNPROTECTED PRIVATE KEY|no mutual signature/i.test(text)) && C._parse_ssh_key_diagnostics)
      guarded._parse_ssh_key_diagnostics(text, ws, source, facts);
    // Auth blockers (a valid credential refused for a fixable reason) can come from any auth tool -
    // nxc, impacket, smbclient, ssh - so recognize them content-first, not tool-gated.
    if (C._parse_auth_blockers && /STATUS_PASSWORD_(?:MUST_CHANGE|EXPIRED)|must change .*password|password has expired|KDC_ERR_KEY_EXPIRED|0xc0000224|0xc0000071|data 532\b|data 773\b|KRB_AP_ERR_SKEW|clock skew too great|time difference too large|STATUS_NOT_SUPPORTED|NT_STATUS_NOT_SUPPORTED|STATUS_NTLMPASSWORD_DISABLED|0xc00000bb|StrongerAuthRequired|NTLM[\s\S]{0,30}disabled|STATUS_ACCOUNT_(?:LOCKED_OUT|DISABLED|RESTRICTION|EXPIRED)|KDC_ERR_CLIENT_REVOKED|0xc0000234|data 775\b|STATUS_LOGON_TYPE_NOT_GRANTED|STATUS_INVALID_LOGON_HOURS|STATUS_INVALID_WORKSTATION|0xc000006e|0xc000006f|0xc0000070|0xc0000072|0xc000015b|0xc0000193|data 530\b|data 531\b|data 533\b|data 701\b|locked out|insufficientAccessRights|insufficient access rights|INSUFFICIENT_ACCESS_RIGHTS|INSUFF_ACCESS_RIGHTS|dsid-03152|ERROR_DS_DRA_ACCESS_DENIED/i.test(bigProbeSample))
      guarded._parse_auth_blockers(text, ws, source, facts);
    // Operational blockers (recon/exec/privesc/web traps) - all content-first, any tool.
    if (C._parse_op_blockers) guarded._parse_op_blockers(bigProbeSample, ws, command, source, facts);

    var headTailSample = text.length > 16384 ? (text.slice(0, 8192) + '\n' + text.slice(-8192)) : text;
    var isHttpContext = !isPayloadBuilderCmd && !isPublicRefHttp && !isFtpOnlyUriCmd && (
      /^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(headTailSample)
      || /<(?:!doctype\s+html|html|head|body|pre)\b/i.test(headTailSample)
      || /\bhttps?:\/\/[^\s'"]+/i.test(command)
    );
    var isHttpClientTurn = !isPayloadBuilderCmd && !isPublicRefHttp && !isFtpOnlyUriCmd && (
      /\b(?:curl|wget|httpie)\b/i.test(lc)
      || (/\b(?:http|python3?|ruby|perl|php)\b/i.test(lc) && (isHttpContext || /\b(?:requests|urllib|httpx|aiohttp|http\.client|curl_init)\b/i.test(command)))
      || isHttpContext
    );
    var hasWebCmdiBody = !!((C._LINUX_ID_RE && C._LINUX_ID_RE.test(headTailSample))
      || (C._CMDI_UID_RE && C._CMDI_UID_RE.test(headTailSample))
      || (C._CMDI_WIN_RE && C._CMDI_WIN_RE.test(headTailSample))
      || /<(?:pre|body|html|p|div)\b[\s\S]{0,400}?\b(?:nt authority\\(?:system|network service|local service)|iis apppool\\[a-z0-9_.-]+)\b/i.test(headTailSample));
    var hasWebLfiBody = !!((C._LFI_PASSWD_RE && C._LFI_PASSWD_RE.test(headTailSample) && C._LFI_PASSWD_SECOND_RE && C._LFI_PASSWD_SECOND_RE.test(headTailSample))
      || (C._LFI_WIN_INI_RE && C._LFI_WIN_INI_RE.test(headTailSample))
      || /^root:\$(?:1|2[abxy]|5|6|y)\$[^\r\n:]+:/m.test(headTailSample));
    var isRemoteWebExploitScriptTurn = !isPayloadBuilderCmd && !isSsh && !isFtpOnlyUriCmd
      && (/\b(?:python3?|ruby|perl|php)\b/i.test(lc) || /\.(?:py|rb|pl|sh)\b/i.test(lc))
      && (/\bhttps?:\/\/[^\s'"]+/i.test(command) || /(?:^|\s)(?:--?(?:rhost|host|target|url)|-[HhUuTt])\s+\S+/.test(command || ''));
    var hasWebExploitReplOrUploadBody = !isPayloadBuilderCmd && !isSsh && !isFtpOnlyUriCmd && !C._is_web_content_command(command)
      && !!((C._WEBSHELL_UPLOAD_RECEIPT_RE && C._WEBSHELL_UPLOAD_RECEIPT_RE.test(headTailSample))
        || (C._WEB_EXPLOIT_REPL_WHOAMI_RE && /\bwhoami\b/i.test(headTailSample) && C._WEB_EXPLOIT_REPL_WHOAMI_RE.test(headTailSample) && !/^\s*whoami\s*$/i.test(command || '')));
    var callerPromptRaw = String((ws && ws.context && ws.context.promptLine) || '').split(/\r?\n/)[0].trim();
    var callerUnixPromptM = callerPromptRaw
      ? (/^(?:\([^)]+\)\s*)?\[?([a-zA-Z0-9_.-]+)(?:@|\u327f)([a-zA-Z0-9_.-]+)(?:[:\s][^\]]*)?\]?\s*[#$%]/.exec(callerPromptRaw)
        || /^((?:sh|bash|zsh|dash|ksh)-[\d.]+)\s*[#$]/.exec(callerPromptRaw))
      : null;
    var hasVerifiedLocalTargetPrompt = !!(callerUnixPromptM
      && !/\[(?:tun|tap|vpn|wg)\d*:/i.test(callerPromptRaw)
      && (callerUnixPromptM[3]
        || (!/^(?:kali|parrot|pwnbox|htb|attacker|pentest|offsec|vagrant|archlinux|exegol|slingshot|commando|blackarch)$/i.test(callerUnixPromptM[1] || '')
            && !/^(?:kali|parrot|pwnbox|htb|attacker|pentest|offsec|vagrant|archlinux|exegol|slingshot|commando|blackarch)$/i.test(callerUnixPromptM[2] || ''))));
    var hasWebExploitHttpSignal = isHttpContext
      || /\bhttps?:\/\/|--url\b|-u\s+\S+|:\d{2,5}\//i.test(command || '')
      || /\bHTTP\/1\.[01]\s+\d{3}\b|\bwebshell\b|wp-content\/uploads\//i.test(headTailSample);
    var isWebExploitCmd = !isPayloadBuilderCmd && !isPublicRefHttp && ((C._WEB_EXPLOIT_ACTION_IDS && C._WEB_EXPLOIT_ACTION_IDS.has(actionId))
      || ((isHttpClientTurn || isRemoteWebExploitScriptTurn) && (hasWebCmdiBody || hasWebLfiBody || hasWebExploitReplOrUploadBody))
      || (hasWebExploitReplOrUploadBody && hasWebExploitHttpSignal && !(hasVerifiedLocalTargetPrompt && !/\bhttps?:\/\/|--url\b|-u\s+\S+|:\d{2,5}\//i.test(command || '')))
      || (/\b(?:curl|wget|httpie|python3?)\b/.test(lc) && !isFtpOnlyUriCmd && (/cmd=|exec=|shell\.php|cmd\.jsp|cmd\.asp|evil\.|reverse|payload|\.\.\/|%2e%2e|php:\/\/filter|expect:\/\/|data:\/\//i.test(command) || (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(headTailSample) && /root:x:0:0:/i.test(headTailSample))))
      || (!command && (/^root:x:0:0:/im.test(headTailSample) || (C._LFI_WIN_INI_RE && C._LFI_WIN_INI_RE.test(headTailSample)) || (/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(headTailSample) && hasWebCmdiBody))));

    // Service login / DB-RCE / bare `id` output that lands a *nix shell (telnet, rlogin/rsh, psql/odat/sqlplus
    // COPY..PROGRAM and friends, or a bare uid=... gid=... paste): reuse the ssh-exec reader to mint the
    // foothold from a pasted uid=... line.
    if (!isSsh && !isWebExploitCmd && (/\b(telnet|rlogin|rsh|rexec|psql|sqlplus|odat)\b/.test(lc) || (C._LINUX_ID_RE && C._LINUX_ID_RE.test(text) && !/^(?:<\s*)?HTTP\/[0-9.]+\s+\d{3}\b/im.test(text) && !/\b(?:curl|wget|sqlmap|ffuf|gobuster|feroxbuster|nikto)\b/.test(lc)))) guarded._parse_ssh_exec(text, ws, command, source, facts);
    if (!isSsh && C._LINUX_SHELL_ACTION_IDS && C._LINUX_SHELL_ACTION_IDS.has(actionId)) guarded._parse_ssh_exec(text, ws, command, source, facts);

    if (isNxc && ((' ' + lc + ' ').indexOf(' rdp ') >= 0 || /^RDP\s+\d+\.\d+\.\d+\.\d+/im.test(text))) guarded._parse_nxc_rdp(text, ws, command, source, facts);

    var looksLikeCracked = C._is_cracking_command(command) || text.indexOf('$keepass$*') >= 0
      || (C._JOHN_LOADED_RE && C._JOHN_LOADED_RE.test(text))
      || (C._JOHN_CRACKED_FOOTER_RE && C._JOHN_CRACKED_FOOTER_RE.test(text))
      || /^\s*[1-9]\d*g\s+\d+:\d{2}:\d{2}:\d{2}\s+DONE\b|\bUse the "--show" option to display all of the cracked passwords\b/im.test(text)
      || /Session\.+:\s*hashcat|Status\.+:\s*Cracked|\b\d+\s+password\s+hash(?:es)?\s+cracked,\s+\d+\s+left\b/i.test(text)
      || (text.indexOf(':') >= 0 && (text.indexOf('$') >= 0 || text.indexOf('pbkdf2_') >= 0 || text.indexOf('sha256:') >= 0 || /\.kdbx|\.psafe3/i.test(text)) && /^(?:\$krb5(?:tgs|asrep)\$[^\r\n:]+|\$DCC2\$\d+#[^#\r\n]+#[0-9a-fA-F]{32}|\$(?:1|2[abxy]|5|6|y|apr1|sha1|NT|S|ansible|PEM)\$[^\s:]+|pbkdf2_sha(?:1|256|512)\$[^\s:]+|sha256:\d+:[^\s:]+|\S+\.(?:kdbx|psafe3)):[^\r\n]+$/im.test(text));
    if (looksLikeCracked) guarded._parse_cracked_credentials(text, ws, command, source, facts);

    // A bare `whoami` (or `whoami /all`) carries no exec-tool token, so the clause above skips it, yet its
    // output IS a proof of on-host execution: a Windows identity line (DOMAIN\user, host\administrator, or
    // nt authority\system). Route it to the same reader so it mints foothold.windows (+ access.system for
    // SYSTEM), the Windows parity of what a bare `id` already mints for Linux. _WHOAMI_ID_RE only matches a
    // backslash identity, so `whoami /priv` (privilege rows, no identity line) and a Linux `whoami` (root)
    // never trip it, and _parse_command_execution self-gates on a real identity so nothing else mints.
    var execTextSample = text.length > 16384 ? (text.slice(0, 8192) + '\n' + text.slice(-8192)) : text;
    var sshExecCtx = [execTextSample, ws && ws.context && ws.context.promptLine, ws && ws.context && ws.context.followPrompt].filter(Boolean).join('\n');
    var isDosEmu = ((lc.indexOf('dosbox') >= 0 || lc.indexOf('mount ') >= 0 || sshExecCtx.indexOf('dosbox') >= 0 || sshExecCtx.indexOf('DOSBox') >= 0 || sshExecCtx.indexOf('MOUNT ') >= 0 || sshExecCtx.indexOf(':\\>') >= 0)
      && _is_dos_emulator_ctx(command, sshExecCtx, ws && ws.context && ws.context.promptLine));
    var isWhoamiId = !isDosEmu && (/\bwhoami\b/i.test(lc) || /\bwhoami\b|Windows IP Configuration/i.test(execTextSample) || (execTextSample.indexOf(':\\') >= 0 && /^\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/im.test(execTextSample))) && C._WHOAMI_ID_RE && C._WHOAMI_ID_RE.test(execTextSample);
    var isWinInteractivePaste = !isDosEmu && ((C._INTERACTIVE_RE && C._INTERACTIVE_RE.test(execTextSample)) || /\b(?:impacket-)?(?:wmiexec|psexec|smbexec|atexec|dcomexec)(?:\.py)?\b/i.test(execTextSample)
      || /fDenyTSConnections|Remote Desktop Users|Remote Management Users|winrm\s+quickconfig|Enable-PSRemoting|AllowAutoConfig|WinRMInit/i.test(lc)
      || /fDenyTSConnections|Remote Desktop Users|Remote Management Users|winrm\s+quickconfig|Enable-PSRemoting|AllowAutoConfig|WinRMInit/i.test(execTextSample));
    var hasSshAuthFail = isSsh && /\b(?:Permission denied|Authentication failed|Connection refused|Connection timed out|Connection closed by|Host key verification failed|No route to host|Could not resolve hostname)\b/i.test(execTextSample);
    var isSshWindowsExec = isSsh && !isDosEmu && !hasSshAuthFail && (
      /^\s*(?:PS\s+)?[A-Za-z]:\\[^>\r\n]*>/im.test(sshExecCtx)
      || /^\s*(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_.$-]+@[A-Za-z0-9_.-]+\s+[A-Za-z]:\\[^>\r\n]*>/im.test(sshExecCtx)
      || /\bVolume in drive [A-Za-z]\b|^\s*Directory of [A-Za-z]:\\|Microsoft Windows \[Version/im.test(execTextSample)
      || (C._WHOAMI_ID_RE && C._WHOAMI_ID_RE.test(execTextSample))
    );
    if (isSshWindowsExec && C._add && C.mkFact) {
      var sshWinUserM = /(?:^|\s)['"]?(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.$-]+)@[A-Za-z0-9_.-]+/.exec(command || '');
      var sshWinAuthVal = { service: 'ssh', os: 'windows' };
      if (sshWinUserM && sshWinUserM[1]) sshWinAuthVal.user = C._clean_username ? C._clean_username(sshWinUserM[1]) : sshWinUserM[1];
      C._add(facts, C.mkFact('ssh.authenticated', 'host:' + ws.target, sshWinAuthVal, C.ProofState.SUPPORTED, source));
    }
    if (!isDosEmu && (((C._is_exec_command(command) || isWhoamiId || isWinInteractivePaste || (!command && (/^\s*nt authority\\system\s*$/im.test(execTextSample) || /^Directory of [A-Za-z]:\\/im.test(execTextSample)))) && !isSsh || isSshWindowsExec)) && has('_parse_command_execution')) guarded._parse_command_execution(text, ws, command, source, facts);

    // A confirmed file transfer / tool staged onto the host (certutil URLCache, wget "saved", scp "100%",
    // bitsadmin, copy): mint a terminal host.tool_staged receipt. The reader self-gates on a tool-specific
    // success token, so an in-progress or failed transfer, or an unrelated command, mints nothing.
    if ((/\b(?:certutil|wget|scp|bitsadmin|xcopy|smbclient|upload)\b/i.test(lc) || /\bcopy\b/i.test(lc) || /putting file\s+\S+\s+as\s+\\|CertUtil:\s*-\w[\w-]*\s*command completed successfully|\bsaved\s+\[\d|\b\d+\s+file\(s\)\s+copied\b/i.test(execTextSample)) && has('_parse_transfer_success')) guarded._parse_transfer_success(text, ws, command, source, facts);

    if (lc.indexOf('penelope') >= 0 || (C._PENELOPE_GOT_RE && C._PENELOPE_GOT_RE.test(execTextSample)) || (C._PENELOPE_UPGRADE_RE && C._PENELOPE_UPGRADE_RE.test(execTextSample))) guarded._parse_penelope(text, ws, source, facts);
    if ((/\b(?:nc|ncat|netcat|penelope|socat|pwncat)\b/i.test(lc) || lc.indexOf('pty.spawn') >= 0 || (execTextSample.indexOf('pty.spawn') >= 0 && /\bpty\.spawn\s*\(/i.test(execTextSample)) || /\bListening on\s+|connect to \[[^\]]+\] from|Connection received on\s+\S+|Ncat:\s*Connection from/i.test(execTextSample) || /^\(UNKNOWN\)\s+\[\d{1,3}(?:\.\d{1,3}){3}\]\s+\d{1,5}\s+\([^)]*\)\s+open\s*$/im.test(execTextSample)) && has('_parse_listener_output')) guarded._parse_listener_output(text, ws, command, source, facts);
    if (has('_looks_like_meterpreter') && guarded._looks_like_meterpreter(execTextSample, command) && has('_parse_meterpreter')) guarded._parse_meterpreter(text, ws, command, source, facts);
    var whoamiEscSample = (command || '') + '\n' + execTextSample;
    if (has('_parse_posix_whoami_escalation') && (/\b(?:whoami|doas|sudo|su|pkexec)\b/i.test(whoamiEscSample) || /(?:\/(?:usr\/)?s?bin\/|(?:^|\s|['"(])\.?\/)(?:ba|da|z|k|a)?sh\b[^\r\n]*?-[A-Za-z']*p\b|\b(?:pcntl_exec|posix_sete?uid|os\.sete?uid|setresuid|setreuid|setuid|execve)\s*\(/i.test(whoamiEscSample))) guarded._parse_posix_whoami_escalation(text, ws, command, source, facts);
    if (has('_parse_windows_admin_staging') && /\b(?:net(?:\.exe)?\s+localgroup|reg(?:\.exe)?\s+save|robocopy)\b/i.test((command || '') + '\n' + text)) guarded._parse_windows_admin_staging(text, ws, command, source, facts);

    if (C._PRIVESC_ACTION_IDS && C._PRIVESC_ACTION_IDS.has(actionId)) {
      guarded._parse_privesc_output(actionId, text, ws, command, source, facts);
    } else if (has('_parse_privesc_output')) {
      var isHttpRespBody = /^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(text);
      var looksLinEnumPaste = !isHttpRespBody && has('_looks_like_linux_enum') && guarded._looks_like_linux_enum(text);
      var isRemoteScanner = hasFtpOwnerListing || isHttpRespBody
        || /\b(?:snmpwalk|snmpbulkwalk|snmp-check|onesixtyone|nmap|masscan|rustscan|httpie|whatweb|nikto|ffuf|gobuster|feroxbuster|dirb|dirsearch|wfuzz|httpx|nuclei|wpscan)\b/i.test(lc)
        || (!looksLinEnumPaste && /\b(?:curl|wget)\b/i.test(lc));
      if (!isRemoteScanner && has('_looks_like_linux_enum') && (looksLinEnumPaste || /\bfind\b[^\r\n]*-perm\b|\bgetcap\b|\bsystemctl\s+cat\b|\bps\s+(?:aux|-ef)\b|\bpspy(?:32|64)?s?\b|\bcrontab\b|\/etc\/cron|\/var\/log\/syslog\b|\/etc\/(?:passwd|shadow)\b|\/var\/run\/docker\.sock\b|\/proc\/1\/cgroup\b|\/\.dockerenv\b/i.test(lc) || (/^\s*groups(?:\s+[A-Za-z0-9_.-]+)?\s*$/i.test(lc) && /\b(?:docker|lxd|lxc|adm|disk|shadow|video)\b/i.test(text)))) {
        guarded._parse_privesc_output('linux-enum', text, ws, command, source, facts);
      }
      if (!isRemoteScanner && has('_looks_like_windows_enum') && (guarded._looks_like_windows_enum(text) || /\bsc(?:\.exe)?\s+qc\b|\bwmic\s+service\b|\bwin32_service\b|\bautorunsc?\b/i.test(lc))) {
        guarded._parse_privesc_output('windows-enum', text, ws, command, source, facts);
      }
    }
    // A bare `whoami /priv` / `whoami /all` or `sudo -l` / `sudo --list` paste carries no privesc
    // action-id, so the gate above skips it. Route on the command OR a conservative content signature
    // (a dangerous Enabled Se*Privilege line; a sudo rights listing) so an attached paste with no
    // command line still mints its lead, while unrelated output (an ls, a config dump) never does.
    if ((lc.indexOf('whoami /priv') >= 0 || lc.indexOf('whoami /all') >= 0 || lc.indexOf('whoami /groups') >= 0 || (has('_looks_like_whoami_priv') && guarded._looks_like_whoami_priv(text))) && has('_parse_whoami_priv')) guarded._parse_whoami_priv(text, ws, command, source, facts);
    if ((lc.indexOf('sudo -l') >= 0 || lc.indexOf('sudo --list') >= 0 || /\bdoas\b/.test(lc) || (has('_looks_like_sudo_l') && guarded._looks_like_sudo_l(text))) && has('_parse_sudo_l')) guarded._parse_sudo_l(text, ws, command, source, facts);
    // net user / net localgroup / net group account enumeration, and winPEAS/PrivescCheck privesc dumps -
    // both arrive as operator-ingest with no action-id, so route on the command OR a conservative content
    // signature. The parsers are content-gated (a domain-group membership -> ad.user_list, a local-admin
    // members list -> config.review; a dangerous Enabled privilege -> privesc.windows_privilege), so an
    // unrelated paste mints nothing.
    if ((lc.indexOf('net user') >= 0 || lc.indexOf('net localgroup') >= 0 || lc.indexOf('net group') >= 0 || (has('_looks_like_net_output') && guarded._looks_like_net_output(text))) && has('_parse_net_accounts')) guarded._parse_net_accounts(text, ws, command, source, facts);
    if ((lc.indexOf('winpeas') >= 0 || lc.indexOf('privesccheck') >= 0 || (has('_looks_like_winpeas') && guarded._looks_like_winpeas(text))) && has('_parse_winpeas')) guarded._parse_winpeas(text, ws, command, source, facts);
    // schtasks /query /v -> scheduled-task privesc lead (SYSTEM/admin run-as pointing at a path);
    // reg query -> Winlogon autologon + stored creds (VNC/PuTTY/SNMP); icacls/accesschk -> a writable
    // service/path ACE for a low-priv principal. All arrive as operator-ingest with no action-id, so
    // route on the command OR a conservative content signature; each parser is content-gated (only a
    // privileged task with a path, a credential-ish reg value, or a writable program-path ACE mints),
    // so an unrelated paste - an ls, a harmless reg dump, a read-only ACE - mints nothing.
    if ((lc.indexOf('schtasks') >= 0 || (has('_looks_like_schtasks') && guarded._looks_like_schtasks(text))) && has('_parse_schtasks')) guarded._parse_schtasks(text, ws, command, source, facts);
    if ((lc.indexOf('reg query') >= 0 || (has('_looks_like_reg_query') && guarded._looks_like_reg_query(text))) && has('_parse_reg_query')) guarded._parse_reg_query(text, ws, command, source, facts);
    if ((lc.indexOf('klist') >= 0 || (has('_looks_like_klist') && guarded._looks_like_klist(text))) && has('_parse_klist')) guarded._parse_klist(text, ws, command, source, facts);
    if ((lc.indexOf('icacls') >= 0 || lc.indexOf('accesschk') >= 0 || /\bget-acl\b/i.test(lc) || (has('_looks_like_icacls_accesschk') && guarded._looks_like_icacls_accesschk(text))) && has('_parse_icacls_accesschk')) guarded._parse_icacls_accesschk(text, ws, command, source, facts);

    // endpoint defensive posture (read-only): languagemode / Get-MpComputerStatus / Get-MpPreference /
    // Get-AppLockerPolicy -> defense.control, so the coach can prefer remote-first and warn before on-host runs.
    if ((lc.indexOf('get-mpcomputerstatus') >= 0 || lc.indexOf('get-applockerpolicy') >= 0 || lc.indexOf('languagemode') >= 0 || lc.indexOf('get-mppreference') >= 0 || (has('_looks_like_defense_enum') && guarded._looks_like_defense_enum(text))) && has('_parse_defense_enum')) guarded._parse_defense_enum(text, ws, command, source, facts);
    if (has('_parse_script_sinks')) guarded._parse_script_sinks(text, command, ws, source, facts);
    if (has('_parse_shadow_file')) guarded._parse_shadow_file(text, command, ws, source, facts);
    var isWebOrRemotePaste = /\b(?:curl|wget|httpie|whatweb|nikto|ffuf|gobuster|feroxbuster|dirb|dirsearch|wfuzz|httpx|nuclei|wpscan|sqlmap|nmap|masscan|rustscan|searchsploit)\b/i.test(lc)
      || /^\s*(?:<\s*)?HTTP\/[12](?:\.\d)?\s+\d{3}\b/im.test(bigProbeSample)
      || /<!doctype\s+html|<\/?(?:html|head|body|pre)\b|<\?(?:php|=)|<%@?\s/i.test(bigProbeSample);
    if (!isWebOrRemotePaste && has('_looks_like_binary_inspection') && guarded._looks_like_binary_inspection(text, command) && has('_parse_binary_inspection')) {
      guarded._parse_binary_inspection(text, ws, command, source, facts);
    }

    if (lc.indexOf('certipy') >= 0 || lc.indexOf('certify') >= 0 || lc.indexOf('pywhisker') >= 0 || /(?:CA Name|Template Name|msPKI-Certificate-Name-Flag|Certipy)[\s\S]{1,600}?(?:ESC\d+|ENROLLEE_SUPPLIES_SUBJECT|Vulnerabilities)/i.test(bigProbeSample)) {
      if (has('_parse_adcs')) guarded._parse_adcs(text, ws, command, source, facts);
    }
    if ((lc.indexOf('certipy auth') >= 0 || lc.indexOf('certipy shadow') >= 0 || lc.indexOf('shadow auto') >= 0 || actionId === 'cert-authenticate' || /Got hash for\s+['"]?[^\s'"]+['"]?\s*:\s*(?:[a-f0-9]{32}:)?[a-f0-9]{32}|Saved credential cache to/i.test(bigProbeSample)) && has('_parse_certipy_auth')) {
      guarded._parse_certipy_auth(text, ws, command, source, facts);
    }
    if (has('_is_ad_abuse_command') && (C._is_ad_abuse_command(command) || (C._AD_ABUSE_ACTION_IDS && C._AD_ABUSE_ACTION_IDS.has(actionId)) || /DACL modified successfully|OwnerSid modified successfully|Password changed successfully!|\[\+\]\s+\S+\s+added to\s+\S+|\[\*\]\s+Action:\s*Ask\s+TGT|TGT request successful!|Service ticket successfully requested|Saving ticket in\s+\S+\.ccache|DeviceKey\s*:|KeyCredential\s+added|\bnet\s+rpc\s+password\b/i.test(bigProbeSample) || (/\bnet(?:\.exe)?\s+user\b[^\r\n]+\/domain\b/i.test(bigProbeSample) && /The command completed successfully\./i.test(bigProbeSample)))) {
      if (has('_parse_ad_abuse_output')) guarded._parse_ad_abuse_output(actionId, text, ws, command, source, facts);
    }
    // Content-sniff fallback: a bloodyAD `get writable` dump is often ATTACHED as a file with no command
    // set, so the ad-abuse gate above never fires. Recognize it from the output itself (the ad-abuse path
    // already covered the command/action case; facts dedupe, so a double hit is harmless).
    else if (has('_parse_bloodyad_writable') && guarded._looks_like_bloodyad_writable(bigProbeSample)) guarded._parse_bloodyad_writable(text, ws, command, source, facts);
    if (has('_parse_ad_delegation_surface') && (isNxc || ['ldapsearch', 'bloodyad', 'get-adcomputer', 'get-adserviceaccount', 'getaduser', 'finddelegation', ' ldap '].some(function (k) { return lc.indexOf(k) >= 0; }) || /\b(?:Delegation\s+RightsTo|msDS-AllowedToDelegateTo|msDS-AllowedToActOnBehalfOfOtherIdentity|TRUSTED_FOR_DELEGATION|TRUSTED_TO_AUTH_FOR_DELEGATION)\b/i.test(bigProbeSample))) guarded._parse_ad_delegation_surface(text, ws, command, source, facts);

    if ((lc.indexOf('ffuf') >= 0 || /"commandline"\s*:\s*"[^"]*ffuf/i.test(bigProbeSample)) && has('_parse_ffuf_json')) guarded._parse_ffuf_json(text, ws, source, facts, command);
    if ((lc.indexOf('feroxbuster') >= 0 || /"type"\s*:\s*"response"[\s\S]{1,200}?"status"\s*:/i.test(bigProbeSample)) && has('_parse_feroxbuster_json')) guarded._parse_feroxbuster_json(text, ws, source, facts, command);
    if ((lc.indexOf('httpx') >= 0 || /"status_code"\s*:\s*\d{3}[\s\S]{1,300}?"(?:webserver|tech)"\s*:/i.test(bigProbeSample)) && has('_parse_httpx_json')) guarded._parse_httpx_json(text, ws, source, facts);
    if ((lc.indexOf('nuclei') >= 0 || /"template-id"\s*:\s*"[^"]+"[\s\S]{1,400}?"matched-at"\s*:/i.test(bigProbeSample)) && has('_parse_nuclei_json')) guarded._parse_nuclei_json(text, ws, source, facts);
    if (has('_is_web_vhost_command') && C._is_web_vhost_command(command)) { if (has('_parse_web_vhosts')) guarded._parse_web_vhosts(text, ws, source, facts); }
    // Content-discovery output pasted WITHOUT the command still dispatches on its own shape. The gobuster path
    // line is [Found: ][http://host]/path (Status: NNN) with zero or more trailing bracket groups (mirroring
    // the leading forms _WEB_GOBUSTER_RE parses): old gobuster v2.0.1 had none, gobuster 3.x adds [Size: N],
    // gobuster 3.8+ emits bare relative paths with (Status: NNN) [Size: N], and a redirect adds [--> url].
    // Anchoring to end-of-line keeps prose that merely mentions a path out, and _parse_web_content self-gates
    // (no path lines -> no fact), so this stays additive.
    else if (C._is_web_content_command(command) || /\[Status:\s*\d{3},\s*Size:\s*\d+/i.test(bigProbeSample) || /\bGobuster\s+v?\d/i.test(bigProbeSample) || ((bigProbeSample.indexOf('http://') >= 0 || bigProbeSample.indexOf('https://') >= 0) && /^\s*\d{3}\s+(?:(?:GET|POST|HEAD)\s+)?\d+l\s+\d+w\s+\d+c\s+https?:\/\//im.test(bigProbeSample)) || (/\(Status:\s*\d{3}\)/i.test(bigProbeSample) && (/^\s*(?:Found:\s*)?(?:https?:\/\/[^/\s]+)?\/\S+\s+\(Status:\s*\d{3}\)\s*(?:\[[^\]]*\]\s*)*$/im.test(bigProbeSample) || /^\s*(?:Found:\s*)?[A-Za-z0-9_.~%-][^\s()]*\s+\(Status:\s*\d{3}\)\s+\[Size:\s*\d+\](?:\s*\[[^\]]*\])*\s*$/im.test(bigProbeSample)))) guarded._parse_web_content(text, ws, source, facts, command);
    if ((lc.indexOf('arjun') >= 0 || /Parameters found(?:\s+for\s+\S+)?\s*:\s*[a-zA-Z0-9_,\s-]+|\[\+\]\s+Heuristic scanner found\s+\d+\s+parameters/i.test(bigProbeSample)) && has('_parse_arjun')) guarded._parse_arjun(text, ws, command, source, facts);
    if (lc.indexOf('sqlmap') >= 0 || /sqlmap identified the following injection point|---\nParameter:\s*\S+\s*\((?:GET|POST|URI|Cookie|Header)\)/i.test(bigProbeSample)) guarded._parse_sqlmap(text, ws, source, facts, command);
    if (lc.indexOf('git-dumper') >= 0 || lc.indexOf('/.git/') >= 0 || /\bgit\s+(?:show|log|diff)\b/i.test(lc) || /^diff --git\s+a\//m.test(bigProbeSample) || (/^commit\s+[0-9a-f]{7,40}\b/m.test(bigProbeSample) && /^@@\s+-\d+/m.test(bigProbeSample)) || C._GIT_HEAD_RE.test(bigProbeSample)) guarded._parse_git_source(text, ws, command, source, facts);
    if ((lc.indexOf('nikto') >= 0 || /^- Nikto v\d+\.\d+/im.test(bigProbeSample)) && has('_parse_nikto')) guarded._parse_nikto(text, ws, source, facts, command);
    var isSqlClientSession = !!(C._is_sql_client_output && C._is_sql_client_output(bigProbeSample, ws, command));
    var isOutboundHttpReqOnly = !!(C._is_outbound_http_request_only && C._is_outbound_http_request_only(bigProbeSample));
    var isNonHttpAccountOrOutbound = !!(C._is_unix_account_dump && C._is_unix_account_dump(bigProbeSample)) || isOutboundHttpReqOnly;
    if (isWebExploitCmd && !isPayloadBuilderCmd && !isOutboundHttpReqOnly) guarded._parse_web_exploit_output(actionId || 'operator-ingest', text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isFtpOnlyUriCmd && !isSqlClientSession && !isNonHttpAccountOrOutbound && (lc.indexOf('whatweb') >= 0 || lc.indexOf('curl') >= 0 || /HTTPServer\[|Country\[[^\]]+\]\[[^\]]+\]/i.test(bigProbeSample))) guarded._parse_http_metadata(text, ws, source, facts);
    // Product fingerprints (Jenkins, NVMS-1000) run content-first on any web-ish
    // paste (nmap http-* scripts, curl -I, whatweb, a pasted page/headers). The
    // parser self-gates on a definitive signature, so an unrelated paste mints
    // nothing; a hit lights the precise exploit move instead of a bare port gate.
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isFtpOnlyUriCmd && !isSqlClientSession && !isNonHttpAccountOrOutbound && has('_parse_web_fingerprint')) guarded._parse_web_fingerprint(text, ws, source, facts);
    // LAPS read (nxc -M laps / --laps, ldapsearch/Get-ADComputer ms-MCS-AdmPwd):
    // content-gated on a LAPS signature, and self-gated to require a real
    // Password:/attribute value so the "No result found" failure mints nothing.
    if (has('_parse_laps') && (/ms-?MCS-AdmPwd|msLAPS-Password|Getting LAPS Passwords|Computer:\S+\s+User:.*Password:/i.test(bigProbeSample) || lc.indexOf('--laps') >= 0)) guarded._parse_laps(text, ws, source, facts);
    if (has('_parse_laps_material') && lc.indexOf('--laps') >= 0) guarded._parse_laps_material(text, ws, command, source, facts);
    // NSClient++ nsclient.ini password (web-API privesc on 8443).
    if (has('_parse_nsclient_ini') && (lc.indexOf('nsclient') >= 0 || /nsclient|\[\/settings\//i.test(bigProbeSample))) guarded._parse_nsclient_ini(text, ws, command, source, facts);
    // KeePass database/dump in hand (.kdbx, $keepass$ hash, master-key dump).
    if (has('_parse_keepass_dump') && (/keepass|\.kdbx/i.test(lc) || /\$keepass\$|\.kdbx/i.test(bigProbeSample))) guarded._parse_keepass_dump(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isFtpOnlyUriCmd && !isSqlClientSession && (['curl', 'whatweb', 'wget', 'gobuster', 'ffuf', 'feroxbuster', 'nikto', 'dirb', 'dirsearch', 'katana', 'hakrawler'].some(function (w) { return lc.indexOf(w) >= 0; }) || /^<(?:!DOCTYPE|html|head|body|form|input|script)\b/im.test(bigProbeSample) || /\[Input[^\]]*Pass(?:word|wd|code)?[^\]]*\]|^URL:\s*https?:\/\/\S+/im.test(bigProbeSample))) guarded._parse_web_surface(text, ws, command, source, facts);
    if (['snmpwalk', 'snmpbulkwalk', 'snmp-check', 'onesixtyone'].some(function (t) { return lc.indexOf(t) >= 0; }) || /(?:SNMPv2-MIB|iso\.3\.6\.1\.2\.1|HOST-RESOURCES-MIB|NET-SNMP-EXTEND-MIB)::/i.test(bigProbeSample)) guarded._parse_snmp_output(text, ws, command, source, facts);
    var dbSessionCheckText = [bigProbeSample, ws && ws.context && ws.context.promptLine, ws && ws.context && ws.context.followPrompt].filter(Boolean).join('\n');
    var looksLikeDbQueryOrHashRow = /\b(?:pg_database|pg_tables|pg_shadow|pg_authid)\b|^\s*\\(?:l|list|dt)\+?(?:\s|;|$)|^\s*List of (?:databases|relations)\s*$/im.test(dbSessionCheckText)
      || (bigProbeSample.indexOf('|') >= 0
        && !/\baad3b435b51404eeaad3b435b51404ee:[0-9a-fA-F]{32}\b/i.test(bigProbeSample)
        && /(?:^[^\r\n]*\|[^\r\n]*(?:\$(?:2[abxy]|1|5|6|y|P|H|apr1)\$[^\s|]{8,}|\*[0-9A-Fa-f]{40}\b|\bmd5[0-9a-fA-F]{32}\b|\bSCRAM-SHA-256\$\d+:[^\s|]+)|(?:\$(?:2[abxy]|1|5|6|y|P|H|apr1)\$[^\s|]{8,}|\*[0-9A-Fa-f]{40}\b|\bmd5[0-9a-fA-F]{32}\b|\bSCRAM-SHA-256\$\d+:[^\s|]+)[^\r\n]*\|)/m.test(bigProbeSample));
    if (['mysql', 'mssqlclient', 'sqlcmd', 'psql', 'mongosh', 'mongo ', 'pymongo', 'mongoclient', 'redis-cli', 'sqlplus', 'odat', 'sqlite3', 'sqlite'].some(function (t) { return lc.indexOf(t) >= 0; }) || /\b(?:nxc|netexec|crackmapexec|cme)\s+mssql\b/.test(lc) || /^redis_version:|^SQL(?:\s*\([^)]*\))?>\s*|^mysql>\s*|^MariaDB\s*\[[^\]]*\]>\s*|^postgres[-=#]*>\s*|^postgres=#\s*/im.test(dbSessionCheckText) || looksLikeDbQueryOrHashRow) guarded._parse_database_output(text, ws, command, source, facts);
    if ((lc.indexOf('sqlite3') >= 0 || ((bigProbeSample.indexOf('|') >= 0 || /CREATE TABLE\s+/i.test(bigProbeSample)) && /CREATE TABLE\s+|^\s*\d+\|[^|\r\n]+\|[^|\r\n]+/im.test(bigProbeSample))) && has('_parse_sqlite_dump')) guarded._parse_sqlite_dump(text, ws, source, facts);
    if (has('_has_notable_programs') && !/\b(?:bloodyad|nxc|netexec|crackmapexec|cme|certipy|ldapsearch|impacket|getnpusers|getuserspns|secretsdump|nmap)\b/i.test(lc) && C._has_notable_programs(text)) guarded._parse_notable_programs(text, ws, source, facts);
    if ((' ' + lc + ' ').indexOf('ftp ') >= 0 || lc.indexOf('lftp') >= 0 || hasFtpUri || hasFtpOwnerListing || /^\s*(?:200 PORT command successful|2(?:27|29) Entering (?:Passive|Extended Passive) Mode|1(?:25|50)[ -](?:Data connection|Opening|Here comes the directory listing|Ok to send data|Transfer starting))/im.test(bigProbeSample)) guarded._parse_ftp_output(text, ws, command, source, facts);
    if (C._SSH_BANNER_RE.test(bigProbeSample)) guarded._parse_ssh_banner(text, ws, source, facts);
    if (((' ' + lc + ' ').indexOf(' 21') >= 0 || lc.indexOf('ftp') >= 0 || C._FTP_BANNER_RE.test(bigProbeSample)) && C._FTP_BANNER_RE.test(bigProbeSample)) guarded._parse_ftp_output(text, ws, command, source, facts);
    if (has('_parse_smtp_output') && (/\b(?:swaks|smtp-user-enum|sendmail)\b/i.test(lc) || /Starting smtp-user-enum\b|^\s*(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9._-]+):\s+[A-Za-z0-9_.+-]+\s+exists\s*$/im.test(bigProbeSample) || /^(?:<-|<--)?\s*220[\s-][^\r\n]*\bE?SMTP\b/im.test(bigProbeSample) || (/^\s*(?:->|-->)?\s*(?:EHLO|HELO|AUTH\s+LOGIN|MAIL\s+FROM:|RCPT\s+TO:|VRFY\s)/im.test(bigProbeSample) && /^\s*(?:<-|<--)?\s*2(?:20|35|50)[\s-]/im.test(bigProbeSample)))) guarded._parse_smtp_output(text, ws, command, source, facts);
    var isImapTranscript = /^\*\s+OK\b[^\r\n]*?\bIMAP4/im.test(bigProbeSample)
      || (/\b(?:LOGIN|AUTHENTICATE|SELECT|EXAMINE|FETCH)\b/i.test(bigProbeSample)
        && /^[A-Za-z0-9._-]+\s+(?:LOGIN|AUTHENTICATE|SELECT|EXAMINE|FETCH|UID\s+FETCH)\b/im.test(bigProbeSample)
        && (/^[A-Za-z0-9._-]+\s+(?:OK|NO|BAD)\b[^\r\n]*\bLOGIN\b/im.test(bigProbeSample) || /^\*\s+\d+\s+(?:EXISTS|FETCH)\b/im.test(bigProbeSample)));
    if (isImapTranscript) {
      if (has('_parse_imap_output')) guarded._parse_imap_output(text, ws, command, source, facts);
      else if (OBOL.parsers && typeof OBOL.parsers._parse_imap_output === 'function') {
        try { OBOL.parsers._parse_imap_output(text, ws, command, source, facts); }
        catch (imapErr) { diagnostics.push({ parser: '_parse_imap_output', message: (imapErr && imapErr.message) || String(imapErr) }); }
      }
    }
    var isPop3Transcript = /^\s*(?:(?:<[-~*]{1,3}|S:|<)\s*)?\+OK\b[^\r\n]*(?:POP3|Dovecot\s+ready)|^\s*\+OK\s+Logged\s+in\./im.test(bigProbeSample)
      || (((' ' + lc + ' ').indexOf(' 110') >= 0 || /\bpop3s?\b/i.test(lc)) && /^\s*\+OK\b/im.test(bigProbeSample));
    if (isPop3Transcript) {
      if (has('_parse_pop3_output')) guarded._parse_pop3_output(text, ws, command, source, facts);
      else if (OBOL.parsers && typeof OBOL.parsers._parse_pop3_output === 'function') {
        try { OBOL.parsers._parse_pop3_output(text, ws, command, source, facts); }
        catch (pop3Err) { diagnostics.push({ parser: '_parse_pop3_output', message: (pop3Err && pop3Err.message) || String(pop3Err) }); }
      } else if (has('_parse_mail_output')) guarded._parse_mail_output(text, ws, command, source, facts);
      else if (OBOL.parsers && typeof OBOL.parsers._parse_mail_output === 'function') {
        try { OBOL.parsers._parse_mail_output(text, ws, command, source, facts); }
        catch (mailErr) { diagnostics.push({ parser: '_parse_mail_output', message: (mailErr && mailErr.message) || String(mailErr) }); }
      }
    }
    var isIdentOutput = /\bident-user-enum\b/i.test(lc)
      || /^\s*\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\s+[A-Za-z_][A-Za-z0-9_.-]{0,31}\s*$/m.test(bigProbeSample);
    if (isIdentOutput) {
      if (has('_parse_ident_output')) guarded._parse_ident_output(text, ws, command, source, facts);
      else if (has('_parse_ident_user_enum')) guarded._parse_ident_user_enum(text, ws, command, source, facts);
      else if (OBOL.parsers && typeof OBOL.parsers._parse_ident_output === 'function') {
        try { OBOL.parsers._parse_ident_output(text, ws, command, source, facts); }
        catch (idErr) { diagnostics.push({ parser: '_parse_ident_output', message: (idErr && idErr.message) || String(idErr) }); }
      } else if (OBOL.parsers && typeof OBOL.parsers._parse_ident_user_enum === 'function') {
        try { OBOL.parsers._parse_ident_user_enum(text, ws, command, source, facts); }
        catch (idErr2) { diagnostics.push({ parser: '_parse_ident_user_enum', message: (idErr2 && idErr2.message) || String(idErr2) }); }
      }
    }
    if (!isPayloadBuilderCmd && has('_parse_archive_listing') && (/\b(?:unzip|7z[ar]?|tar|jar|unar)\b/i.test(lc) || /^\s*(?:Archive:\s+\S+|(?:inflating|extracting):\s+\S+)/im.test(bigProbeSample))) {
      guarded._parse_archive_listing(text, ws, command, source, facts);
    }
    if (!isPayloadBuilderCmd && has('_parse_gcore_output') && (/\b(?:gcore|gdb)\b/i.test(lc) || /^\s*Saved corefile\s+\S+/im.test(bigProbeSample))) {
      guarded._parse_gcore_output(text, ws, command, source, facts);
    }
    if (has('_parse_rsync_nfs') && (/\b(?:rsync|showmount)\b/.test(lc) || /^Export list for\s+\S+:|^NFS\s+\d{1,3}(?:\.\d{1,3}){3}\s+2049\b/im.test(bigProbeSample))) guarded._parse_rsync_nfs(text, ws, command, source, facts);

    if (((lc.indexOf('rubeus') >= 0 && (lc.indexOf('asktgt') >= 0 || lc.indexOf('tgtdeleg') >= 0)) || /ServiceName\s*:\s*krbtgt\/[\s\S]{1,400}?Base64EncodedTicket/i.test(bigProbeSample)) && has('_parse_rubeus_asktgt')) guarded._parse_rubeus_asktgt(text, ws, source, facts);
    if ((lc.indexOf('sharpsccm') >= 0 || lc.indexOf('sccmhunter') >= 0 || /Network Access Account|SMS_Site|MP_LocationManager|CCM_NetworkAccessAccount/i.test(bigProbeSample)) && has('_parse_sccm')) guarded._parse_sccm(text, ws, source, facts);

    if (lc.indexOf('dig') >= 0 && lc.indexOf('axfr') >= 0 && has('_parse_dns_zone')) guarded._parse_dns_zone(text, ws, source, facts, command);
    if ((lc.indexOf('ike-scan') >= 0 || /IKE PSK parameters/i.test(bigProbeSample) || (/:[0-9a-fA-F]{4,}:[0-9a-fA-F]{4,}:[0-9a-fA-F]{4,}/.test(bigProbeSample) && /^[0-9a-fA-F]+(?::[0-9a-fA-F]+){8}$/m.test(bigProbeSample))) && has('_parse_ike_psk')) guarded._parse_ike_psk(text, ws, source, facts);
    if ((lc.indexOf('ipmitool') >= 0 || lc.indexOf('ipmi') >= 0 || /\$rakp\$|RAKP-(?:HMAC-SHA1|Hash)/i.test(bigProbeSample) || (/:[0-9a-fA-F]{40}/.test(bigProbeSample) && /^[A-Za-z0-9_.-]+:[0-9a-fA-F]{40,}:[0-9a-fA-F]{40}$/m.test(bigProbeSample))) && has('_parse_ipmi_rakp')) guarded._parse_ipmi_rakp(text, ws, source, facts);
    if ((/\b(?:hashid|hash-identifier|nth|haiti|name-that-hash)\b/.test(lc) || actionId === 'crack-identify' || /\[Hashcat Mode:\s*\d+\]|Most Likely\s*:/i.test(bigProbeSample)) && has('_parse_hash_identify')) guarded._parse_hash_identify(text, ws, command, source, facts);

    // findings-check actions
    if (actionId === 'responder-poison' || lc.indexOf('responder') >= 0 || /\[(?:SMB|HTTP|LDAP|MSSQL|DCE-RPC|WinRM)\]\s+NTLMv[12](?:-SSP)?\s+Client\s*:/i.test(bigProbeSample)) { if (has('_parse_responder')) guarded._parse_responder(text, ws, source, facts); }

    if ((/\b(?:hydra|medusa|ncrack|crowbar|patator)\b/.test(lc) || /\[\d+\]\[[a-z0-9_-]+\]\s+host:\s*\S+\s+login:\s*\S+\s+password:/i.test(bigProbeSample)) && has('_parse_hydra')) guarded._parse_hydra(text, ws, command, source, facts);

    // Flag capture (content-gated inside): a `===FLAG:path::value` marker from the flag-hunt move, or a
    // direct `type/cat ...proof.txt` read, mints objective.<slot>_flag so the read flag reaches the report.
    if (has('_parse_flags')) guarded._parse_flags(text, ws, command, source, facts);

    // Section 33 content-gated OSWE parsers (only the ported ones run)
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_source_secret') && C._has_source_secret(text)) guarded._parse_source_secret(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && has('_has_windows_creds') && C._has_windows_creds(text, command)) guarded._parse_windows_creds(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_product_signature') && C._has_product_signature(text, ws, command)) guarded._parse_product_signature(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_sqli_oracle') && C._has_sqli_oracle(text)) guarded._parse_sqli_oracle(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_web_disclosure') && C._has_web_disclosure(text, command) && has('_parse_web_disclosure')) guarded._parse_web_disclosure(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_web_manifest') && C._has_web_manifest(text, command) && has('_parse_web_manifest')) guarded._parse_web_manifest(text, ws, command, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && !isOutboundHttpReqOnly && has('_has_web_vuln_sinks') && C._has_web_vuln_sinks(text, command) && has('_parse_web_vuln_sinks')) guarded._parse_web_vuln_sinks(text, ws, command, source, facts);

    // findings-lens checks (the "checks" lane + a couple of recon observations): route on the move's
    // action-id, each parser is content-gated so an unrelated paste mints nothing.
    if (!isPayloadBuilderCmd && !isPublicRefHttp && (actionId === 'check-web-headers' || (/\bcurl\b/.test(lc) && !isFtpOnlyUriCmd && /\s-(?:I|-head|[a-zA-Z]*i)\b/.test(' ' + command))) && has('_parse_http_headers')) guarded._parse_http_headers(text, ws, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && (actionId === 'check-http-methods' || /^\s*(allow|public):/im.test(bigProbeSample)) && has('_parse_http_methods')) guarded._parse_http_methods(text, ws, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && (actionId === 'check-cors' || /access-control-allow-origin:/i.test(bigProbeSample)) && has('_parse_http_cors')) guarded._parse_http_cors(text, ws, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && actionId === 'check-web-body' && has('_parse_http_body')) guarded._parse_http_body(text, ws, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && (actionId === 'check-tls-config' || lc.indexOf('sslscan') >= 0 || lc.indexOf('testssl') >= 0 || lc.indexOf('ssl-enum-ciphers') >= 0 || /TLSv1\.[01]\s+enabled|Heartbleed\s+vulnerable/i.test(bigProbeSample)) && has('_parse_tls_info')) guarded._parse_tls_info(text, ws, source, facts);
    if (!isPayloadBuilderCmd && !isPublicRefHttp && (actionId === 'check-exposed-files' || /(?:Index of \/\s*<\/title>|\[To Parent Directory\]|^User-agent:\s*\*[\s\S]{1,200}?Disallow:\s*\/)/im.test(bigProbeSample)) && has('_parse_http_exposed')) guarded._parse_http_exposed(text, ws, source, facts);
    if ((actionId === 'recon-dns' || lc.indexOf('axfr') >= 0) && has('_parse_dns_zone')) guarded._parse_dns_zone(text, ws, source, facts, command);
    if ((actionId === 'check-dns-email' || /v=spf1\s|v=DMARC1\s/i.test(bigProbeSample)) && has('_parse_dns_email')) guarded._parse_dns_email(text, ws, source, facts);
    if ((actionId === 'check-subdomain-takeover' || (/is\s+an\s+alias\s+for|\bIN\s+CNAME\b/i.test(bigProbeSample) && /github\.io|herokuapp\.com|s3\.amazonaws\.com|azurewebsites\.net|cloudfront\.net|pantheonsite\.io|zendesk\.com|fastly\.net|ghost\.io|myshopify\.com|surge\.sh|bitbucket\.io|unbouncepages\.com|wordpress\.com|tumblr\.com/i.test(bigProbeSample))) && has('_parse_dns_takeover')) guarded._parse_dns_takeover(text, ws, source, facts);
    if ((actionId === 'vhost-discovery' || (lc.indexOf('host:') >= 0 && lc.indexOf('fuzz') >= 0) || /\b(?:gobuster\s+(?:vhost|dns)|feroxbuster[^\n]*--extract-links)\b/i.test(lc) || /^Found:\s+[a-zA-Z0-9_.-]+\s+\(Status:\s*\d{3}\)/im.test(bigProbeSample)) && has('_parse_vhost')) guarded._parse_vhost(text, ws, source, facts);
    // late-game AD recording facts (the access is already landed; these record the specific primitive)
    if ((actionId === 'ticket-reuse' || actionId === 'lateral-exec') && has('_parse_lateral_movement')) guarded._parse_lateral_movement(text, ws, source, facts);
    if (actionId === 'coerce-auth' && has('_parse_coerced_auth')) guarded._parse_coerced_auth(text, ws, source, facts);
    if ((actionId === 'gpo-abuse' || /\b(?:sharpGPOAbuse|pyGPOAbuse)\b/i.test(command)) && has('_parse_gpo_control')) guarded._parse_gpo_control(text, ws, source, facts);
    if ((actionId === 'sid-history-abuse' || /sidhistory/i.test(command)) && has('_parse_sid_history')) guarded._parse_sid_history(text, ws, source, facts);

    // Known-exploit fingerprint recognizer: when pasted service/version output names a product+version
    // (or a CVE / nmap vuln verdict) that a promoted known-exploit module targets, mint a vuln.<name>
    // lead so the coach lights that exact module. Anchored and additive; unrelated output mints nothing.
    if (!isPayloadBuilderCmd && has('_parse_vulnmatch')) guarded._parse_vulnmatch(text, ws, source, facts, command);

    // Exploit-DB (searchsploit) Stage 1 table/JSON parser and Stage 2 mirrored script inspector.
    if (has('_looks_like_searchsploit') && guarded._looks_like_searchsploit(text, command) && has('_parse_searchsploit')) {
      guarded._parse_searchsploit(text, ws, command, source, facts);
    }
    if (has('_looks_like_edb_script') && guarded._looks_like_edb_script(text, command) && has('_parse_edb_script')) {
      guarded._parse_edb_script(text, ws, command, source, facts);
    }

    // Connectivity: a foothold's own interface/route dump -> the subnets it reaches (and multihomed);
    // a pivot tool's setup output -> the live tunnel. Powers the hub connectivity view.
    if (has('_parse_local_net') && (/\bip\s+(?:-\d+\s+)?a(?:ddr)?\b|\bifconfig\b|\bip\s+route\b|\bipconfig\b|\broute\s+print\b|\bnetstat\s+-r/.test(lc) || /\binet\s+\d|IPv4 Address|Network Destination|\bGenmask\b/i.test(text)))
      guarded._parse_local_net(text, ws, source, facts);
    if (has('_parse_tunnel') && (/\bchisel\b|\bligolo\b|\bsshuttle\b|\bdnscat|ssh\s+[^\n]*-[a-z]*d\b|\bagent(?:\.exe)?\s+-connect\b/.test(lc) || /\bchisel\b|ligolo|sshuttle|dnscat|Agent joined|\[Tunnel\] Interface ligolo|obol:fact:pivot_active|\b(?:client|server):\s+(?:Connecting to ws:\/\/|Connected\s*\(Latency|Fingerprint\s+[0-9a-f]{2}:)|\btun:\s+proxy#R:/i.test(text)))
      guarded._parse_tunnel(text, ws, source, facts, command);
    // Adjacent hosts (ARP/neighbour cache), listening services, and internal resolvers from the foothold
    // - the leads that tell the operator what to aim the pivot at. Command-keyed, with a shape fallback.
    if (has('_parse_local_neighbors') && (/\bip\s+neigh|\barp\s+-a\b/.test(lc) || /\blladdr\b|\bdynamic\b/i.test(text)))
      guarded._parse_local_neighbors(text, ws, source, facts);
    if (has('_parse_local_listeners') && (/\bnetstat\s+-[a-z]*[alno]|\bss\s+-[a-z]*l/.test(lc) || /\bLISTEN(?:ING)?\b/.test(text)))
      guarded._parse_local_listeners(text, ws, source, facts);
    if (has('_parse_local_dns') && (/\bresolv\.conf\b|\bresolvectl\b|ipconfig\s+\/all/.test(lc) || /^\s*nameserver\s+\d|DNS Servers[^\n:]*:/im.test(text)))
      guarded._parse_local_dns(text, ws, source, facts);
    // Internal-resolver interrogation: a dig/nslookup/host query or an AXFR zone transfer against the
    // foothold's resolver -> the domain and its DCs (unlocking the AD lane), plus a zone receipt.
    if (has('_parse_dns') && (/\b(?:dig|nslookup|host|dnsrecon|dnsenum)\b/.test(lc) || /\bIN\s+(?:SOA|SRV|NS)\b|_ldap\._tcp|service\s*=\s*\d+\s+\d+\s+\d+|has address/i.test(text)))
      guarded._parse_dns(text, ws, source, facts, command);

    // Output-shape fallback (Tier 2): recognize common output by its shape when the command-keyed
    // dispatch above did not key on it. Strictly additive and guarded, so it only fills gaps (a bare
    // port table, a raw HTTP response, a pasted AS-REP/TGS hash) and never alters a parsed result.
    if (!isPayloadBuilderCmd && has('_parse_shape')) guarded._parse_shape(text, ws, source, facts);

    // Stage 0 Exploit-DB versioned non-stock banner recognizer (yields whenever any vuln.* matched).
    if (!isPayloadBuilderCmd && !isPublicRefHttp && has('_parse_versioned_banner_for_edb')) guarded._parse_versioned_banner_for_edb(text, ws, command, source, facts);

    // Wittgensteinian Contextual Inference (Tier 3) & Causal Entailment Gate Synchronizer:
    // combines atomic primitives, 2D table/KV geometry, Operator Attention Frame, and global entities
    // when Tier 1 & Tier 2 did not match, and backfills entailed prerequisite gates on out-of-order jumps.
    if (has('_parse_inference')) guarded._parse_inference(text, ws, command, source, facts, actionId, opts);
    if (isPublicRefHttp) {
      var pubTargetScope = 'host:' + ws.target;
      for (var pri = facts.length - 1; pri >= 0; pri--) {
        var prf = facts[pri];
        if (prf && prf.scope === pubTargetScope && (prf.kind === 'http.reachable' || /^web\./.test(prf.kind || '') || /^credential\./.test(prf.kind || '') || /^hash\./.test(prf.kind || ''))) {
          facts.splice(pri, 1);
        }
      }
    }
    if (has('_apply_causal_entailment')) guarded._apply_causal_entailment(facts, ws, command, text, source, opts);
    if (isPublicRefHttp) {
      var pubTargetScope2 = 'host:' + ws.target;
      for (var prj = facts.length - 1; prj >= 0; prj--) {
        var prf2 = facts[prj];
        if (prf2 && prf2.scope === pubTargetScope2 && (prf2.kind === 'http.reachable' || /^web\./.test(prf2.kind || '') || /^credential\./.test(prf2.kind || '') || /^hash\./.test(prf2.kind || ''))) {
          facts.splice(prj, 1);
        }
      }
    }

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
      diagnostics.push({ parser: 'dispatcher', message: (e && e.message) || String(e) });
      return { facts: facts, unmatched: facts.length === 0, diagnostics: diagnostics, error: (e && e.message) || String(e) };
    }

    if (typeof opts.observedAt === 'number') facts.forEach(function (f) { f.created_at = opts.observedAt; });
    return { facts: facts, unmatched: facts.length === 0, diagnostics: diagnostics, error: diagnostics.map(function (d) { return d.parser + ': ' + d.message; }).join('; ') };
  }

  OBOL.parsers.parseActionOutput = parseActionOutput;
  OBOL.parsers.parse_action_output = parseActionOutput; // python-name alias

  var _PROMPT_PREFIX_RE = /^\s*(?:\([^)]+\)\s*)?(?:\[?(?:[a-zA-Z0-9_.-]+\\)?[a-zA-Z0-9_.$-]+@[a-zA-Z0-9_.-]+[:\s][^\r\n$#%>\]]*\]?[$#%>]|(?:PS\s+)?[A-Za-z]:\\[^\r\n>]*>|(?:sh|bash|zsh|dash)-[\d.]+[$#]|[$#>])\s+/;
  var _KNOWN_CMD_LINE_RE = /^\s*(?:sudo\s+|proxychains4?\s+)?(?:nmap|masscan|rustscan|nxc|netexec|crackmapexec|cme|impacket-[a-z0-9_-]+|[A-Za-z0-9_-]+\.py|ldapsearch|smbclient|smbmap|rpcclient|enum4linux(?:-ng)?|kerbrute|bloodhound(?:-python)?|sharphound|bloodyad|certipy(?:-ad)?|certify(?:\.exe)?|rubeus(?:\.exe)?|mimikatz(?:\.exe)?|pypykatz|evil-winrm|xfreerdp|ssh|sshpass|hashcat|john|hydra|medusa|ncrack|crowbar|ffuf|feroxbuster|gobuster|dirb|dirsearch|wfuzz|httpx|nuclei|nikto|whatweb|wpscan|arjun|sqlmap|git-dumper|git|curl|wget|snmpwalk|snmpbulkwalk|snmp-check|onesixtyone|mysql|mssqlclient|sqlcmd|psql|redis-cli|mongosh|sqlite3|sqlplus|odat|dig|nslookup|host|dnsrecon|chisel|ligolo[a-z_-]*|sshuttle|responder|ike-scan|ipmitool|nth|hashid|hash-identifier|haiti|searchsploit|exiftool|linpeas|winpeas|whoami|id|uname|find|getcap|ps|netstat|ss|ip|ifconfig|ipconfig|arp|route|systeminfo|schtasks|reg|cmdkey|icacls|accesschk|klist|nltest|powerview|get-net\w+|get-domain\w*|get-ad\w+|get-gppermission|get-acl|get-childitem|gci|invoke-\w+|cat|type|strings|ltrace|strace|ldd|readelf|objdump|ilspycmd|wmic|systemctl|2to3|gcc|javac|python[23]?|pip[23]?|sc(?=\s+qc\b)|head(?=\s+-|\s+\d{3,6}\.))\b/i;

  // Convenience for pasted terminal output without a specific action card.
  OBOL.parsers.analyzeTerminal = function (text, opts) {
    opts = opts || {};
    var cleanText = _stripAnsi(text || '');
    if (C && C._normalize_cr) cleanText = C._normalize_cr(cleanText);
    var lines = cleanText.split(/\r?\n/);
    var inferredCmd = _stripAnsi(opts.command || '');
    if (!inferredCmd && lines.length) {
      var l0 = lines[0].trim();
      if (/^[┌╭─]+/.test(l0) && lines.length > 1 && /^\s*[└╰─]+\s*[$#%>]/.test(lines[1])) {
        inferredCmd = lines[1].replace(/^\s*[└╰─]+\s*[$#%>]\s*/, '').trim();
      } else if (_PROMPT_PREFIX_RE.test(l0)) {
        inferredCmd = l0.replace(_PROMPT_PREFIX_RE, '').trim();
      } else if (_KNOWN_CMD_LINE_RE.test(l0)
          && !/^(?:Host|User-Agent|Server|Location|Set-Cookie|Allow|Public)\s*:/i.test(l0)
          && !/\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<target>|<ip>|<host>|-~>/.test(l0)) {
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
