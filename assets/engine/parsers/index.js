/*!
 * obol engine — parsers/index.js
 * The command-keyed dispatcher: OBOL.parsers.parseActionOutput(...) routes one action's raw
 * output to every parser its command/action-id matches, returning the narrow facts they prove.
 * Faithful JS port of obol-local/obol/parsers/__init__.py's parse_action_output.
 *
 * Output matching no parser yields NO facts (facts are never invented). Every emitted fact
 * carries `source` (lineage) and an explicit ProofState.
 *
 * SCOPE handling: there is no workspace in the browser. Callers pass an explicit target scope
 * (e.g. "host:10.10.10.10" or a bare "10.10.10.10") and an optional `domain`; these stand in for
 * the Python ws.target / ws.facts("ad.domain_known"). `domain` is the previously-proven AD domain
 * a caller commits, exactly as the Python fixture harness seeds ws.facts from the manifest.
 *
 * DOCUMENTED GAPS (parsers deliberately left unported — none are exercised by the fixture corpus;
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

  function makeWs(scope, domain) {
    var target = scope || '';
    if (target.indexOf('host:') === 0) target = target.slice(5);
    if (target.indexOf('domain:') === 0) target = '';
    if (!target) target = '10.10.10.10';
    return { target: target, domainSeed: domain || '', seedFacts: [] };
  }

  function parseActionOutput(opts) {
    opts = opts || {};
    var actionId = opts.actionId || '';
    var command = opts.command || '';
    var stdout = opts.stdout || '';
    var stderr = opts.stderr || '';
    var source = (opts.source !== undefined && opts.source !== null) ? opts.source : command;
    var ws = makeWs(opts.scope, opts.domain);
    var text = [stdout, stderr].filter(Boolean).join('\n');
    var facts = [];

    // The dispatch fans one paste out to many independent sub-parsers. A single fragile parser — or a
    // helper missing because a stale/partial asset load left the parser bundle inconsistent — must
    // never lose the whole paste (and the facts already collected). So the run is wrapped: on any
    // throw we log the culprit and return the facts gathered so far. Facts are never invented, only
    // possibly under-collected. nmap runs first, so a scan paste still yields ports.
    var lc = command.toLowerCase();
    var domainHint = '';
    var actObj = { id: actionId };
    try {

    domainHint = has('_domain_from_text') ? C._domain_from_text(text) : '';

    if (lc.indexOf('nmap ') >= 0 || lc.indexOf('nmap ') === 0) {
      if (has('_parse_nmap')) C._parse_nmap(text, ws, source, facts, actionId);
    }

    var isNxc = lc.indexOf('nxc ') >= 0 || lc.indexOf('nxc ') === 0;
    if (isNxc) {
      C._parse_nxc_common(text, ws, source, facts);
      if (C._is_ldap_command(command) && (actionId === 'ad-anon-ldap-enum' || lc.indexOf('--users') >= 0)) {
        C._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
        if (lc.indexOf('--users') >= 0 && has('_parse_ldap_descriptions')) C._parse_ldap_descriptions(text, ws, source, facts, { domain_hint: domainHint });
      }
      if (C._is_smb_command(command)) {
        C._parse_nxc_smb_session(text, ws, command, source, facts);
        C._parse_smb_shares(text, ws, source, facts);
        if (actionId === 'ad-user-enum' || lc.indexOf('--rid-brute') >= 0) C._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint });
      }
      if (lc.indexOf('--asreproast') >= 0) C._parse_asrep_hashes(text, ws, source, facts);
      C._parse_nxc_auth_validation(text, ws, source, facts);
      C._parse_auth_failures(text, ws, source, facts);
      if (lc.indexOf('--kerberoast') >= 0 || lc.indexOf('--kerberoasting') >= 0) C._parse_tgs_hashes(text, ws, source, facts);
      if (lc.indexOf('--bloodhound') >= 0) C._parse_bloodhound_collection(text, ws, source, facts);
    }

    if (lc.indexOf('ldapsearch') >= 0) {
      C._parse_ldapsearch(text, ws, source, facts);
      if (lc.indexOf('(objectclass=user)') >= 0) C._parse_user_list(text, ws, source, facts, { prove_anonymous_ldap: C._looks_anonymous_ldap_command(command, actObj), domain_hint: domainHint });
    }

    if (lc.indexOf('smbclient') >= 0 || lc.indexOf('smbmap') >= 0 || lc.indexOf('rpcclient') >= 0 || lc.indexOf('enum4linux') >= 0) {
      C._parse_smb_shares(text, ws, source, facts);
      C._parse_gpp_artifacts(text, ws, source, facts);
      if (actionId === 'ad-user-enum' || lc.indexOf('enumdomusers') >= 0) C._parse_rid_user_list(text, ws, source, facts, { domain_hint: domainHint });
    }

    if (lc.indexOf('spider_plus') >= 0 || (lc.indexOf('smbmap') >= 0 && (' ' + lc).indexOf(' -r') >= 0)) {
      C._parse_share_inventory(text, ws, command, source, facts);
    }

    if (lc.indexOf('gpp-decrypt') >= 0 && has('_parse_gpp_decrypted')) C._parse_gpp_decrypted(text, ws, source, facts);
    if ((lc.indexOf('wpscan') >= 0 || actionId === 'wordpress')) C._parse_wpscan(text, ws, source, facts);
    if ((actionId === 'trust-enum' || lc.indexOf('domain_trusts') >= 0 || lc.indexOf('domaintrust') >= 0 || lc.indexOf('lookupsid') >= 0) && has('_parse_domain_trusts')) C._parse_domain_trusts(text, ws, source, facts);
    if ((actionId === 'zerologon-check' || lc.indexOf('zerologon') >= 0) && has('_parse_zerologon_scan')) C._parse_zerologon_scan(text, ws, source, facts);

    if ((actionId === 'powerview-enum' || lc.indexOf('get-netuser') >= 0 || lc.indexOf('get-domainuser') >= 0) && has('_parse_powerview')) C._parse_powerview(text, ws, command, source, facts, { domain_hint: domainHint });
    if (['get-netgroup', 'get-domaingroup', 'get-netcomputer', 'get-domaincomputer', 'objectacl', 'get-acl'].some(function (k) { return lc.indexOf(k) >= 0; }) && has('_parse_powerview_objects')) C._parse_powerview_objects(text, ws, command, source, facts, { domain_hint: domainHint });

    if (lc.indexOf('kerbrute') >= 0) C._parse_kerbrute(text, ws, source, facts, { domain_hint: domainHint });

    if (lc.indexOf('getnpusers') >= 0 || lc.indexOf('asreproast') >= 0) C._parse_asrep_hashes(text, ws, source, facts);
    if (lc.indexOf('getuserspns') >= 0 || lc.indexOf('kerberoast') >= 0) C._parse_tgs_hashes(text, ws, source, facts);

    if (lc.indexOf('secretsdump') >= 0 || lc.indexOf('hashdump') >= 0 || (lc.indexOf('volatility') >= 0 && lc.indexOf('dump') >= 0) || (isNxc && ['--ntds', '--sam', '--lsa'].some(function (f) { return lc.indexOf(f) >= 0; }))) {
      C._parse_ntlm_dump(text, ws, command, source, facts);
    }

    if (lc.indexOf('bloodhound-python') >= 0 || lc.indexOf('sharphound') >= 0) C._parse_bloodhound_collection(text, ws, source, facts);
    if (lc.indexOf('bloodhound') >= 0) C._parse_bloodhound_analysis(text, ws, source, facts);

    if ((' ' + lc + ' ').indexOf(' winrm ') >= 0 || lc.indexOf('evil-winrm') >= 0) C._parse_evil_winrm(text, ws, command, source, facts);

    var isSsh = C._is_ssh_command(command);
    if (isSsh) C._parse_ssh_exec(text, ws, command, source, facts);

    if (isNxc && (' ' + lc + ' ').indexOf(' rdp ') >= 0) C._parse_nxc_rdp(text, ws, command, source, facts);

    if (C._is_cracking_command(command)) C._parse_cracked_credentials(text, ws, command, source, facts);

    if (C._is_exec_command(command) && !isSsh) C._parse_command_execution(text, ws, command, source, facts);

    if (lc.indexOf('penelope') >= 0) C._parse_penelope(text, ws, source, facts);

    if (C._PRIVESC_ACTION_IDS && C._PRIVESC_ACTION_IDS.has(actionId)) C._parse_privesc_output(actionId, text, ws, command, source, facts);
    if (has('_parse_script_sinks')) C._parse_script_sinks(text, command, ws, source, facts);
    if (has('_parse_shadow_file')) C._parse_shadow_file(text, command, ws, source, facts);

    if (lc.indexOf('certipy') >= 0 || lc.indexOf('pywhisker') >= 0) {
      if (has('_parse_adcs')) C._parse_adcs(text, ws, command, source, facts);
      if ((lc.indexOf('certipy auth') >= 0 || lc.indexOf('certipy shadow') >= 0 || lc.indexOf('shadow auto') >= 0 || actionId === 'cert-authenticate') && has('_parse_certipy_auth')) C._parse_certipy_auth(text, ws, command, source, facts);
    }
    if (C._is_ad_abuse_command(command) || C._AD_ABUSE_ACTION_IDS.has(actionId)) C._parse_ad_abuse_output(actionId, text, ws, command, source, facts);
    // Content-sniff fallback: a bloodyAD `get writable` dump is often ATTACHED as a file with no command
    // set, so the ad-abuse gate above never fires. Recognize it from the output itself (the ad-abuse path
    // already covered the command/action case; facts dedupe, so a double hit is harmless).
    else if (has('_parse_bloodyad_writable') && C._looks_like_bloodyad_writable(text)) C._parse_bloodyad_writable(text, ws, command, source, facts);
    if (isNxc || ['ldapsearch', 'bloodyad', 'get-adcomputer', 'get-adserviceaccount', 'getaduser', ' ldap '].some(function (k) { return lc.indexOf(k) >= 0; })) C._parse_ad_delegation_surface(text, ws, command, source, facts);

    if (lc.indexOf('ffuf') >= 0 && has('_parse_ffuf_json')) C._parse_ffuf_json(text, ws, source, facts);
    if (lc.indexOf('feroxbuster') >= 0 && has('_parse_feroxbuster_json')) C._parse_feroxbuster_json(text, ws, source, facts);
    if (lc.indexOf('httpx') >= 0 && has('_parse_httpx_json')) C._parse_httpx_json(text, ws, source, facts);
    if (lc.indexOf('nuclei') >= 0 && has('_parse_nuclei_json')) C._parse_nuclei_json(text, ws, source, facts);
    if (C._is_web_vhost_command(command)) { if (has('_parse_web_vhosts')) C._parse_web_vhosts(text, ws, source, facts); }
    else if (C._is_web_content_command(command)) C._parse_web_content(text, ws, source, facts);
    if (lc.indexOf('sqlmap') >= 0) C._parse_sqlmap(text, ws, source, facts);
    if (lc.indexOf('git-dumper') >= 0 || lc.indexOf('/.git/') >= 0 || C._GIT_HEAD_RE.test(text)) C._parse_git_source(text, ws, command, source, facts);
    if (lc.indexOf('nikto') >= 0 && has('_parse_nikto')) C._parse_nikto(text, ws, source, facts);
    if (C._WEB_EXPLOIT_ACTION_IDS.has(actionId)) C._parse_web_exploit_output(actionId, text, ws, command, source, facts);
    if (lc.indexOf('whatweb') >= 0 || lc.indexOf('curl') >= 0) C._parse_http_metadata(text, ws, source, facts);
    if (['curl', 'whatweb', 'wget', 'gobuster', 'ffuf', 'feroxbuster', 'nikto', 'dirb', 'katana', 'hakrawler'].some(function (w) { return lc.indexOf(w) >= 0; })) C._parse_web_surface(text, ws, command, source, facts);
    if (['snmpwalk', 'snmp-check', 'onesixtyone'].some(function (t) { return lc.indexOf(t) >= 0; })) C._parse_snmp_output(text, ws, command, source, facts);
    if (['mysql', 'mssqlclient', 'psql', 'mongosh', 'mongo ', 'pymongo', 'mongoclient', 'redis-cli'].some(function (t) { return lc.indexOf(t) >= 0; })) C._parse_database_output(text, ws, command, source, facts);
    if ((' ' + lc + ' ').indexOf('ftp ') >= 0 || lc.indexOf('lftp') >= 0) C._parse_ftp_output(text, ws, command, source, facts);
    if (C._SSH_BANNER_RE.test(text)) C._parse_ssh_banner(text, ws, source, facts);
    if (((' ' + lc + ' ').indexOf(' 21') >= 0 || lc.indexOf('ftp') >= 0) && C._FTP_BANNER_RE.test(text)) C._parse_ftp_output(text, ws, command, source, facts);

    if (lc.indexOf('rubeus') >= 0 && (lc.indexOf('asktgt') >= 0 || lc.indexOf('tgtdeleg') >= 0) && has('_parse_rubeus_asktgt')) C._parse_rubeus_asktgt(text, ws, source, facts);
    if ((lc.indexOf('sharpsccm') >= 0 || lc.indexOf('sccmhunter') >= 0) && has('_parse_sccm')) C._parse_sccm(text, ws, source, facts);

    if (lc.indexOf('dig') >= 0 && lc.indexOf('axfr') >= 0 && has('_parse_dns_zone')) C._parse_dns_zone(text, ws, source, facts);
    if (lc.indexOf('ike-scan') >= 0 && has('_parse_ike_psk')) C._parse_ike_psk(text, ws, source, facts);

    // findings-check actions
    if (actionId === 'responder-poison' || lc.indexOf('responder') >= 0) { if (has('_parse_responder')) C._parse_responder(text, ws, source, facts); }

    if (lc.indexOf('hydra') >= 0 && has('_parse_hydra')) C._parse_hydra(text, ws, command, source, facts);

    // §33 content-gated OSWE parsers (only the ported ones run)
    if (has('_has_product_signature') && C._has_product_signature(text)) C._parse_product_signature(text, ws, command, source, facts);
    if (has('_has_sqli_oracle') && C._has_sqli_oracle(text)) C._parse_sqli_oracle(text, ws, command, source, facts);

    } catch (e) {
      try { if (typeof console !== 'undefined' && console.warn) console.warn('obol parser: a sub-parser failed — keeping the ' + facts.length + ' fact(s) already recognized. Command: ' + command + ' — ' + (e && e.message)); } catch (_e) {}
      return { facts: facts, unmatched: facts.length === 0, error: (e && e.message) || String(e) };
    }

    return { facts: facts, unmatched: facts.length === 0 };
  }

  OBOL.parsers.parseActionOutput = parseActionOutput;
  OBOL.parsers.parse_action_output = parseActionOutput; // python-name alias

  // Convenience for pasted terminal output without a specific action card.
  OBOL.parsers.analyzeTerminal = function (text, opts) {
    opts = opts || {};
    return parseActionOutput({
      actionId: opts.actionId || 'operator-ingest',
      command: opts.command || (String(text || '').split(/\r?\n/)[0] || ''),
      stdout: text || '',
      stderr: '',
      source: opts.source !== undefined ? opts.source : (opts.command || ''),
      scope: opts.scope,
      domain: opts.domain,
    });
  };

})(typeof globalThis !== 'undefined' ? globalThis : this);
