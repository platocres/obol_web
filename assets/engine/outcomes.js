/*!
 * OBOL outcome contract. An observation and an operation's completion are different claims.
 * This module classifies supported output families without minting or retracting facts.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function unique(values) { return values.filter(function (v, i) { return values.indexOf(v) === i; }); }
  function supported(f) { return f && (!f.state || f.state === 'supported'); }
  function snapshot(context) {
    context = context || {};
    if (OBOL.context && OBOL.context.snapshot) return OBOL.context.snapshot(context);
    return { target: context.target || '', targetDomain: context.targetDomain || '', authRealm: context.authRealm || '',
      principal: context.principal || '', credentialId: context.credentialId || '', service: context.service || '',
      locus: context.locus || '', attemptKey: context.attemptKey || '' };
  }
  function factProof(f) {
    return supported(f) && !/^(?:blocker\.|credential\.(?:validation|authorization)$|ssh\.key_rejected$)/.test(f.kind || '');
  }
  function observedMessages(facts, auth) {
    var ranked = facts.slice().sort(function (a, b) {
      function rank(f) { return /^(?:access\.|foothold\.|objective\.)/.test(f.kind) ? 0 : /\.authenticated$|credential\.validated/.test(f.kind) ? 1 : /^credential\.|^hash\./.test(f.kind) ? 2 : /^(ad\.|loot\.)/.test(f.kind) ? 3 : 4; }
      return rank(a) - rank(b);
    });
    var seen = {}, messages = [];
    ranked.forEach(function (f) {
      if (seen[f.kind]) return; seen[f.kind] = true;
      var v = f.value || {}, user = v.principal || v.user || v.username || '', message = '';
      if (/\.authenticated$/.test(f.kind)) message = f.kind.split('.')[0].toUpperCase() + ' authentication observed' + (user ? ' for ' + user : '') + '.';
      else if (f.kind === 'credential.validated') { if (!facts.some(function (p) { return /\.authenticated$/.test(p.kind); })) message = 'Authentication observed in the recorded context.'; }
      else if (/^credential\.(available|plaintext)$/.test(f.kind)) { if (!auth) message = 'Credential material recovered' + (user ? ' for ' + user : '') + '; recovery alone does not establish authentication.'; }
      else if (/^hash\./.test(f.kind)) message = 'Offline hash material recovered' + (user ? ' for ' + user : '') + '.';
      else if (f.kind === 'access.admin') message = 'Administrative capability demonstrated by the recorded output.';
      else if (f.kind === 'access.system' || f.kind === 'access.root') message = (f.kind === 'access.root' ? 'Root' : 'SYSTEM') + ' execution demonstrated.';
      else if (f.kind === 'host.rdp_enabled') message = 'RDP enabled on target (port 3389 unlocked for xfreerdp).';
      else if (f.kind === 'host.winrm_enabled') message = 'WinRM access enabled on target (port 5985 unlocked for evil-winrm).';
      else if (/^foothold\.|^access\.shell$/.test(f.kind)) message = 'A shell or execution foothold was observed in the recorded context.';
      else if (f.kind === 'ad.user_list') message = 'Directory accounts enumerated' + (v.count ? ': ' + v.count : '') + '.';
      else if (f.kind === 'privesc.sudo_binary') message = 'Sudo binary permitted: ' + (v.bin || 'check GTFOBins') + '.';
      else if (f.kind === 'privesc.suid_candidate') message = 'Non-standard SUID binary found: ' + ((v.paths || []).join(', ') || v.bin || 'check GTFOBins') + '.';
      else if (f.kind === 'smb.readable_share') message = 'Readable SMB share confirmed' + (v.share ? ': ' + v.share : '') + '.';
      else {
        var label = OBOL.pack && OBOL.pack.friendly ? OBOL.pack.friendly(f.kind) : f.kind.replace(/[._]/g, ' ');
        message = 'Observed: ' + String(label || f.kind) + '.';
      }
      if (message && messages.indexOf(message) < 0) messages.push(message);
    });
    return messages.slice(0, 4);
  }
  function alreadyKnown(facts, previous) {
    var proof = facts.filter(factProof), prior = (previous && previous.facts) || previous || [];
    return proof.length > 0 && proof.every(function (f) {
      return prior.some(function (p) { return supported(p) && p.kind === f.kind && p.scope === f.scope
        && (OBOL.facts && OBOL.facts.valuesEqual ? OBOL.facts.valuesEqual(p.value, f.value) : JSON.stringify(p.value) === JSON.stringify(f.value)); });
    });
  }
  function observations(text) {
    var result = [];
    String(text || '').split(/\r?\n/).forEach(function (line) {
      var m = /^\s*(SMB|LDAP|WINRM|SSH|MSSQL|RDP|FTP|WMI)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\S+\s+\[([+-])\]\s+(.*)$/i.exec(line);
      if (!m) return;
      if (/^(?:Executed command|Dumping|Enumerated|Spidering|Brute forcing|Copied|Deleted|Created)/i.test(m[4])) return;
      var principal = /^([^\s:]+)(?::|\s)/.exec(m[4]);
      result.push({ target: m[2], service: m[1].toLowerCase(), principal: principal ? principal[1] : '',
        authentication: m[3] === '+' ? 'accepted' : /STATUS_LOGON_FAILURE|authentication failed|invalid (?:password|credentials)/i.test(m[4]) ? 'rejected' : 'unresolved',
        authorization: /STATUS_ACCESS_DENIED|access (?:is )?denied|insufficientAccessRights/i.test(m[4]) ? 'denied' : 'unresolved' });
    });
    return result;
  }
  var _PROMPT_ONLY_LINE_RE = /^\s*(?:[┌╭]──.*|[└╰]─\s*[#$%>].*|\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\]]*\](?:\s*\[[^\]]+\])?|(?:\([^)]+\)\s*)?\[?[\w.\-]+@[\w.\-]+(?::[^\s#$%\]]*|\s+[^\r\n#$%\]]*)\]?\s*[#$%](?:\s+.*)?|(?:\*?Evil-WinRM\*?\s+)?PS\s+[A-Za-z]:[^>]*>(?:\s+.*)?|[A-Za-z]:\\[^>]*>(?:\s+.*)?)$/;
  function completion(text, command) {
    var cmd = String(command || '').toLowerCase(), body = String(text || '');
    if (/^\s*\[OBOL:\s*completed with no output\s*\/\s*nothing found\]\s*$/i.test(body)) {
      return { complete: true, negative: true };
    }
    if (cmd && body.trim()) {
      var nonEmptyLines = body.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
      if (nonEmptyLines.length >= 1 && nonEmptyLines.length <= 4 && nonEmptyLines.every(function (l) { return _PROMPT_ONLY_LINE_RE.test(l); })) {
        return { complete: true, negative: true };
      }
    }
    if (/\bnmap\b|\bmasscan\b/.test(cmd) || /<nmaprun\b|Nmap scan report for/.test(body)) {
      var nmapDone = /\bNmap done:\s*\d+ IP address(?:es)?\s*\(\d+ hosts? up\)\s*scanned|<finished\b[^>]*\bexit=["']success["']/i.test(body);
      return { complete: nmapDone, negative: nmapDone && /\bNmap done:\s*\d+ IP address(?:es)?\s*\(0 hosts? up\)|All \d+ scanned ports[^\r\n]*(?:closed|filtered)/i.test(body) };
    }
    if (/\b(?:hashcat|john)\b/.test(cmd)) return { complete: /Status\.*:\s*(?:Exhausted|Cracked)|\d+ password hashes? cracked,\s*\d+ left|No password hashes left to crack|Session completed/i.test(body), negative: (/Status\.*:\s*Exhausted|\b0 password hashes? cracked,\s*\d+ left|No password hashes left to crack/i.test(body) && !/\b[1-9]\d* password hashes? cracked/i.test(body)) };
    if (/\bldapsearch\b/.test(cmd)) return { complete: /^result:\s*0\s+Success\s*$/im.test(body), negative: /^result:\s*0\s+Success\s*$/im.test(body) && /^#?\s*numEntries:\s*0\s*$/im.test(body) };
    if (/\b(?:impacket-[\w-]+|getnpusers|getuserspns|finddelegation|lookupsid|rpcdump)\b/.test(cmd)) {
      var impNone = /\b(?:No entries found|Total of records returned\s+0|No SPNs found|No delegation found)\b/i.test(body);
      return { complete: impNone || /Impacket v\d|\[\*\]\s*Received\s+\d+\s+endpoints\./i.test(body), negative: impNone };
    }
    if (/(?:^|[\s;|&])(?:dig|host|nslookup)\b/.test(cmd)) {
      var dnsFail = /;\s*Transfer failed\.|;\s*communications error|status:\s*(?:REFUSED|NXDOMAIN|SERVFAIL)\b|Host\s+\S+\s+not found/i.test(body) && !/\bIN\s+(?:A|AAAA|SRV|SOA|NS|TXT|MX|CNAME|PTR)\s+\S/i.test(body);
      var dnsDone = dnsFail || /\bQuery time:\s*\d+\s*msec|\bIN\s+(?:A|AAAA|SRV|SOA|NS|TXT|MX|CNAME|PTR)\s+\S|Microsoft\s+DNS/i.test(body);
      return { complete: dnsDone, negative: dnsFail };
    }
    if (/\bbloodyad\b/.test(cmd)) {
      var bNone = /\b(?:No writable objects|0 objects|No object found|Nothing found)\b/i.test(body);
      return { complete: bNone || /distinguishedName:/i.test(body), negative: bNone };
    }
    if (/\bcertipy(?:-ad)?\b/.test(cmd)) {
      var cNone = /\b(?:Found no vulnerable|No vulnerable|0 vulnerable)\b/i.test(body) || (/Saved text output|Certificate Authorities/i.test(body) && !/\[!\]\s*Vulnerabilities/i.test(body));
      return { complete: cNone || /Saved text output|Certificate Authorities/i.test(body), negative: cNone };
    }
    if (/\b(?:nxc|netexec|crackmapexec|cme|smbmap|rpcclient|ffuf|gobuster|feroxbuster|dirsearch)\b/.test(cmd)) {
      var none = /(?:^|\n)[^\n]*(?:No (?:readable shares|shares|users|entries|results|matches) (?:were )?found|Total of records returned\s+0|(?:Found|Returned)\s+0\s+(?:results|entries|matches)|(?:enumeration|inventory|scan) completed[^\n]*\b0\s+(?:results|entries|matches))/i.test(body);
      if (!none && /\b(?:nxc|netexec|crackmapexec|cme)\b/.test(cmd) && /(?:\s-m\s+\S+|\s--(?:pass-pol|users|groups|local-groups|loggedon-users|sessions|computers|disks|rid-brute|shares)\b)/.test(cmd)) {
        var nxcLines = body.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) { return l && !_PROMPT_ONLY_LINE_RE.test(l) && !/^\s*[$#]\s+\S/.test(l); });
        var plusLines = nxcLines.filter(function (l) { return /\[\+\]/.test(l); });
        var minusLines = nxcLines.filter(function (l) { return /\[-\]/.test(l); });
        var allProto = nxcLines.length > 0 && nxcLines.every(function (l) { return /^(?:SMB|LDAP|WINRM|MSSQL|WMI|SSH|FTP|RDP)\s+\S+\s+\d+\s+/i.test(l); });
        if (allProto && plusLines.length === 1 && minusLines.length === 0 && nxcLines.length <= 2) none = true;
      }
      return { complete: none || /(?:inventory|enumeration) completed|Finished:|:: Progress:\s*\[\s*(\d+)\s*\/\s*\1\s*\]/i.test(body), negative: none };
    }
    if (/\b(?:hydra|medusa|ncrack|crowbar)\b/.test(cmd) || /\b0 valid passwords? found\b/i.test(body)) {
      var bruteNone = /\b0 valid passwords? found\b/i.test(body);
      return { complete: bruteNone || /\b\d+ of \d+ target(?:s)? successfully completed\b/i.test(body), negative: bruteNone };
    }
    if (/\b(?:ntpdate|ntpsec-ntpdate|rdate)\b/.test(cmd)) return { complete: /(?:step|adjust) time|offset\s+[-+]?\d|time server/i.test(body), negative: false };
    return { complete: false, negative: false };
  }
  function classify(opts) {
    opts = opts || {};
    var text = String(opts.text || '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, ''), command = String(opts.command || '');
    var facts = opts.facts || [], proof = facts.filter(factProof), diagnostics = opts.diagnostics || [];
    var kinds = unique(proof.map(function (f) { return f.kind; }));
    var auth = proof.some(function (f) { return /^(?:(?:smb|ldap|winrm|rdp|ssh|mssql|ftp|wmi)\.authenticated|credential\.validated|ad\.anonymous_bind|smb\.(?:null_session|guest_session))$/.test(f.kind); });
    var textForDenial = text.replace(/^.*Set-WSManQuickConfig\s*:\s*Access is denied.*$/gim, '');
    var denial = /STATUS_ACCESS_DENIED|NT_STATUS_ACCESS_DENIED|\baccess (?:is )?denied\b|insufficientAccessRights|insufficient access rights|successful bind must be completed|anonymous bind disallowed/i.test(textForDenial)
      || facts.some(function (f) { return f && (f.kind === 'credential.authorization' || f.kind === 'blocker.ldap_anonymous_disabled'); });
    var guestDisabled = /\\guest:\S*\s+STATUS_ACCOUNT_DISABLED/i.test(text) || (/\s-u\s+['"]?guest['"]?\b/i.test(command) && /STATUS_ACCOUNT_DISABLED/i.test(text));
    var rejected = guestDisabled || /STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|\bauthentication (?:failed|failure)\b|\binvalid (?:password|credentials)\b|\bLogin incorrect\b|\bLogin failed for user\b|WinRMAuthorizationError|NOAUTH Authentication required|Permission denied \((?:publickey|password)|ERRCONNECT_(?:AUTHENTICATION_FAILED|LOGON_FAILURE)/i.test(text)
      || facts.some(function (f) { return f && f.kind === 'credential.validation' && (f.state === 'refuted' || (f.value || {}).status === 'rejected'); });
    var environment = (!guestDisabled && /(?:^|\n)(?:[^\n]{0,150})?(?:command not found|is not recognized as an internal or external command|No such file or directory|\busage:|unrecognized (?:option|argument)|invalid option|missing (?:required )?(?:option|argument)|ModuleNotFoundError:|ImportError:|Traceback \(most recent call last\):|Connection (?:refused|reset)|could not connect|Name or service not known|Temporary failure in name resolution|Network is unreachable|\b(?:connection|request|operation|scan|socket|read)\s+timed?\s*out\b|(?<!nmblookup[^\n]{0,40})\btimed\s+out\b|KRB_AP_ERR_SKEW|clock skew too great|STATUS_PASSWORD_(?:MUST_CHANGE|EXPIRED)|STATUS_ACCOUNT_(?:LOCKED_OUT|DISABLED|RESTRICTION|EXPIRED)|BIO_do_handshake failed|freerdp_tls_handshake|ERRCONNECT_TLS_CONNECT_FAILED|Set-WSManQuickConfig\s*:\s*Access is denied|WsManError,Microsoft\.WSMan\.Management)/i.test(text))
      || facts.some(function (f) { return /^blocker\.(?:clock_skew|name_resolution|no_tty|crlf|hash_format|hashcat_env|web_wildcard|tls_scheme|kerberos_spn|xp_cmdshell_disabled|password_change|ntlm_disabled|nxc_c_share_denied|nxc_spider_usage|account_restricted|winrm_closed)$/.test(f.kind); });
    var truncated = /\[truncated(?:[,\]]| output)|\[output truncated\]|output (?:was )?truncated|unexpected (?:end of (?:file|input)|EOF)|incomplete (?:output|capture)/i.test(text);
    var parsedError = !!opts.parseError || diagnostics.length > 0;
    var done = completion(text, command), obs = observations(text);
    var mixedAuth = obs.some(function (o) { return o.authentication === 'accepted'; }) && obs.some(function (o) { return o.authentication === 'rejected'; });
    var operation = /\b(?:nxc|netexec|crackmapexec|cme)\b/i.test(command) && /(?:\s--(?:users|groups|local-groups|shares|rid-brute|pass-pol|loggedon-users|sessions|disks|computers|ntds|sam|lsa|dpapi|mkfile|put-file|get-file|spider|gmsa|laps|kerberoasting|asreproast|bloodhound)\b|\s-(?:M|[xX])\s)/i.test(command);
    var resultProof = proof.some(function (f) { return !(operation && /^smb\.(?:null_session|guest_session)$/.test(f.kind)) && !/^(?:scan\.nmap\.|host\.|port:|ports\.|service\.|(?:smb|ldap|kerberos|winrm|rdp|ssh|mssql|ftp|wmi)\.(?:reachable|authenticated)$|smb\.(?:signing|smbv1)$|ad\.(?:domain_known|base_dn|dc_candidate|anonymous_bind)$|credential\.(?:available|validated|plaintext|hash|candidate|ntlm_hash)$)/.test(f.kind); });
    var bloodyWritableProof = proof.some(function (f) { return f && (f.kind === 'ad.acl_lead' || f.kind === 'ad.gpo_writable'); });
    var context = snapshot(opts.context || {});
    var outcome = { version: 1, kind: 'unknown', status: 'unresolved', retryable: true, conclusive: false, retireCommand: false, retireMove: false,
      title: 'Output saved; outcome unresolved', summary: 'No supported outcome was recognized. The attempt remains available.',
      detail: 'Review the command, context, and complete output. Unknown output is not a negative finding or a completed move.',
      established: kinds, unresolved: ['Operation completion and unsupported claims remain unproven.'], next: 'review', context: context,
      observations: obs, signals: { authentication: auth, authorizationDenied: denial, rejected: rejected, environment: environment, truncated: truncated, completed: done.complete, negative: done.negative, parserError: parsedError } };
    outcome.observed = observedMessages(proof, auth);
    if (OBOL.facts && OBOL.facts.fingerprint) outcome.operationKey = OBOL.facts.fingerprint(JSON.stringify([context.attemptKey || '', command.trim().replace(/\s+/g, ' ')]));
    function set(kind, title, summary, detail, status, next, conclusive) {
      outcome.kind = kind; outcome.title = title; outcome.summary = summary; outcome.detail = detail;
      outcome.status = status; outcome.next = next; outcome.conclusive = !!conclusive;
      outcome.retireCommand = !!conclusive; outcome.retryable = !conclusive || kind === 'rejected' || kind === 'authorization-denied';
    }
    if (parsedError) set(proof.length ? 'partial' : 'parser-error', proof.length ? 'Some observations recognized; parsing incomplete' : 'Output saved; parser could not interpret it',
      proof.length ? 'Supported observations were retained, but part of the output could not be parsed.' : 'The parser reported an error. No successful or negative conclusion is assumed.',
      'The raw output and parser diagnostics are saved. Keep this attempt available for review or retry.', 'unresolved', 'review', false);
    else if ((truncated && proof.length) || mixedAuth || (environment && (resultProof || auth))) set('partial', 'Partial or mixed result',
      'Keep each supported observation. The complete operation or some sub-results remain unresolved.',
      'An incomplete capture or mixed result does not exhaust this move. Review the saved output before continuing.', 'unresolved', 'review', false);
    else if (denial && !resultProof) set('authorization-denied', auth ? 'Authentication accepted; operation denied' : 'Operation denied; authentication unproven',
      auth ? 'Authentication remains established for this identity and service. The requested operation was denied.' : 'The output establishes a denial for this operation. It does not independently establish successful authentication.',
      'The denial applies to this host, identity, service, and operation. It does not invalidate the credential everywhere or prove administrative access.', 'blocked', 'alternate-context', true);
    else if (rejected && !resultProof) set('rejected', 'Authentication rejected for this context',
      'This authentication attempt was rejected. No access was established by this attempt.',
      'Keep the result attached to the specific host, identity, credential, and service. Other contexts remain untested.', 'blocked', 'alternate-context', true);
    else if (environment) set('environment-error', 'Execution or environment problem',
      'The output reports a tool, setup, transport, or account prerequisite problem.',
      'Resolve the reported prerequisite and retry. This output does not establish a negative finding about the underlying investigation.', 'blocked', 'repair', false);
    else if (/\bbloodyad\b.*\bget\s+writable\b/i.test(command) && done.complete && !bloodyWritableProof) set('completed-negative', 'Operation completed; no abusable writable objects',
      'bloodyAD get writable completed without finding abusable writable objects for this principal.',
      'The negative result is limited to this identity and domain. Other enumeration or escalation paths remain available.', 'complete', 'continue', true);
    else if (done.negative && !resultProof) set('completed-negative', 'Operation completed; no matching results',
      'The supported output family explicitly reports a completed negative result for this operation.',
      'The negative result is limited to this query, endpoint, identity, and service. Other contexts remain available.', 'complete', 'continue', true);
    else if (proof.length) {
      var conclusive = done.complete || resultProof || (auth && !operation) || /\b(?:id|whoami)\b/.test(command) && kinds.some(function (k) { return /^(?:access\.|foothold\.|host\.user)/.test(k); });
      if (operation && !resultProof && !done.complete) set('partial', 'Authentication observed; operation result unresolved',
        'The service authentication was recognized, but the requested enumeration or operation has no supported completion result.',
        'Authentication is retained. Keep this operation available until its own output establishes a result.', 'unresolved', 'review', false);
      else set('success', 'Supported observations recognized',
        auth ? 'Authentication is established for the recorded host, identity, credential, and service only.' : 'The output supports the recorded observations.',
        auth ? 'Authentication alone does not establish an interactive shell, administrative rights, or access to other services.' : 'Only the listed observations are established. Unreported capabilities remain unproven.', conclusive ? 'complete' : 'observed', 'continue', conclusive);
      if (outcome.kind === 'success' && alreadyKnown(facts, opts.previousFacts)) {
        outcome.originalKind = 'success'; outcome.kind = 'duplicate'; outcome.title = 'Supported result confirmed again';
        outcome.summary = 'This output confirms observations already recorded. Zero newly added facts does not mean the operation failed.';
      }
    } else if (done.complete && !truncated) {
      if (/\bbloodyad\b.*\bget\s+writable\b/i.test(command) && !proof.length) {
        set('completed-negative', 'Operation completed; no abusable writable objects',
          'bloodyAD get writable completed without finding abusable writable objects for this principal.',
          'The negative result is limited to this identity and domain. Other enumeration or escalation paths remain available.', 'complete', 'continue', true);
      } else {
        set('completed', 'Tool completion recognized; objective unresolved',
          'The tool reported completion, but no supported positive or negative finding was extracted.',
          'Keep the evidence and review the operation. Tool completion alone does not prove the investigation was answered.', 'unresolved', 'review', false);
      }
    }
    if (truncated && !proof.length && !parsedError) {
      outcome.kind = 'unknown'; outcome.status = 'unresolved'; outcome.conclusive = false; outcome.retireCommand = false; outcome.retryable = true;
      outcome.title = 'Truncated output; outcome unresolved'; outcome.summary = 'No supported observation was recognized in this incomplete capture.';
      outcome.detail = 'The raw output is saved. Recover the complete output before drawing a positive or negative conclusion.'; outcome.next = 'review';
    }
    var wb = OBOL.workbench;
    var cleanUsr = String(context.principal || '').replace(/^.*[\\/]/, '').replace(/@.*$/, '');
    var ctxParams = { target: context.target || '', domain: context.targetDomain || context.authRealm || '', user: cleanUsr };
    outcome.baselines = (wb && wb.scanBenignBaselines) ? wb.scanBenignBaselines(text, command) : _builtinBaselines(text, command);
    outcome.errorFixes = (wb && wb.diagnoseErrors) ? wb.diagnoseErrors(text, command, ctxParams) : _builtinErrorFixes(text, ctxParams);
    if (outcome.baselines && outcome.baselines.length && outcome.kind === 'unknown' && !truncated && !parsedError && !environment && !proof.length) {
      set('completed-negative', outcome.baselines[0].title || 'Operation completed; benign baseline',
        outcome.baselines[0].detail || 'The output matches a standard benign OS baseline with no escalation vector.',
        outcome.baselines[0].next || 'Pivot to the next enumeration vector.', 'complete', 'continue', true);
    }
    return outcome;
  }
  var _STOCK_SUID = { passwd: 1, su: 1, sudo: 1, mount: 1, umount: 1, chsh: 1, chfn: 1, newgrp: 1, gpasswd: 1, fusermount: 1, fusermount3: 1, ping: 1, ping6: 1, pppd: 1, 'openssh-keysign': 1, 'ssh-keysign': 1, 'dbus-daemon-launch-helper': 1, eject: 1, 'snap-confine': 1, 'polkit-agent-helper-1': 1, unix_chkpwd: 1, chage: 1, expiry: 1, at: 1, crontab: 1 };
  function _builtinBaselines(text, command) {
    var t = String(text || ''), out = [];
    var suidLines = t.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) { return /^\/(?:usr\/|bin\/|sbin\/|lib\/|snap\/)\S+$/.test(l); });
    if (suidLines.length >= 2 || (/find\b.*-perm/i.test(command || '') && suidLines.length >= 1)) {
      var stock = [], custom = [];
      suidLines.forEach(function (p) { var b = p.split('/').pop(); if (_STOCK_SUID[b]) stock.push(b); else custom.push(p); });
      if (stock.length && !custom.length) {
        out.push({ id: 'benign-suid', title: 'SUID Scan Complete: Only Standard OS Binaries Found (' + stock.length + ' ignored)', verdict: 'Dead End (Benign Baseline)', detail: 'All ' + stock.length + ' SUID binaries (' + stock.slice(0, 6).join(', ') + (stock.length > 6 ? '...' : '') + ') are default OS binaries with no GTFOBins SUID escape.', next: 'Pivot to sudo -l, capabilities (getcap -r / 2>/dev/null), or cron jobs.' });
      }
    }
    if (/PRIVILEGES INFORMATION/i.test(t) || /\bSeChangeNotifyPrivilege\b/i.test(t)) {
      if (!/\b(SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeDebugPrivilege|SeTakeOwnershipPrivilege|SeLoadDriverPrivilege|SeManageVolumePrivilege)\b/i.test(t)) {
        out.push({ id: 'benign-whoami-priv', title: 'Windows Token Privileges: Standard Low-Privilege Account', verdict: 'Dead End (No Token Escalation)', detail: 'Only baseline user privileges are present. SeImpersonatePrivilege and SeBackupPrivilege are absent.', next: 'Check group memberships (whoami /groups), stored credentials (cmdkey /list), services, or PowerShell history.' });
      }
    }
    if (/Sorry,\s+user\s+\S+\s+may not run sudo|is not allowed to run sudo|is not in the sudoers file/i.test(t)) {
      out.push({ id: 'benign-sudo-denied', title: 'Sudo Check Complete: Account Has Zero Sudo Rules', verdict: 'Dead End (No Sudo Rights)', detail: 'The sudoers policy explicitly denies sudo execution for this user.', next: 'Move on to SUID/capabilities, cron jobs, internal localhost ports (ss -tlnp), or config files.' });
    }
    return out;
  }
  function _safeTok(s, fb) {
    var v = String(s || '').trim().replace(/['"\\$`;&|<>\r\n]/g, '');
    return v || fb;
  }
  function _builtinErrorFixes(text, vals) {
    var t = String(text || ''), out = [], tgt = _safeTok(vals && vals.target, '{{target}}'), dom = _safeTok(vals && vals.domain, '{{domain}}'), usr = _safeTok(vals && vals.user, '{{user}}');
    if (/Note:\s*Host seems down|0 hosts up/i.test(t)) out.push({ id: 'err-host-down', title: 'Nmap Blocked by Ping Filter', why: 'ICMP echo requests are dropped by the firewall.', fixCmd: 'nmap -Pn -p- --min-rate 3000 -T4 ' + tgt });
    if (/KRB_AP_ERR_SKEW|clock skew too great/i.test(t)) out.push({ id: 'err-clock-skew', title: 'Kerberos Clock Skew (>5m Drift)', why: 'Kali clock differs from the Domain Controller.', fixCmd: 'sudo timedatectl set-ntp off && sudo rdate -n ' + tgt });
    if (/KDC_ERR_S_PRINCIPAL_UNKNOWN|Server not found in Kerberos database/i.test(t)) out.push({ id: 'err-spn-ip', title: 'Kerberos Principal Unknown (Use FQDN, Not IP)', why: 'Kerberos requires the host FQDN rather than an IP address.', fixCmd: "echo '" + tgt + " " + dom + "' | sudo tee -a /etc/hosts" });
    if (/sudo:\s*(?:no tty present|a (?:terminal|password) is required)/i.test(t)) out.push({ id: 'err-no-tty', title: 'Interactive PTY Required for sudo', why: 'Dumb shell cannot prompt for a password.', fixCmd: 'python3 -c \'import pty;pty.spawn("/bin/bash")\'' });
    if (/Permission denied \(publickey/i.test(t)) out.push({ id: 'err-pubkey', title: 'SSH Refused Password Login (PublicKey Only)', why: 'sshd only accepts SSH private keys.', fixCmd: 'ssh -i id_rsa ' + usr + '@' + tgt });
    if (/BIO_do_handshake failed|ERRCONNECT_TLS_CONNECT_FAILED|freerdp_tls_handshake/i.test(t)) out.push({ id: 'xfreerdp-tls', title: 'FreeRDP TLS Handshake Rejected by OpenSSL 3 (Legacy TLS 1.0 / SHA-1)', why: 'Legacy Windows hosts (Server 2008 R2 / 2012 / Win7) negotiate TLS 1.0 with SHA-1 certificates, which OpenSSL 3 blocks before /cert:ignore runs.', fixCmd: "xfreerdp /v:" + tgt + (dom && dom !== '{{domain}}' ? (" /d:'" + dom + "'") : '') + " /u:'" + usr + "' /p:'{{password}}' /cert:ignore /tls:seclevel:0 +clipboard" });
    if (/Set-WSManQuickConfig\s*:\s*Access is denied|WsManError,Microsoft\.WSMan\.Management/i.test(t)) out.push({ id: 'winrm-wmi-quickconfig', title: 'Set-WSManQuickConfig Blocked Over WMI Network Logon', why: 'WMI spawns a Logon Type 3 network token that WSMan rejects during Set-WSManQuickConfig, aborting before TCP 5985 starts listening.', fixCmd: "nxc smb " + tgt + " -u '" + usr + "' -p '{{password}}' -x '(reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v AllowAutoConfig /t REG_DWORD /d 1 /f & reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\" /v IPv4Filter /t REG_SZ /d \"*\" /f & reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=WinRM dir=in action=allow protocol=TCP localport=5985 & sc config WinRM start= auto & net stop WinRM & net start WinRM & schtasks /create /tn WinRMInit /tr \"powershell.exe -NoProfile -Command Enable-PSRemoting -Force\" /sc ONSTART /ru SYSTEM /f & schtasks /run /tn WinRMInit & ping -n 5 127.0.0.1 >nul & schtasks /delete /tn WinRMInit /f)'" });
    if (/Errno::ECONNREFUSED[^\r\n]*port 5985|Connection refused[^\r\n]*:5985\b/i.test(t)) out.push({ id: 'winrm-conn-refused', title: 'WinRM Port 5985 Connection Refused (No HTTP Listener Bound)', why: 'TCP 5985 passed the firewall and returned RST because no WinRM HTTP listener is bound on the host yet.', fixCmd: "impacket-psexec '" + (dom && dom !== '{{domain}}' ? (dom + '/') : '') + usr + ":{{password}}@" + tgt + "'" });
    return out;
  }
  function aggregate(outcomes) {
    outcomes = (outcomes || []).filter(Boolean);
    if (!outcomes.length) return null;
    if (outcomes.length === 1) return outcomes[0];
    var kinds = unique(outcomes.map(function (o) { return o.kind; }));
    var unresolved = outcomes.some(function (o) { return !o.conclusive; });
    return { version: 1, kind: kinds.length === 1 ? kinds[0] : 'mixed', status: unresolved ? 'unresolved' : 'complete',
      retryable: outcomes.some(function (o) { return o.retryable; }), conclusive: !unresolved, retireCommand: false, retireMove: false,
      title: kinds.length === 1 ? outcomes[0].title : 'Session contains different outcomes',
      summary: outcomes.slice(0, 5).map(function (o, i) { return (i + 1) + '. ' + o.title; }).join(' ') + (outcomes.length > 5 ? ' ' + (outcomes.length - 5) + ' additional command outcomes are recorded individually.' : ''),
      detail: 'Each command keeps its own outcome, context, evidence, and retry status. A session-wide label does not replace those individual results.',
      established: unique([].concat.apply([], outcomes.map(function (o) { return o.established || []; }))),
      unresolved: unresolved ? ['One or more commands need review, repair, or additional output.'] : [], next: unresolved ? 'review' : 'continue',
      context: {}, outcomes: outcomes };
  }
  function describe(outcome) { return outcome ? outcome.title + '. ' + outcome.summary : 'Output saved. Review the recorded observations and context.'; }
  function render(outcome) {
    if (!outcome) return '';
    var c = outcome.context || {}, context = [c.target, c.principal, c.service, c.locus].filter(Boolean).join(' / ');
    var nextLabels = { review: 'Review the saved output and context; this attempt remains available.', repair: 'Resolve the reported prerequisite, then retry this attempt.', 'alternate-context': 'Review this specific denial and choose another relevant identity, service, or operation.', continue: 'Review the recorded evidence and the refreshed recommendations.' };
    var routing = outcome.routing || {}, forced = routing.mode === 'forced' ? '<div class="ev-hint outcome-routing">Explicit filing destination: ' + esc(routing.target)
      + (routing.sourceTargets && routing.sourceTargets.length ? '. Original output names: ' + routing.sourceTargets.map(esc).join(', ') : '') + '.</div>' : '';
    var diagHtml = '';
    if (outcome.errorFixes && outcome.errorFixes.length) {
      diagHtml += '<div class="outcome-triage-list">' + outcome.errorFixes.map(function (ef) {
        return '<div class="outcome-triage-card outcome-triage-err">'
          + '<div class="ot-head"><span class="ot-badge ot-badge-err">Error Diagnosis</span> <strong>' + esc(ef.title) + '</strong></div>'
          + '<p class="ot-why">' + esc(ef.why) + '</p>'
          + (ef.fixCmd ? '<div class="ot-cmd"><code>' + esc(ef.fixCmd) + '</code><button type="button" class="btn-copy" data-copy="' + esc(ef.fixCmd) + '">Copy Fix</button></div>' : '')
          + '</div>';
      }).join('') + '</div>';
    }
    if (outcome.baselines && outcome.baselines.length) {
      diagHtml += '<div class="outcome-triage-list">' + outcome.baselines.map(function (bl) {
        return '<div class="outcome-triage-card outcome-triage-base">'
          + '<div class="ot-head"><span class="ot-badge ot-badge-base">' + esc(bl.verdict || 'Benign Baseline') + '</span> <strong>' + esc(bl.title) + '</strong></div>'
          + '<p class="ot-why">' + esc(bl.detail) + '</p>'
          + '<p class="ot-next"><strong>Next Step:</strong> ' + esc(bl.next) + '</p>'
          + '</div>';
      }).join('') + '</div>';
    }
    return '<div class="outcome-receipt" data-outcome="' + esc(outcome.kind) + '" data-outcome-status="' + esc(outcome.status) + '" role="status">'
      + '<strong>' + esc(outcome.title) + '</strong>' + (context ? '<div class="ev-hint outcome-context">' + esc(context) + '</div>' : '')
      + forced
      + '<p>' + esc(outcome.summary) + '</p><p>' + esc(outcome.detail) + '</p>'
      + (outcome.observed && outcome.observed.length ? '<ul class="outcome-observed">' + outcome.observed.map(function (message) { return '<li>' + esc(message) + '</li>'; }).join('') + '</ul>' : '')
      + diagHtml
      + '<div class="ev-hint outcome-next">' + esc(nextLabels[outcome.next] || nextLabels.review) + '</div></div>';
  }
  OBOL.outcomes = { classify: classify, completion: completion, aggregate: aggregate, snapshot: snapshot, describe: describe, render: render, alreadyKnown: alreadyKnown };
})(typeof globalThis !== 'undefined' ? globalThis : this);
