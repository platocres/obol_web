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
      else if (/^foothold\.|^access\.shell$/.test(f.kind)) message = 'A shell or execution foothold was observed in the recorded context.';
      else if (f.kind === 'ad.user_list') message = 'Directory accounts enumerated' + (v.count ? ': ' + v.count : '') + '.';
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
      var principal = /^([^\s:]+)(?::|\s)/.exec(m[4]);
      result.push({ target: m[2], service: m[1].toLowerCase(), principal: principal ? principal[1] : '',
        authentication: m[3] === '+' ? 'accepted' : /STATUS_LOGON_FAILURE|authentication failed|invalid (?:password|credentials)/i.test(m[4]) ? 'rejected' : 'unresolved',
        authorization: /STATUS_ACCESS_DENIED|access (?:is )?denied|insufficientAccessRights/i.test(m[4]) ? 'denied' : 'unresolved' });
    });
    return result;
  }
  function completion(text, command) {
    var cmd = String(command || '').toLowerCase(), body = String(text || '');
    if (/\bnmap\b|\bmasscan\b/.test(cmd) || /<nmaprun\b|Nmap scan report for/.test(body)) {
      var nmapDone = /\bNmap done:\s*\d+ IP address(?:es)?\s*\(\d+ hosts? up\)\s*scanned|<finished\b[^>]*\bexit=["']success["']/i.test(body);
      return { complete: nmapDone, negative: nmapDone && /\bNmap done:\s*\d+ IP address(?:es)?\s*\(0 hosts? up\)|All \d+ scanned ports[^\r\n]*(?:closed|filtered)/i.test(body) };
    }
    if (/\b(?:hashcat|john)\b/.test(cmd)) return { complete: /Status\.*:\s*(?:Exhausted|Cracked)|\d+ password hashes? cracked,\s*\d+ left|Session completed/i.test(body), negative: /Status\.*:\s*Exhausted|\b0 password hashes? cracked,\s*[1-9]\d* left/i.test(body) };
    if (/\bldapsearch\b/.test(cmd)) return { complete: /^result:\s*0\s+Success\s*$/im.test(body), negative: /^result:\s*0\s+Success\s*$/im.test(body) && /^#?\s*numEntries:\s*0\s*$/im.test(body) };
    if (/\b(?:nxc|netexec|crackmapexec|cme|smbmap|rpcclient|ffuf|gobuster|feroxbuster|dirsearch)\b/.test(cmd)) {
      var none = /(?:^|\n)[^\n]*(?:No (?:readable shares|shares|users|entries|results|matches) (?:were )?found|(?:Found|Returned)\s+0\s+(?:results|entries|matches)|(?:enumeration|inventory|scan) completed[^\n]*\b0\s+(?:results|entries|matches))/i.test(body);
      return { complete: none || /(?:inventory|enumeration) completed|Finished:|:: Progress:\s*\[\s*(\d+)\s*\/\s*\1\s*\]/i.test(body), negative: none };
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
    var denial = /STATUS_ACCESS_DENIED|NT_STATUS_ACCESS_DENIED|\baccess (?:is )?denied\b|insufficientAccessRights|insufficient access rights/i.test(text)
      || facts.some(function (f) { return f && f.kind === 'credential.authorization'; });
    var rejected = /STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|\bauthentication (?:failed|failure)\b|\binvalid (?:password|credentials)\b|\bLogin incorrect\b|Permission denied \((?:publickey|password)/i.test(text)
      || facts.some(function (f) { return f && f.kind === 'credential.validation' && (f.state === 'refuted' || (f.value || {}).status === 'rejected'); });
    var environment = /(?:^|\n)(?:[^\n]{0,150})?(?:command not found|is not recognized as an internal or external command|No such file or directory|\busage:|unrecognized (?:option|argument)|invalid option|missing (?:required )?(?:option|argument)|ModuleNotFoundError:|ImportError:|Traceback \(most recent call last\):|Connection (?:refused|reset)|could not connect|Name or service not known|Temporary failure in name resolution|Network is unreachable|timed out|timeout|KRB_AP_ERR_SKEW|clock skew too great|STATUS_PASSWORD_(?:MUST_CHANGE|EXPIRED)|STATUS_ACCOUNT_(?:LOCKED_OUT|DISABLED|RESTRICTION|EXPIRED))/i.test(text)
      || facts.some(function (f) { return /^blocker\.(?:clock_skew|name_resolution|no_tty|crlf|hash_format|hashcat_env|web_wildcard|tls_scheme|kerberos_spn|xp_cmdshell_disabled|password_change|ntlm_disabled|nxc_c_share_denied|nxc_spider_usage|account_restricted)$/.test(f.kind); });
    var truncated = /\[truncated(?:[,\]]| output)|\[output truncated\]|output (?:was )?truncated|unexpected (?:end of (?:file|input)|EOF)|incomplete (?:output|capture)/i.test(text);
    var parsedError = !!opts.parseError || diagnostics.length > 0;
    var done = completion(text, command), obs = observations(text);
    var mixedAuth = obs.some(function (o) { return o.authentication === 'accepted'; }) && obs.some(function (o) { return o.authentication === 'rejected'; });
    var operation = /\b(?:nxc|netexec|crackmapexec|cme)\b/.test(command) && /(?:\s--(?:users|groups|shares|rid-brute|ntds|sam|lsa|spider)\b|\s-[MxX]\s)/.test(command);
    var resultProof = proof.some(function (f) { return !/^(?:host\.|port:|ports\.|service\.|(?:smb|ldap|winrm|rdp|ssh|mssql|ftp|wmi)\.(?:reachable|authenticated)$|ad\.(?:domain_known|base_dn|dc_candidate|anonymous_bind)$|credential\.(?:available|validated|plaintext|hash)$)/.test(f.kind); });
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
    else if (denial) set('authorization-denied', auth ? 'Authentication accepted; operation denied' : 'Operation denied; authentication unproven',
      auth ? 'Authentication remains established for this identity and service. The requested operation was denied.' : 'The output establishes a denial for this operation. It does not independently establish successful authentication.',
      'The denial applies to this host, identity, service, and operation. It does not invalidate the credential everywhere or prove administrative access.', 'blocked', 'alternate-context', true);
    else if (rejected) set('rejected', 'Authentication rejected for this context',
      'This authentication attempt was rejected. No access was established by this attempt.',
      'Keep the result attached to the specific host, identity, credential, and service. Other contexts remain untested.', 'blocked', 'alternate-context', true);
    else if (environment) set('environment-error', 'Execution or environment problem',
      'The output reports a tool, setup, transport, or account prerequisite problem.',
      'Resolve the reported prerequisite and retry. This output does not establish a negative finding about the underlying investigation.', 'blocked', 'repair', false);
    else if (done.negative) set('completed-negative', 'Operation completed; no matching results',
      'The supported output family explicitly reports a completed negative result for this operation.',
      'The negative result is limited to this query, endpoint, identity, and service. Other contexts remain available.', 'complete', 'continue', true);
    else if (proof.length) {
      var conclusive = done.complete || (auth && !operation) || /\b(?:id|whoami)\b/.test(command) && kinds.some(function (k) { return /^(?:access\.|foothold\.|host\.user)/.test(k); });
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
    } else if (done.complete && !truncated) set('completed', 'Tool completion recognized; objective unresolved',
      'The tool reported completion, but no supported positive or negative finding was extracted.',
      'Keep the evidence and review the operation. Tool completion alone does not prove the investigation was answered.', 'unresolved', 'review', false);
    if (truncated && !proof.length && !parsedError) {
      outcome.kind = 'unknown'; outcome.status = 'unresolved'; outcome.conclusive = false; outcome.retireCommand = false; outcome.retryable = true;
      outcome.title = 'Truncated output; outcome unresolved'; outcome.summary = 'No supported observation was recognized in this incomplete capture.';
      outcome.detail = 'The raw output is saved. Recover the complete output before drawing a positive or negative conclusion.'; outcome.next = 'review';
    }
    return outcome;
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
    return '<div class="outcome-receipt" data-outcome="' + esc(outcome.kind) + '" data-outcome-status="' + esc(outcome.status) + '" role="status">'
      + '<strong>' + esc(outcome.title) + '</strong>' + (context ? '<div class="ev-hint outcome-context">' + esc(context) + '</div>' : '')
      + forced
      + '<p>' + esc(outcome.summary) + '</p><p>' + esc(outcome.detail) + '</p>'
      + (outcome.observed && outcome.observed.length ? '<ul class="outcome-observed">' + outcome.observed.map(function (message) { return '<li>' + esc(message) + '</li>'; }).join('') + '</ul>' : '')
      + '<div class="ev-hint outcome-next">' + esc(nextLabels[outcome.next] || nextLabels.review) + '</div></div>';
  }
  OBOL.outcomes = { classify: classify, aggregate: aggregate, snapshot: snapshot, describe: describe, render: render, alreadyKnown: alreadyKnown };
})(typeof globalThis !== 'undefined' ? globalThis : this);
