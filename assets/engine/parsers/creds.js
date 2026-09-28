/*!
 * obol engine — parsers/creds.js
 * Faithful JS port of obol-local/obol/parsers/creds.py.
 * Cracked hash -> credential.available; dumped NTLM -> pass-the-hash / crackable material.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _HASHCAT_NTLM_RE = /^(?<hash>[0-9a-fA-F]{32}):(?<pw>.+)$/;

  function _user_for_nthash(ws, nthash) {
    nthash = (nthash || '').toLowerCase();
    var facts = (ws && ws.seedFacts) || [];
    for (var i = 0; i < facts.length; i++) {
      var val = facts[i].value || {};
      var entries = val.entries || [];
      for (var j = 0; j < entries.length; j++) {
        if (entries[j] && String(entries[j].nthash || '').toLowerCase() === nthash) return String(entries[j].user || '');
      }
      if (String(val.nthash || '').toLowerCase() === nthash && val.user) return String(val.user);
    }
    return '';
  }

  function _user_for_roast(ws, htype) {
    var kind = htype === 'krb5tgs' ? 'hash.tgs' : 'hash.asrep';
    var facts = (ws && ws.seedFacts) || [];
    for (var i = 0; i < facts.length; i++) {
      if (facts[i].kind === kind && (facts[i].value || {}).user) return String(facts[i].value.user);
    }
    return '';
  }

  function _parse_hash_user(hashText) {
    var asrep = reSearch(C._ASREP_USER_RE, hashText);
    if (asrep) return [C._clean_username(asrep[1]), (asrep[2] || '').toLowerCase(), 'asrep'];
    var tgs = reSearch(C._TGS_USER_RE, hashText);
    if (tgs) return [C._clean_username(tgs[1]), '', 'tgs'];
    return ['', '', ''];
  }
  C._parse_hash_user = _parse_hash_user;

  function _add_plaintext_credential(facts, ws, source, user, password, domain, method, hashType) {
    user = C._clean_username(user);
    password = (password || '').trim();
    if (!C._valid_username(user, false) || !C._valid_password(password)) return;
    var domainName = domain || C._domain_from_facts(ws);
    var value = { user: user, password: password, method: method };
    if (domainName) value.domain = domainName;
    if (hashType) value.hash_type = hashType;
    var scope = C._scope_for_domain(ws, domainName);
    _add(facts, mkFact('credential.plaintext', scope, value, S, source));
    _add(facts, mkFact('credential.available', scope, value, S, source));
  }
  C._add_plaintext_credential = _add_plaintext_credential;

  function _parse_cracked_credentials(text, ws, command, source, facts) {
    var lc = command.toLowerCase();
    var textLow = text.toLowerCase();
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line || line[0] === '#') return;
      var ll = line.toLowerCase();
      if (C._JOHN_NOISE_PREFIXES.some(function (p) { return ll.indexOf(p) === 0; })) return;

      if (ll.indexOf('$krb5asrep$') >= 0 || ll.indexOf('$krb5tgs$') >= 0) {
        var idx = line.lastIndexOf(':');
        if (idx < 0) return;
        var hashText = line.slice(0, idx), password = line.slice(idx + 1);
        var hu = _parse_hash_user(hashText);
        _add_plaintext_credential(facts, ws, source, hu[0], password, hu[1], lc.indexOf('hashcat') >= 0 ? 'hashcat' : 'john', hu[2]);
        return;
      }

      if (lc.indexOf('hashcat') >= 0) {
        var m = _HASHCAT_NTLM_RE.exec(line);
        if (m && C._valid_password(m.groups.pw)) {
          var nthash = m.groups.hash.toLowerCase();
          var cred = { kind: 'cracked_ntlm', nthash: nthash, password: m.groups.pw };
          var u = _user_for_nthash(ws, nthash);
          if (u) cred.user = u;
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, cred, S, source));
          return;
        }
      }

      if (lc.indexOf('john') >= 0 && (textLow.indexOf('krb5tgs') >= 0 || textLow.indexOf('krb5asrep') >= 0) && reSearch(C._JOHN_CRACKED_FOOTER_RE, text)) {
        var jm = /^\?:(?<pw>.+)$/.exec(line);
        if (jm && C._valid_password(jm.groups.pw)) {
          var htype = textLow.indexOf('krb5tgs') >= 0 ? 'krb5tgs' : 'krb5asrep';
          var cr = { kind: 'cracked_' + htype, password: jm.groups.pw };
          var ur = _user_for_roast(ws, htype);
          if (ur) cr.user = ur;
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, cr, S, source));
          return;
        }
      }

      if (lc.indexOf('john') < 0) return;
      if (lc.indexOf('--show') < 0 && !reSearch(C._JOHN_CRACKED_FOOTER_RE, text)) return;
      var sm = C._JOHN_SHOW_RE.exec(line);
      if (!sm) return;
      if (!C._valid_password(sm.groups.password)) return;
      _add_plaintext_credential(facts, ws, source, sm.groups.user, sm.groups.password, '', 'john', '');
    });
  }
  C._parse_cracked_credentials = _parse_cracked_credentials;

  function _parse_ntlm_dump(text, ws, command, source, facts) {
    var entries = [], seen = {}, krbtgtNt = '', domCounts = {};
    reAll(C._NTDS_HASH_RE, text).forEach(function (m) {
      var user = C._clean_username(m.groups.user);
      if (!user) return;
      var nt = m.groups.nt.toLowerCase();
      var key = user.toLowerCase() + '|' + nt;
      if (seen[key]) return;
      seen[key] = true;
      // The dump lines carry the domain themselves (`htb.local\Administrator:500:…`); tally it so the loot
      // is scoped to the REAL domain even when the engagement never had one typed in — otherwise the facts
      // land under a placeholder scope (`domain:domain`) and the Administrator cred won't dedupe with the
      // one an nxc -H validation mints under the real domain.
      var edom = (m.groups.domain || '').trim();
      entries.push({ user: user, rid: parseInt(m.groups.rid, 10), nthash: nt, domain: edom });
      if (edom && edom.indexOf('.') >= 0) domCounts[edom] = (domCounts[edom] || 0) + 1;
      if (user.toLowerCase() === 'krbtgt') krbtgtNt = nt;
    });
    if (!entries.length) return;
    var lowered = text.toLowerCase(), lc = command.toLowerCase();
    var ntdsContext = !!krbtgtNt || lc.indexOf('--ntds') >= 0 || lc.indexOf('-just-dc') >= 0 ||
      ['ntds.dit', 'drsuapi', 'dumping domain credentials'].some(function (mk) { return lowered.indexOf(mk) >= 0; });
    // Prefer a domain proven by earlier facts; else the most common domain the dump lines themselves name.
    var dumpDomain = Object.keys(domCounts).sort(function (a, b) { return domCounts[b] - domCounts[a]; })[0] || '';
    var domainName = C._domain_from_facts(ws) || dumpDomain || '';
    var scope = domainName ? ('domain:' + domainName) : C._scope_for_domain(ws);
    _add(facts, mkFact('hash.ntlm', scope, { count: entries.length, entries: entries }, S, source));
    _add(facts, mkFact('credential.candidate', scope, { kind: 'ntlm_hash', count: entries.length }, S, source));
    if (krbtgtNt) _add(facts, mkFact('hash.krbtgt', scope, { nthash: krbtgtNt }, S, source));
    if (ntdsContext) {
      _add(facts, mkFact('loot.ntds', scope, { count: entries.length, method: 'credential-dump' }, S, source));
      // The dump hands you every account's NT hash — surface the built-in Administrator (RID 500) as a
      // ready-to-use credential so it lands on the credential cards and pass-the-hash commands fill from it.
      // This is the one that owns the domain; the full set stays in hash.ntlm for the report.
      var admin = entries.filter(function (e) { return e.rid === 500; })[0]
        || entries.filter(function (e) { return e.user.toLowerCase() === 'administrator'; })[0];
      if (admin && admin.nthash && admin.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
        var av = { user: admin.user, nthash: admin.nthash, method: 'dcsync', hash_type: 'ntlm' };
        var adom = admin.domain || domainName;
        if (adom) av.domain = adom;
        _add(facts, mkFact('credential.available', scope, av, S, source));
      }
    }
  }
  C._parse_ntlm_dump = _parse_ntlm_dump;

  var _RESPONDER_HASH_RE = /NTLMv2-SSP Hash\s*:\s*(?<hash>(?<user>[^:\s]+)::[^\s]+:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]+:[0-9A-Fa-f]+)/;

  function _parse_responder(text, ws, source, facts) {
    var users = [];
    reAll(_RESPONDER_HASH_RE, text).forEach(function (m) {
      if (users.indexOf(m.groups.user) < 0) users.push(m.groups.user);
    });
    if (!users.length) return;
    var value = { kind: 'netntlmv2', via: 'responder', count: users.length, users: users.slice(0, 20) };
    _add(facts, mkFact('credential.candidate', 'host:' + ws.target, value, S, source));
    _add(facts, mkFact('credential.netntlm', 'host:' + ws.target, value, S, source));
  }
  C._parse_responder = _parse_responder;

  // Flag capture → objective.<slot>_flag, so a read flag lands in the report. Two shapes are recognized,
  // both PROOF-bound (a proof-file path must be present, so a stray 32-hex like an NT hash is never a flag):
  //   1. `===FLAG:<path>::<contents>` markers the flag-hunt move prints (one per file it read);
  //   2. a direct read of a named flag file — `type …\proof.txt`, `cat …/local.txt` — with a flag-shaped
  //      value in the output.
  // Slot is decided by the file name: proof.txt/root.txt = root, local.txt/user.txt = local, else generic.
  var _FLAG_MARK_RE = /===FLAG:\s*(?<path>[^\r\n]*?)::(?<body>[^\r\n]*)/g;
  // A flag value is the WHOLE token: a 32/64-hex, a {braced} CTF flag, or a UUID — anchored so it can only
  // match a value that stands on its own, never a hex substring lifted out of a bigger line. This is the
  // guard that stops an NT hash inside an auth banner (`…\Administrator:32693…deadbeef (Pwn3d!)`) from ever
  // being recorded as a captured flag.
  var _FLAG_TOKEN = '(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64}|\\{[0-9A-Za-z_@!#%.:\\-]{3,}\\}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})';
  var _FLAG_VALUE_ANCHORED = new RegExp('^' + _FLAG_TOKEN + '$');
  var _FLAG_FILE_IN_CMD_RE = /(?:\btype\b|\bcat\b|\bmore\b|Get-Content|\bgc\b)\s+[^\r\n|]*?(?<file>(?:local|proof|user|root|flag\d?)\.txt)/i;
  // A read is REMOTE (a one-liner run FROM the operator box) when it leads with a transport/exec tool:
  // nxc/impacket/wmiexec/psexec/smbclient (non-interactive), or an ssh/evil-winrm/rdp ONE-LINER. OffSec
  // scores a flag read this way ZERO — the report proof must come from an interactive shell ON the target.
  // So a remote read only LOCATES a flag (records where it is + its value as intel); it never counts as
  // captured. A BARE read (`type …\root.txt`, `cat …/root.txt`) has no transport lead — you typed it inside
  // the interactive session, so THAT is the capture that reaches the report.
  var _REMOTE_LEAD_RE = /^\s*(?:(?:sudo|command|exec|proxychains\d?|stdbuf|timeout|doas)\s+(?:-\S+\s+|\S+=\S+\s+)*|\w+=\S+\s+)*(?:nxc|netexec|crackmapexec|cme|impacket-[\w.]+|wmiexec(?:\.py)?|smbexec(?:\.py)?|atexec(?:\.py)?|dcomexec(?:\.py)?|psexec(?:\.py)?|smbclient|smbmap|winrs|evil-winrm|ssh|sshpass|plink|xfreerdp|rdesktop|rpcclient)\b/i;
  function _slot_for_flagfile(name) {
    var n = (name || '').toLowerCase();
    if (/proof\.txt|root\.txt/.test(n)) return 'root';
    if (/local\.txt|user\.txt/.test(n)) return 'local';
    return 'flag';
  }
  function _flag_kind(slot) { return slot === 'root' ? 'objective.root_flag' : (slot === 'local' ? 'objective.local_flag' : 'objective.flag'); }
  // A spidered/listed flag-file PATH — nxc/smbmap `--spider` prints `//host/C$/Users/.../root.txt [lastm:… size:…]`,
  // smbclient/dir print a UNC/Windows path. This LOCATES a flag (records where it is) without reading its value,
  // so the operator can read it on-host next; the exact path also fills the on-host capture command.
  var _SPIDER_PATH_RE = /(?:\/\/|\\\\)[^\s/\\]+[/\\]([A-Za-z])\$[/\\]([^\s\[\]"']*?(?:local|proof|user|root|flag\d?)\.txt)\b/gi;
  function _parse_flags(text, ws, command, source, facts) {
    var scope = 'host:' + ws.target, seen = {}, seenPath = {};
    // On-host ⟺ a bare read (no remote transport leading the command). A remote/one-liner read is locate-only.
    var onHost = !!(command && String(command).trim()) && !_REMOTE_LEAD_RE.test(command);
    function mint(path, flag, slotHint) {
      if (!flag || seen[flag]) return;
      seen[flag] = 1;
      var base = String(path || '').split(/[\\/]/).pop() || '';
      var slot = slotHint || _slot_for_flagfile(base);
      // On-host bare read → the captured objective that reaches the report. Remote read → located intel only
      // (`objective.flag_located`): obol knows where the flag is and its value, but you must read it from an
      // interactive shell on the target for it to count.
      var kind = onHost ? _flag_kind(slot) : 'objective.flag_located';
      _add(facts, mkFact(kind, scope, { flag: flag, slot: slot, name: base, path: path || '' }, S, source));
    }
    // A located PATH with no value yet (a spider/dir listing) — record where the flag is, so the on-host
    // capture step can fill the real path. Never a captured objective (no value = nothing read).
    function mintPath(path, slot) {
      if (!path || seenPath[path]) return;
      seenPath[path] = 1;
      var base = String(path).split(/[\\/]/).pop() || '';
      _add(facts, mkFact('objective.flag_located', scope, { slot: slot || _slot_for_flagfile(base), name: base, path: path }, S, source));
    }
    // 1) `===FLAG:path::value` markers — mint only when the value IS a clean flag token (the file's whole
    //    contents), never a marker whose body is tool text (a failed hunt that printed no real flag).
    var m; _FLAG_MARK_RE.lastIndex = 0;
    while ((m = _FLAG_MARK_RE.exec(text))) { var body = (m.groups.body || '').trim(); if (_FLAG_VALUE_ANCHORED.test(body)) mint(m.groups.path, body); }
    // 2) a direct read of a named flag file (`type …\proof.txt`) — the flag must stand ALONE on its own
    //    output line, so a 32-hex embedded in an auth banner or a hash-dump line is never taken for a flag.
    var fm = _FLAG_FILE_IN_CMD_RE.exec(command || '');
    if (fm) {
      var slot = _slot_for_flagfile(fm.groups.file);
      String(text || '').split(/\r?\n/).forEach(function (l) { var t = l.trim(); if (_FLAG_VALUE_ANCHORED.test(t)) mint(fm.groups.file, t, slot); });
    }
    // 3) LOCATE: a spider/dir listing of flag-file paths (no value) → record each location + its exact path.
    var sp; _SPIDER_PATH_RE.lastIndex = 0;
    while ((sp = _SPIDER_PATH_RE.exec(text))) {
      var winPath = sp[1].toUpperCase() + ':\\' + String(sp[2]).replace(/[/\\]+/g, '\\');
      var pbase = winPath.split(/[\\/]/).pop() || '';
      mintPath(winPath, _slot_for_flagfile(pbase));
    }
  }
  C._parse_flags = _parse_flags;

})(typeof globalThis !== 'undefined' ? globalThis : this);
