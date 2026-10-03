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

      // john's LIVE cracking output (a normal run, not --show) prints each recovered secret as
      // `<plaintext>        (<label>)`. Gated on john's "Loaded N password hash" preamble. The
      // plaintext is a candidate secret; the parenthesized label names what it unlocks.
      if (lc.indexOf('john') >= 0 && reSearch(C._JOHN_LOADED_RE, text)) {
        var lm = C._JOHN_CRACKED_LIVE_RE.exec(line);
        if (lm && lm.groups.pw.indexOf(':') < 0 && C._valid_password(lm.groups.pw.trim())) {
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target,
            { kind: 'cracked_secret', password: lm.groups.pw.trim(), label: lm.groups.label.trim(), via: 'john' }, S, source));
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

  // ── mimikatz credential dumps ────────────────────────────────────────────────────
  // sekurlsa::logonpasswords blocks (`* Username : X` / `* NTLM : <32hex>` / `* Password : <clear>`)
  // and lsadump::sam / lsadump::lsa output (`RID : … (nnn)` + `User : X` + `Hash NTLM: <32hex>` /
  // `* NTLM : <hash>`). Mint hash.ntlm for every recovered NT hash and credential.plaintext for every
  // cleartext password present; a full SAM/LSA/DCSync dump also earns loot.ntds. Conservative: a hash
  // is recorded only when an accompanying username line set the current account, and `(null)` is skipped.
  var _MIMI_SIG_RE = /sekurlsa::|lsadump::|crypto::capi|mimikatz\s+#|pypykatz|^Hash NTLM:/im;
  var _MIMI_USERNAME_RE = /^\s*\*\s*Username\s*:\s*(?<user>.+?)\s*$/i;   // sekurlsa section user
  var _MIMI_LSA_USER_RE = /^\s*User\s*:\s*(?<user>.+?)\s*$/i;            // lsadump RID-block user (not "User Name :")
  var _MIMI_DOMAIN_RE = /^\s*\*\s*Domain\s*:\s*(?<dom>.+?)\s*$/i;
  var _MIMI_RID_RE = /^\s*RID\s*:\s*[0-9a-fA-F]+\s*\((?<rid>\d+)\)/i;
  var _MIMI_NTLM_RE = /^\s*(?:\*\s*)?(?:Hash\s+)?NTLM\s*:\s*(?<nt>[0-9a-fA-F]{32})\b/i;
  var _MIMI_PASSWORD_RE = /^\s*\*\s*Password\s*:\s*(?<pw>.+?)\s*$/i;

  function _looks_like_mimikatz(text) { return !!reSearch(_MIMI_SIG_RE, text || ''); }
  C._looks_like_mimikatz = _looks_like_mimikatz;

  function _parse_mimikatz(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target, lc = (command || '').toLowerCase(), lowered = text.toLowerCase();
    var entries = [], seen = {}, plainSeen = {}, curUser = '', curDomain = '', curRid = null;
    text.split(/\r?\n/).forEach(function (raw) {
      var um = _MIMI_USERNAME_RE.exec(raw) || _MIMI_LSA_USER_RE.exec(raw);
      if (um) {
        var u = um.groups.user.trim();
        if (u.indexOf('\\') >= 0) curDomain = u.split('\\')[0].trim(); // lsadump `User : HTB\bob`
        curUser = C._clean_username(u);
        return;
      }
      var dm = _MIMI_DOMAIN_RE.exec(raw);
      if (dm) { curDomain = dm.groups.dom.trim(); return; }
      var rm = _MIMI_RID_RE.exec(raw);
      if (rm) { curRid = parseInt(rm.groups.rid, 10); return; }
      var nm = _MIMI_NTLM_RE.exec(raw);
      if (nm && curUser && C._valid_username(curUser)) {
        var nt = nm.groups.nt.toLowerCase(), key = curUser.toLowerCase() + '|' + nt;
        if (!seen[key]) {
          seen[key] = true;
          var e = { user: curUser, nthash: nt };
          if (curRid !== null) e.rid = curRid;
          if (curDomain && curDomain !== '(null)') e.domain = curDomain;
          entries.push(e);
        }
        return;
      }
      var pm = _MIMI_PASSWORD_RE.exec(raw);
      if (pm && curUser && C._valid_username(curUser)) {
        var pw = pm.groups.pw.trim();
        if (pw && pw !== '(null)' && C._valid_password(pw)) {
          var pk = curUser.toLowerCase() + '|' + pw;
          if (!plainSeen[pk]) {
            plainSeen[pk] = true;
            var dom = (curDomain && curDomain.indexOf('.') >= 0) ? curDomain : '';
            _add_plaintext_credential(facts, ws, source, curUser, pw, dom, 'mimikatz', '');
          }
        }
      }
    });
    if (!entries.length) return;
    _add(facts, mkFact('hash.ntlm', h, { count: entries.length, entries: entries, via: 'mimikatz' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { kind: 'ntlm_hash', count: entries.length, via: 'mimikatz' }, S, source));
    // A full SAM/LSA/DCSync dump hands you every local/domain account hash — surface it as loot.ntds.
    if (lc.indexOf('lsadump') >= 0 || lowered.indexOf('lsadump::') >= 0) {
      _add(facts, mkFact('loot.ntds', h, { count: entries.length, method: 'lsadump' }, S, source));
    }
  }
  C._parse_mimikatz = _parse_mimikatz;

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
  // Strip a leading shell prompt so a pasted interactive frame's echoed command can be read: an on-host
  // capture is pasted whole — `*Evil-WinRM* PS C:\Users\…> hostname; ipconfig; type C:\…\user.txt` — and the
  // read (and whether it was on-host) has to come from that echoed line, since the paste box may attach a
  // different command (the spider that located the flag) or none at all.
  function _strip_prompt(line) {
    return String(line)
      .replace(/^\s*\*?Evil-WinRM\*?\s*PS\s+[A-Za-z]:\\[^>\r\n]*>\s*/i, '') // *Evil-WinRM* PS C:\...>
      .replace(/^\s*PS\s+[A-Za-z]:\\[^>\r\n]*>\s*/i, '')                    // PS C:\...>
      .replace(/^\s*[A-Za-z]:\\[^>\r\n]*>\s*/, '')                          // C:\...>
      .replace(/^\s*[└├]─?[$#]\s*/, '')                                     // kali └─$ / └─#
      .replace(/^\s*[\w.-]+@[\w.-]+:[^$#\r\n]*[$#]\s*/, '')                 // user@host:~$ / #
      .replace(/^\s*[$#]\s+/, '');                                          // bare $ / #
  }
  function _parse_flags(text, ws, command, source, facts) {
    var scope = 'host:' + ws.target, seen = {}, seenPath = {};
    var cmdRemote = !!(command && String(command).trim()) && _REMOTE_LEAD_RE.test(command);
    function mint(path, flag, slotHint, onHost) {
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
    var markerOnHost = !!(command && String(command).trim()) && !cmdRemote;
    var m; _FLAG_MARK_RE.lastIndex = 0;
    while ((m = _FLAG_MARK_RE.exec(text))) { var body = (m.groups.body || '').trim(); if (_FLAG_VALUE_ANCHORED.test(body)) mint(m.groups.path, body, null, markerOnHost); }
    // 2) a direct read of a named flag file (`type …\proof.txt`, `cat …/root.txt`) — from the attached
    //    command, else from the read echoed after a shell prompt in the pasted frame. The flag must stand
    //    ALONE on its own output line, so a 32-hex in an auth banner or a hash-dump line is never a flag.
    var readFile = null, readOnHost = false;
    var fm = _FLAG_FILE_IN_CMD_RE.exec(command || '');
    if (fm) { readFile = fm.groups.file; readOnHost = !cmdRemote; }
    else {
      var ls = String(text || '').split(/\r?\n/);
      for (var li = 0; li < ls.length; li++) {
        var bare = _strip_prompt(ls[li]);
        var fx = _FLAG_FILE_IN_CMD_RE.exec(bare);
        if (fx) { readFile = fx.groups.file; readOnHost = !_REMOTE_LEAD_RE.test(bare); break; }
      }
    }
    if (readFile) {
      var slot = _slot_for_flagfile(readFile);
      String(text || '').split(/\r?\n/).forEach(function (l) { var t = l.trim(); if (_FLAG_VALUE_ANCHORED.test(t)) mint(readFile, t, slot, readOnHost); });
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
