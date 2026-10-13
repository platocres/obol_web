/*!
 * obol engine — parsers/creds.js
 * Faithful JS port of 
 * Cracked hash -> credential.available; dumped NTLM -> pass-the-hash / crackable material.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _HASHCAT_NTLM_RE = /^(?<hash>[0-9a-fA-F]{32}):(?<pw>.+)$/;
  var _HASHCAT_IPMI_RE = /^(?:[0-9a-fA-F]+:)?(?<user>[a-zA-Z0-9._-]+):[0-9a-fA-F]{16,}:[0-9a-fA-F]{16,}:(?<pw>[^\r\n]+)$/;

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
    // A credential you CRACKED from a hash (john/hashcat) is validated by construction: the crack proved
    // the plaintext produces that account's own hash, so it needs no "does it work?" probe. Mark it so the
    // Validate step settles for it. A dumped/found plaintext (mimikatz) is NOT auto-validated.
    if (method === 'john' || method === 'hashcat') _add(facts, mkFact('credential.validated', 'host:' + ws.target, { user: user, via: method }, S, source));
    var uLow = (user || '').toLowerCase();
    if (uLow === 'administrator' || uLow === 'root') {
      _add(facts, mkFact('credential.admin', scope, value, S, source));
      _add(facts, mkFact('access.admin', scope, value, S, source));
    }
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

      if (ll.indexOf('$sntp-ms$') >= 0) {
        var idxS = line.lastIndexOf(':');
        if (idxS >= 0) {
          var hashTextS = line.slice(0, idxS), passS = line.slice(idxS + 1).trim();
          if (C._valid_password(passS)) {
            var ridM = /^(\d+):/.exec(hashTextS);
            var ridUser = ridM ? ('RID-' + ridM[1]) : 'sntp-account';
            _add_plaintext_credential(facts, ws, source, ridUser, passS, C._domain_from_facts(ws), 'hashcat', 'sntp');
            return;
          }
        }
      }

      if (ll.indexOf('$keepass$*') >= 0) {
        var idxK = line.lastIndexOf(':');
        if (idxK >= 0) {
          var passK = line.slice(idxK + 1).trim();
          if (C._valid_password(passK)) {
            _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'keepass_master', password: passK, via: lc.indexOf('hashcat') >= 0 ? 'hashcat' : 'john' }, S, source));
            _add_plaintext_credential(facts, ws, source, 'keepass_master', passK, C._domain_from_facts(ws), lc.indexOf('hashcat') >= 0 ? 'hashcat' : 'john', 'keepass');
            return;
          }
        }
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
        var mIpmi = _HASHCAT_IPMI_RE.exec(line);
        if (mIpmi && C._valid_password(mIpmi.groups.pw)) {
          var ipmiUser = C._clean_username(mIpmi.groups.user);
          if (C._valid_username(ipmiUser, false)) {
            _add_plaintext_credential(facts, ws, source, ipmiUser, mIpmi.groups.pw, C._domain_from_facts(ws), 'hashcat', 'ipmi-rakp');
            return;
          }
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
          var pwTrim = lm.groups.pw.trim();
          var lbl = lm.groups.label ? lm.groups.label.trim() : '';
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target,
            { kind: 'cracked_secret', password: pwTrim, label: lbl, via: 'john' }, S, source));
          var urLive = (lbl && lbl !== '?') ? lbl : (_user_for_roast(ws, 'krb5tgs') || _user_for_roast(ws, 'krb5asrep') || 'Administrator');
          var htypeLive = (textLow.indexOf('krb5tgs') >= 0 || textLow.indexOf('tgs') >= 0) ? 'krb5tgs' : 'krb5asrep';
          _add_plaintext_credential(facts, ws, source, urLive, pwTrim, C._domain_from_facts(ws), 'john', htypeLive);
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

  // hydra (and medusa/ncrack, same shape) success lines:
  //   [22][ssh] host: 10.10.10.10   login: bob   password: Summer2024
  //   [80][http-post-form] host: 10.10.10.10   login: admin   password: Summer2024!
  // A hit is a VALIDATED online credential, so mint credential.available (+ plaintext) per login.
  // Conservative: only the bracketed-service success shape counts; a status/attempt line mints nothing.
  var _HYDRA_RE = /\[(?<port>\d{1,5})\]\[(?<svc>[A-Za-z][\w-]*)\][^\n]*?\blogin:\s*(?<user>\S+)\s+password:\s*(?<pw>\S.*?)\s*$/gim;
  function _parse_hydra(text, ws, command, source, facts) {
    var h = 'host:' + ws.target, m, seen = {}, n = 0;
    _HYDRA_RE.lastIndex = 0;
    while ((m = _HYDRA_RE.exec(text))) {
      var g = m.groups, key = g.svc + '|' + g.user + '|' + g.pw;
      if (seen[key]) continue; seen[key] = 1; n++;
      var cred = { user: g.user, password: g.pw, service: g.svc, port: +g.port, via: 'online-brute' };
      _add(facts, mkFact('credential.available', h, cred, S, source));
      _add(facts, mkFact('credential.plaintext', h, cred, S, source));
      // An online-brute hit already PROVED the login against the live service, so it is validated.
      _add(facts, mkFact('credential.validated', h, { user: g.user, service: g.svc, via: 'online-brute' }, S, source));
    }
    return n;
  }
  C._parse_hydra = _parse_hydra;

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
        _add(facts, mkFact('credential.admin', scope, av, S, source));
        _add(facts, mkFact('access.admin', scope, av, S, source));
      }
    } else {
      _add(facts, mkFact('loot.sam', 'host:' + ws.target, { count: entries.length, method: 'sam-dump' }, S, source));
      var localAdmin = entries.filter(function (e) { return e.rid === 500; })[0]
        || entries.filter(function (e) { return e.user.toLowerCase() === 'administrator'; })[0];
      if (localAdmin && localAdmin.nthash && localAdmin.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
        var lav = { user: localAdmin.user, nthash: localAdmin.nthash, method: 'sam-dump', hash_type: 'ntlm' };
        _add(facts, mkFact('credential.available', 'host:' + ws.target, lav, S, source));
        _add(facts, mkFact('credential.admin', 'host:' + ws.target, lav, S, source));
      }
    }
  }
  C._parse_ntlm_dump = _parse_ntlm_dump;

  function _looks_like_sam_dump(text) {
    if (!text) return false;
    return /^(?:[a-zA-Z0-9._$-]+:\d{3,5}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::)/m.test(text);
  }
  C._looks_like_sam_dump = _looks_like_sam_dump;

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

  // ── MSCache2 / DCC2 cached domain-logon hashes ───────────────────────────────────
  // secretsdump `-o`/cached output and mimikatz `lsadump::cache` surface domain creds that were cached
  // for offline logon as `$DCC2$<iters>#<user>#<32hex>` (hashcat mode 2100). These crack offline only
  // (no PtH), so they unlock the crack-mscache2 move rather than a direct login. Conservative: require
  // the literal `$DCC2$` token with its well-formed `#user#hash` tail — we never mint from a bare mention.
  var _DCC2_RE = /\$DCC2\$\d+#([^#\s:]+)#([0-9a-fA-F]{32})\b/g;
  function _looks_like_mscache(text) { return !!text && text.indexOf('$DCC2$') >= 0; }
  C._looks_like_mscache = _looks_like_mscache;

  function _parse_mscache(text, ws, command, source, facts) {
    if (!text || text.indexOf('$DCC2$') < 0) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target, entries = [], seen = {}, m;
    _DCC2_RE.lastIndex = 0;
    while ((m = _DCC2_RE.exec(text)) !== null) {
      var user = C._clean_username(m[1]), hash = m[2].toLowerCase();
      if (!C._valid_username(user, false)) continue;
      var key = user.toLowerCase() + '|' + hash;
      if (seen[key]) continue;
      seen[key] = true;
      entries.push({ user: user, mscache: m[0] });
    }
    if (!entries.length) return;
    _add(facts, mkFact('hash.mscache', h, { count: entries.length, entries: entries, mode: 2100, via: 'cache-dump' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { kind: 'mscache2', count: entries.length }, S, source));
  }
  C._parse_mscache = _parse_mscache;

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

  // ── Timeroasting / MS SNTP hashes ────────────────────────────────────────────────
  // NetExec `-M timeroast` or standalone SNTP timeroaster outputs `$sntp-ms$<32hex>$<hex>` (hashcat mode 31300).
  var _SNTP_SIG_RE = /\$sntp-ms\$[0-9a-fA-F]{32}\$[0-9a-fA-F]+/i;
  var _SNTP_LINE_RE = /(?:(?<rid>\d+):)?(?<hash>\$sntp-ms\$[0-9a-fA-F]{32}\$[0-9a-fA-F]+)/gi;
  function _looks_like_timeroast(text) { return !!text && _SNTP_SIG_RE.test(text); }
  C._looks_like_timeroast = _looks_like_timeroast;

  function _parse_timeroast(text, ws, command, source, facts) {
    if (!text || !_SNTP_SIG_RE.test(text)) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target, entries = [], hashes = [], seen = {}, m;
    _SNTP_LINE_RE.lastIndex = 0;
    while ((m = _SNTP_LINE_RE.exec(text)) !== null) {
      var hash = m.groups.hash, rid = m.groups.rid ? parseInt(m.groups.rid, 10) : null;
      if (seen[hash]) continue;
      seen[hash] = true;
      hashes.push(hash);
      entries.push({ hash: hash, rid: rid });
    }
    if (!hashes.length) return;
    _add(facts, mkFact('hash.sntp', h, { count: hashes.length, hashes: hashes, entries: entries, via: 'timeroast' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { kind: 'timeroast', count: hashes.length, via: 'timeroast' }, S, source));
  }
  C._parse_timeroast = _parse_timeroast;

  // ── Generic Structured Credential Dumps ──────────────────────────────────────────
  // Matches multi-line blocks printed by credential extraction tools and dump scripts:
  //   Domain: MEGABANK.LOCAL
  //   Username: administrator
  //   Password: d0m@in4dminyeah!
  // as well as command-line process credentials (e.g. SNMP leaks: `/bin/prog -u user -p pass`)
  var _GENERIC_CRED_BLOCK_RE = /(?:Domain\s*:\s*(?<dom>[^\r\n]+)\s*\r?\n\s*)?User(?:name)?\s*:\s*(?<user>[^\r\n]+)\s*\r?\n\s*(?:Domain\s*:\s*(?<dom2>[^\r\n]+)\s*\r?\n\s*)?Password\s*:\s*(?<pw>[^\r\n]+)/gi;
  var _CMD_CRED_RE = /(?:^|\s|\/)(?:-u|--user|-username|--username|\/u|\/user)[:=\s]+['"]?(?<user>[a-zA-Z0-9._-]+)['"]?\s+(?:-p|--password|-pass|--pass|\/p|\/pass|\/password)[:=\s]+['"]?(?<pw>[^\s'"]+)['"]?/gi;
  var _JSON_CRED_RE = /"(?:username|user)"\s*:\s*"(?<user>[^"]+)"[\s\S]{1,120}?"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"/gi;
  var _JSON_CRED_REV_RE = /"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"[\s\S]{1,120}?"(?:username|user)"\s*:\s*"(?<user>[^"]+)"/gi;
  var _URL_CRED_RE = /https?:\/\/(?<user>[a-zA-Z0-9._-]+):(?<pw>[^@\s'"]+)@/gi;
  var _KEEPASS_DUMP_RE = /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _MREMOTENG_DECRYPT_RE = /^\s*(?<user>[a-zA-Z0-9._$-]+)@(?<host>[a-zA-Z0-9._-]+)(?::\d+)?\s*\|\s*password\s+is:\s*(?<pw>\S+)/gim;
  var _CISCO_CONFIG_CRED_RE = /^\s*username\s+(?<user>[a-zA-Z0-9._-]+)(?:\s+privilege\s+\d+)?\s+(?:password\s+0|secret\s+0|password)\s+['"]?(?<pw>[^\r\n\s'"]+)['"]?/gmi;
  var _CISCO_DECRYPT_OUTPUT_RE = /(?:cisco-decrypt|decrypted\s*(?:cisco)?\s*password)\s*[:=->]\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _CONN_STRING_USER_RE = /(?:User ID|UID)\s*=\s*['"]?(?<user>[a-zA-Z0-9._-]+)['"]?/gi;
  var _CONN_STRING_PASS_RE = /(?:Password|PWD)\s*=\s*['"]?(?<pw>[^;'"\r\n]+)['"]?/gi;
  var _NOSQL_EXTRACT_RE = /(?:(?:extracted|recovered|found)\s*(?:nosql|user|admin|db)?\s*(?:password|passwd|creds?)\s*[:=->]|\[\+\]\s*(?:password|extracted)\s*[:=->])\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _PRTG_DBPASS_RE = /<(?:dbpassword|dbpass)>(?:<text>)?(?<pw>[^<]+)(?:<\/text>)?<\/(?:dbpassword|dbpass)>/gi;
  var _AMPORTAL_PASS_RE = /^\s*(?:AMPDBPASS|AMPMGRPASS)\s*=\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gmi;
  var _COLDFUSION_HASH_RE = /^\s*(?:password|encryptedPassword)\s*=\s*['"]?(?<hash>[a-fA-F0-9]{40})['"]?/gmi;
  var _ODAT_CRED_RE = /\[\+\]\s+Valid credentials found:\s*(?<user>[a-zA-Z0-9_$]+)\/(?<pw>\S+)/gi;

  function _looks_like_generic_dumped_credentials(text) {
    return !!text && (
      /(?:Domain\s*:\s*[^\r\n]+\s*\r?\n\s*)?User(?:name)?\s*:\s*[^\r\n]+\s*\r?\n\s*Password\s*:\s*[^\r\n]+/i.test(text) ||
      /(?:^|\s|\/)(?:-u|--user|-username|--username|\/u|\/user)[:=\s]+['"]?[a-zA-Z0-9._-]+['"]?\s+(?:-p|--password|-pass|--pass|\/p|\/pass|\/password)[:=\s]+['"]?[^\s'"]+['"]?/i.test(text) ||
      /"(?:username|user)"\s*:\s*"[^"]+"[\s\S]{1,120}?"(?:password|pass)"\s*:\s*"[^"]+"/i.test(text) ||
      /"(?:password|pass)"\s*:\s*"[^"]+"[\s\S]{1,120}?"(?:username|user)"\s*:\s*"[^"]+"/i.test(text) ||
      /https?:\/\/[a-zA-Z0-9._-]+:[^@\s'"]+@/i.test(text) ||
      /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*[^\r\n]+/i.test(text) ||
      /[a-zA-Z0-9._$-]+@[a-zA-Z0-9._-]+(?::\d+)?\s*\|\s*password\s+is:/i.test(text) ||
      /<(?:dbpassword|dbpass)>/i.test(text) ||
      /\b(?:AMPDBPASS|AMPMGRPASS)\s*=/i.test(text) ||
      /\b(?:password|encryptedPassword)\s*=\s*[a-fA-F0-9]{40}\b/i.test(text) ||
      /\[\+\]\s+Valid credentials found:\s*[a-zA-Z0-9_$]+\/\S+/i.test(text) ||
      /^[+-]?\s*(?:(?:db_|admin_|app_|api_)?password|passwd|pwd)\s*[=:]\s*['"]?[^\r\n\s'"]+['"]/mi.test(text) ||
      /^\s*username\s+[a-zA-Z0-9._-]+(?:\s+privilege\s+\d+)?\s+(?:password|secret)\b/mi.test(text) ||
      /(?:cisco-decrypt|decrypted\s*(?:cisco)?\s*password)\s*[:=->]/i.test(text) ||
      /(?:User ID|UID)\s*=\s*[a-zA-Z0-9._-]+[\s\S]{1,150}?(?:Password|PWD)\s*=/i.test(text) ||
      /(?:Password|PWD)\s*=[^;\r\n]+[\s\S]{1,150}?(?:User ID|UID)\s*=/i.test(text) ||
      /(?:(?:extracted|recovered|found)\s*(?:nosql|user|admin|db)?\s*(?:password|passwd)|\[\+\]\s*password)\s*[:=->]/i.test(text) ||
      /^(?:["']?[a-zA-Z0-9_]+["']?[,\t])*(?:["']?(?:username|user|login)["']?[,\t])+(?:["']?[a-zA-Z0-9_]+["']?[,\t])*(?:["']?(?:password|pass|passwd|pwd)["']?)/mi.test(text)
    );
  }
  C._looks_like_generic_dumped_credentials = _looks_like_generic_dumped_credentials;

  function _parse_csv_dumped_credentials(text, ws, source, facts) {
    var lines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
    if (lines.length < 2) return;
    var headerLine = lines[0].toLowerCase();
    var sep = headerLine.indexOf('\t') >= 0 ? '\t' : (headerLine.indexOf(',') >= 0 ? ',' : null);
    if (!sep) return;
    var headers = headerLine.split(sep).map(function (h) { return h.replace(/^["']|["']$/g, '').trim(); });
    var userIdx = -1, passIdx = -1;
    for (var hi = 0; hi < headers.length; hi++) {
      var hName = headers[hi];
      if (userIdx === -1 && (hName === 'username' || hName === 'user' || hName === 'login' || hName === 'user_name')) userIdx = hi;
      if (passIdx === -1 && (hName === 'password' || hName === 'pass' || hName === 'passwd' || hName === 'pwd')) passIdx = hi;
    }
    if (userIdx === -1 || passIdx === -1) return;
    for (var i = 1; i < lines.length; i++) {
      var row = lines[i].split(sep).map(function (c) { return c.replace(/^["']|["']$/g, '').trim(); });
      if (row.length <= Math.max(userIdx, passIdx)) continue;
      var u = C._clean_username(row[userIdx]);
      var p = (row[passIdx] || '').trim();
      if (C._valid_username(u, false) && C._valid_password(p)) {
        _add_plaintext_credential(facts, ws, source, u, p, C._domain_from_facts(ws), 'db-dump', '');
      }
    }
  }

  function _parse_generic_dumped_credentials(text, ws, command, source, facts) {
    if (!text) return;
    text = text.replace(C._ANSI_RE, '');
    _GENERIC_CRED_BLOCK_RE.lastIndex = 0;
    var m;
    while ((m = _GENERIC_CRED_BLOCK_RE.exec(text)) !== null) {
      var user = C._clean_username(m.groups.user);
      var pw = (m.groups.pw || '').trim();
      var dom = (m.groups.dom || m.groups.dom2 || '').trim();
      if (!C._valid_username(user, false) || !C._valid_password(pw)) continue;
      _add_plaintext_credential(facts, ws, source, user, pw, dom || C._domain_from_facts(ws), 'dump', '');
    }

    _CMD_CRED_RE.lastIndex = 0;
    var cm;
    while ((cm = _CMD_CRED_RE.exec(text)) !== null) {
      var cUser = C._clean_username(cm.groups.user);
      var cPw = (cm.groups.pw || '').trim();
      if (!C._valid_username(cUser, false) || !C._valid_password(cPw)) continue;
      _add_plaintext_credential(facts, ws, source, cUser, cPw, C._domain_from_facts(ws), 'process-leak', '');
    }

    _JSON_CRED_RE.lastIndex = 0;
    var jm;
    while ((jm = _JSON_CRED_RE.exec(text)) !== null) {
      var jUser = C._clean_username(jm.groups.user);
      var jPw = (jm.groups.pw || '').trim();
      if (!C._valid_username(jUser, false) || !C._valid_password(jPw)) continue;
      _add_plaintext_credential(facts, ws, source, jUser, jPw, C._domain_from_facts(ws), 'api-leak', '');
    }
    _JSON_CRED_REV_RE.lastIndex = 0;
    while ((jm = _JSON_CRED_REV_RE.exec(text)) !== null) {
      var jrUser = C._clean_username(jm.groups.user);
      var jrPw = (jm.groups.pw || '').trim();
      if (!C._valid_username(jrUser, false) || !C._valid_password(jrPw)) continue;
      _add_plaintext_credential(facts, ws, source, jrUser, jrPw, C._domain_from_facts(ws), 'api-leak', '');
    }

    _URL_CRED_RE.lastIndex = 0;
    var um;
    while ((um = _URL_CRED_RE.exec(text)) !== null) {
      var uUser = C._clean_username(um.groups.user);
      var uPw = (um.groups.pw || '').trim();
      if (!C._valid_username(uUser, false) || !C._valid_password(uPw)) continue;
      _add_plaintext_credential(facts, ws, source, uUser, uPw, C._domain_from_facts(ws), 'url-auth', '');
    }

    _KEEPASS_DUMP_RE.lastIndex = 0;
    var km;
    while ((km = _KEEPASS_DUMP_RE.exec(text)) !== null) {
      var kPw = (km.groups.pw || '').trim();
      if (kPw && C._valid_password(kPw)) {
        var h = 'host:' + ws.target;
        _add(facts, mkFact('credential.candidate', h, { kind: 'keepass_master', password: kPw, via: 'memory-dump' }, S, source));
      }
    }

    _MREMOTENG_DECRYPT_RE.lastIndex = 0;
    var mm;
    while ((mm = _MREMOTENG_DECRYPT_RE.exec(text)) !== null) {
      var mUser = C._clean_username(mm.groups.user);
      var mPw = (mm.groups.pw || '').trim();
      if (C._valid_username(mUser, false) && C._valid_password(mPw)) {
        _add_plaintext_credential(facts, ws, source, mUser, mPw, C._domain_from_facts(ws), 'mremoteng', '');
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'mremoteng_secret', user: mUser, password: mPw, host: mm.groups.host }, S, source));
      }
    }

    _CISCO_CONFIG_CRED_RE.lastIndex = 0;
    var ciscoM;
    while ((ciscoM = _CISCO_CONFIG_CRED_RE.exec(text)) !== null) {
      var ciscoUser = C._clean_username(ciscoM.groups.user);
      var ciscoPw = (ciscoM.groups.pw || '').trim();
      if (C._valid_username(ciscoUser, false) && C._valid_password(ciscoPw)) {
        _add_plaintext_credential(facts, ws, source, ciscoUser, ciscoPw, C._domain_from_facts(ws), 'cisco-config', '');
      }
    }

    _CISCO_DECRYPT_OUTPUT_RE.lastIndex = 0;
    var ciscoDecM;
    while ((ciscoDecM = _CISCO_DECRYPT_OUTPUT_RE.exec(text)) !== null) {
      var decPw = (ciscoDecM.groups.pw || '').trim();
      if (C._valid_password(decPw)) {
        _add_plaintext_credential(facts, ws, source, 'cisco_admin', decPw, C._domain_from_facts(ws), 'cisco-decrypt', '');
      }
    }

    _PRTG_DBPASS_RE.lastIndex = 0;
    var prtgM;
    while ((prtgM = _PRTG_DBPASS_RE.exec(text)) !== null) {
      var prtgPw = (prtgM.groups.pw || '').trim();
      if (C._valid_password(prtgPw)) {
        _add_plaintext_credential(facts, ws, source, 'prtgadmin', prtgPw, C._domain_from_facts(ws), 'prtg-config', '');
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'prtg_secret', user: 'prtgadmin', password: prtgPw }, S, source));
      }
    }

    _AMPORTAL_PASS_RE.lastIndex = 0;
    var ampM;
    while ((ampM = _AMPORTAL_PASS_RE.exec(text)) !== null) {
      var ampPw = (ampM.groups.pw || '').trim();
      if (C._valid_password(ampPw)) {
        _add_plaintext_credential(facts, ws, source, 'root', ampPw, C._domain_from_facts(ws), 'amportal-conf', '');
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'amportal_secret', user: 'root', password: ampPw }, S, source));
      }
    }

    _COLDFUSION_HASH_RE.lastIndex = 0;
    var cfM;
    while ((cfM = _COLDFUSION_HASH_RE.exec(text)) !== null) {
      var cfHash = (cfM.groups.hash || '').trim();
      if (cfHash && cfHash.length === 40) {
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'coldfusion_hash', user: 'admin', hash: cfHash, hash_type: 'sha1' }, S, source));
      }
    }

    _ODAT_CRED_RE.lastIndex = 0;
    var odatM;
    while ((odatM = _ODAT_CRED_RE.exec(text)) !== null) {
      var odatU = (odatM.groups.user || '').trim();
      var odatP = (odatM.groups.pw || '').trim();
      if (C._valid_username(odatU, false) && C._valid_password(odatP)) {
        _add_plaintext_credential(facts, ws, source, odatU, odatP, 'oracle', 'odat', '');
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'oracle_database', user: odatU, password: odatP }, S, source));
      }
    }

    _parse_csv_dumped_credentials(text, ws, source, facts);

    var linesCs = text.split(/\r?\n/);
    for (var ci = 0; ci < linesCs.length; ci++) {
      var csLine = linesCs[ci];
      if (/(?:User ID|UID)\s*=/i.test(csLine) && /(?:Password|PWD)\s*=/i.test(csLine)) {
        _CONN_STRING_USER_RE.lastIndex = 0;
        _CONN_STRING_PASS_RE.lastIndex = 0;
        var uMatch = _CONN_STRING_USER_RE.exec(csLine);
        var pMatch = _CONN_STRING_PASS_RE.exec(csLine);
        if (uMatch && pMatch) {
          var csU = C._clean_username(uMatch.groups.user);
          var csP = (pMatch.groups.pw || '').trim();
          if (C._valid_username(csU, false) && C._valid_password(csP)) {
            _add_plaintext_credential(facts, ws, source, csU, csP, C._domain_from_facts(ws), 'connection-string', '');
          }
        }
      }
    }

    _NOSQL_EXTRACT_RE.lastIndex = 0;
    var nsm;
    while ((nsm = _NOSQL_EXTRACT_RE.exec(text)) !== null) {
      var nsPw = (nsm.groups.pw || '').trim();
      if (C._valid_password(nsPw)) {
        _add_plaintext_credential(facts, ws, source, 'admin', nsPw, C._domain_from_facts(ws), 'nosql-blind', '');
      }
    }
  }
  C._parse_generic_dumped_credentials = _parse_generic_dumped_credentials;

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
  var _FLAG_TOKEN = '(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64}|(?:HTB|FLAG|flag)\\{[0-9A-Za-z_@!#%.:\\-]{3,\\}|\\{[0-9A-Za-z_@!#%.:\\-]{3,\\}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})';
  var _FLAG_VALUE_ANCHORED = new RegExp('^' + _FLAG_TOKEN + '$');
  var _FLAG_FILE_IN_CMD_RE = /(?:\btype\b|\bcat\b|\bmore\b|\bhead\b|\btail\b|\bbat\b|\bless\b|\bgrep\b|Get-Content|\bgc\b|Select-String)\s+[^\r\n|]*?(?<file>(?:[a-zA-Z0-9._-]+\.txt:)?(?:local|proof|user|root|flag\d?)\.txt)/i;
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
  var _SPIDER_PATH_RE = /(?:\/\/|\\\\)[^\s/\\]+[/\\](?:([A-Za-z])\$|Users)[/\\]([^\s\[\]"']*?(?:local|proof|user|root|flag\d?)\.txt)(?=\s|$|\[|"|')/gi;
  // Strip a leading shell prompt so a pasted interactive frame's echoed command can be read: an on-host
  // capture is pasted whole — `*Evil-WinRM* PS C:\Users\…> hostname; ipconfig; type C:\…\user.txt` — and the
  // read (and whether it was on-host) has to come from that echoed line, since the paste box may attach a
  // different command (the spider that located the flag) or none at all.
  function _strip_prompt(line) {
    return String(line)
      .replace(/^\s*(?:(?:SMB|WINRM|WMI|RPC|SSH)\s+\S+\s+\d+\s+\S+\s+)/i, '') // NetExec / CME row prefix
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
      // On-host bare read → the captured objective that reaches the report. Remote exec (-x/wmiexec)
      // also captures the objective when code execution was achieved.
      var isExec = command && /-x\b|wmiexec|psexec|smbclient.*get/i.test(command);
      var kind = (onHost || isExec) ? _flag_kind(slot) : 'objective.flag_located';
      _add(facts, mkFact(kind, scope, { flag: flag, slot: slot, name: base, path: path || '' }, S, source));
    }
    // A located PATH with no value yet (a spider/dir listing) — record where the flag is, so the on-host
    // capture step can fill the real path. Never a captured objective (no value = nothing read).
    function mintPath(path, slot) {
      if (!path) return;
      var clean = String(path).trim().replace(/[/\\]+/g, '\\');
      // Reject non-flag extensions (.lnk shortcuts) and Windows Recent/Temp junk directories
      if (/\.lnk$/i.test(clean)) return;
      if (/[\\/](?:Recent|Temporary Internet Files|INetCache|AppData[\\/]Local[\\/]Temp)[\\/]/i.test(clean)) return;
      if (seenPath[clean]) return;
      seenPath[clean] = 1;
      var base = clean.split(/[\\/]/).pop() || '';
      var actualSlot = slot || _slot_for_flagfile(base);
      _add(facts, mkFact('objective.flag_located', scope, { slot: actualSlot, name: base, path: clean }, S, source));
      if (actualSlot === 'root' || actualSlot === 'local') {
        _add(facts, mkFact('objective.flag_located_' + actualSlot, scope, { slot: actualSlot, name: base, path: clean }, S, source));
      }
    }
    // 1) `===FLAG:path::value` markers — mint only when the value IS a clean flag token (the file's whole
    //    contents), never a marker whose body is tool text (a failed hunt that printed no real flag).
    var markerOnHost = !!(command && String(command).trim()) && !cmdRemote;
    var m; _FLAG_MARK_RE.lastIndex = 0;
    while ((m = _FLAG_MARK_RE.exec(text))) { var body = (m.groups.body || '').trim(); if (_FLAG_VALUE_ANCHORED.test(body)) mint(m.groups.path, body, null, markerOnHost); }
    // 2) a direct read of a named flag file (`type …\proof.txt`, `cat …/root.txt`) — from the attached
    //    command, else from the read echoed after a shell prompt in the pasted frame. The flag must stand
    //    ALONE on its own output line, so a 32-hex in an auth banner or a hash-dump line is never a flag.
    //    A single paste can hold MORE THAN ONE read (a promptless whole-blob capture, or an interactive
    //    frame where the operator read user.txt then root.txt), so walk the lines in order and attribute
    //    each flag value to the NEAREST PRECEDING read: the user flag is local, the root flag is root,
    //    never both collapsed onto the first file's slot. The attached command seeds the initial read for
    //    the case where the value is pasted with no echoed `type` line.
    var curFile = null, curSlot = null, curOnHost = false;
    var fm = _FLAG_FILE_IN_CMD_RE.exec(command || '');
    if (fm) { curFile = fm.groups.file; curSlot = _slot_for_flagfile(curFile); curOnHost = !cmdRemote; }
    String(text || '').split(/\r?\n/).forEach(function (l) {
      var bare = _strip_prompt(l);
      var fx = _FLAG_FILE_IN_CMD_RE.exec(bare);
      if (fx) { curFile = fx.groups.file; curSlot = _slot_for_flagfile(curFile); curOnHost = !_REMOTE_LEAD_RE.test(bare); return; }
      if (curFile && _FLAG_VALUE_ANCHORED.test(bare.trim())) {
        mint(curFile, bare.trim(), curSlot, curOnHost);
      } else if (!curFile && /^(?:HTB|FLAG|flag)\{[^}]+\}/i.test(bare.trim())) {
        mint('user.txt', bare.trim(), 'flag', true);
      }
    });
    // 3) LOCATE: a spider/dir listing of flag-file paths (no value) → record each location + its exact path.
    var sp; _SPIDER_PATH_RE.lastIndex = 0;
    while ((sp = _SPIDER_PATH_RE.exec(text))) {
      var drive = sp[1] ? (sp[1].toUpperCase() + ':\\') : 'C:\\Users\\';
      var winPath = drive + String(sp[2]).replace(/[/\\]+/g, '\\');
      var pbase = winPath.split(/[\\/]/).pop() || '';
      mintPath(winPath, _slot_for_flagfile(pbase));
    }
    // 3b) LOCATE from a RECURSIVE SEARCH that prints BARE local paths, one per line: Windows
    // `where /r C:\Users\ user.txt` / `Get-ChildItem -Recurse | % FullName` / `dir /s /b`, and Linux
    // `find / -name user.txt`. These print a real path with no UNC `\\host\C$` lead, so _SPIDER_PATH_RE
    // misses them and (before this) locating a flag on-host minted nothing, leaving the capture step to
    // guess a wrong path. A bare path is only taken when it STANDS ALONE on its line (after the shell
    // prompt is stripped), so a `type …\user.txt` command echo or an `===FLAG:` marker is never caught here.
    String(text || '').split(/\r?\n/).forEach(function (l) {
      var t = _strip_prompt(String(l)).trim();
      if (!t || /[<>|]/.test(t)) return;                       // not a redirection/pipe line
      if (_BARE_WIN_FLAGPATH_RE.test(t)) { mintPath(t.replace(/[/]+/g, '\\'), _slot_for_flagfile(t.split(/[\\/]/).pop())); return; }
      if (_BARE_NIX_FLAGPATH_RE.test(t)) { mintPath(t, _slot_for_flagfile(t.split(/[\\/]/).pop())); }
    });
    // 3c) LOCATE from Windows dir /r (Alternate Data Streams)
    var _ADS_DIR_R_RE = /\b(?<fn>[a-zA-Z0-9._-]+\.txt):(?<stream>(?:local|proof|user|root|flag\d?)\.txt):\$DATA\b/gi;
    var adsMatch;
    while ((adsMatch = _ADS_DIR_R_RE.exec(text)) !== null) {
      var adsTarget = adsMatch.groups.fn + ':' + adsMatch.groups.stream;
      mintPath(adsTarget, _slot_for_flagfile(adsMatch.groups.stream));
    }
  }
  // A bare flag-file path on its own line, as a recursive search prints it. Anchored start-to-end so only a
  // whole-line path matches (never a path embedded in a `type`/`cat` command echo or an `===FLAG:` marker).
  var _BARE_WIN_FLAGPATH_RE = /^[A-Za-z]:[\\/](?:[^\\/\r\n]+[\\/])+(?:local|proof|user|root|flag\d?)\.txt$/i;
  var _BARE_NIX_FLAGPATH_RE = /^\/(?:[^/\r\n]+\/)+(?:local|proof|user|root|flag\d?)\.txt$/i;
  C._parse_flags = _parse_flags;

  // A KeePass database/dump in hand: a located .kdbx file, a keepass2john hash
  // ($keepass$*...), or a master-key recovery dump. Mints loot.keepass_dump so
  // the recover/crack move leads precisely instead of riding the generic "you
  // have loot files" gate. A bare mention with no artifact mints nothing.
  var _KEEPASS_KDBX_RE = /\b[\w.$\-]+\.kdbx\b/i;
  var _KEEPASS_HASH_RE = /\$keepass\$\*\d/i;
  var _KEEPASS_DUMP_RE = /\bkeepass[\w.]*\.(?:dmp|dump)\b|masterkey(?:\.txt)?\b.*keepass|keepass.*master\s*key/i;
  function _parse_keepass_dump(text, ws, command, source, facts) {
    if (!text && !command) return;
    var hay = (text || '') + '\n' + (command || '');
    var m = reSearch(_KEEPASS_HASH_RE, hay) || reSearch(_KEEPASS_KDBX_RE, hay) || reSearch(_KEEPASS_DUMP_RE, hay);
    if (!m) return;
    var h = 'host:' + ws.target;
    var kdbx = reSearch(_KEEPASS_KDBX_RE, hay);
    _add(facts, mkFact('loot.keepass_dump', h, { file: kdbx ? kdbx[0] : null, has_hash: !!reSearch(_KEEPASS_HASH_RE, hay), via: 'keepass' }, S, source));
  }
  C._parse_keepass_dump = _parse_keepass_dump;

})(typeof globalThis !== 'undefined' ? globalThis : this);
