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
    var entries = [], seen = {}, krbtgtNt = '';
    reAll(C._NTDS_HASH_RE, text).forEach(function (m) {
      var user = C._clean_username(m.groups.user);
      if (!user) return;
      var nt = m.groups.nt.toLowerCase();
      var key = user.toLowerCase() + '|' + nt;
      if (seen[key]) return;
      seen[key] = true;
      entries.push({ user: user, rid: parseInt(m.groups.rid, 10), nthash: nt });
      if (user.toLowerCase() === 'krbtgt') krbtgtNt = nt;
    });
    if (!entries.length) return;
    var lowered = text.toLowerCase(), lc = command.toLowerCase();
    var ntdsContext = !!krbtgtNt || lc.indexOf('--ntds') >= 0 || lc.indexOf('-just-dc') >= 0 ||
      ['ntds.dit', 'drsuapi', 'dumping domain credentials'].some(function (mk) { return lowered.indexOf(mk) >= 0; });
    var scope = C._scope_for_domain(ws);
    _add(facts, mkFact('hash.ntlm', scope, { count: entries.length, entries: entries }, S, source));
    _add(facts, mkFact('credential.candidate', scope, { kind: 'ntlm_hash', count: entries.length }, S, source));
    if (krbtgtNt) _add(facts, mkFact('hash.krbtgt', scope, { nthash: krbtgtNt }, S, source));
    if (ntdsContext) _add(facts, mkFact('loot.ntds', scope, { count: entries.length, method: 'credential-dump' }, S, source));
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

})(typeof globalThis !== 'undefined' ? globalThis : this);
