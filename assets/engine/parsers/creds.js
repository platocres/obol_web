/*!
 * obol engine - parsers/creds.js
 * Faithful JS port of 
 * Cracked hash -> credential.available; dumped NTLM -> pass-the-hash / crackable material.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  var _HASHCAT_NTLM_RE = /^(?:(?:(?<domain>[^\\:\s]+)\\)?(?<user>[^:\s$]+):)?(?:\$NT\$)?(?<hash>[0-9a-fA-F]{16}|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}):(?<pw>[^\r\n:]+)$/;
  var _HASHCAT_NETNTLM_RE = /^(?<user>[a-zA-Z0-9._$-]+)::(?<domain>[^:]*):[0-9a-fA-F:]+:(?<pw>[^\r\n]+)$/;
  var _HASHCAT_IPMI_RE = /^(?:[0-9a-fA-F]+:)?(?<user>[a-zA-Z0-9._-]+):[0-9a-fA-F]{16,}:[0-9a-fA-F]{16,}:(?<pw>[^\r\n]+)$/;
  var _CRACKED_DCC2_RE = /^(?:[^:\s]+:)?\$DCC2\$\d+#(?<user>[^#]+)#(?<hash>[0-9a-fA-F]{32}):(?<pw>[^\r\n]+)$/i;
  var _CRACKED_MODULAR_RE = /^(?:(?<user>[^:\s$]+):)?(?<hash>\$(?:1|2[abxy]|5|6|y|apr1|P|H|pbkdf2[^$]*|pfx|pkzip2?|zip2|rar\d?|7z|office|pdf|sshng)\$[^\s:]+):(?<pw>[^\r\n:]+)$/i;

  function _user_for_nthash(ws, nthash) {
    nthash = (nthash || '').toLowerCase();
    var facts = (ws && (ws.seedFacts || ws.facts || ws.existing_facts)) || [];
    for (var i = 0; i < facts.length; i++) {
      var f = facts[i];
      var val = f.value || {};
      var entries = val.entries || [];
      for (var j = 0; j < entries.length; j++) {
        var e = entries[j];
        if (e && String(e.nthash || e.hash || '').toLowerCase() === nthash) return String(e.user || '');
      }
      if ((String(val.nthash || '').toLowerCase() === nthash || String(val.hash || '').toLowerCase() === nthash) && val.user) return String(val.user);
      if ((f.kind === 'hash.ntlm' || f.kind === 'credential.hash') && val.user) {
        if (String(val.hash || val.ntlm || val.nthash || '').toLowerCase() === nthash) return String(val.user);
      }
    }
    return '';
  }

  function _user_for_roast(ws, htype, currentFacts) {
    var kind = htype === 'krb5tgs' ? 'hash.tgs' : 'hash.asrep';
    var candKind = htype === 'krb5tgs' ? 'tgs_hash' : 'asrep_hash';
    var facts = [].concat((ws && (ws.seedFacts || ws.facts || ws.existing_facts)) || [], currentFacts || []);
    for (var i = 0; i < facts.length; i++) {
      var f = facts[i];
      if (!f || !f.value) continue;
      if (f.kind === kind && f.value.user) return String(f.value.user);
      if (f.kind === 'credential.candidate' && f.value.kind === candKind && f.value.user) return String(f.value.user);
    }
    return '';
  }

  function _parse_hash_user(hashText) {
    var asrep = reSearch(C._ASREP_USER_RE, hashText);
    if (asrep) return [C._clean_username(asrep[1]), (asrep[2] || '').toLowerCase(), 'asrep'];
    var tgs = reSearch(C._TGS_USER_RE, hashText);
    if (tgs) return [C._clean_username(tgs[1]), (tgs[2] || '').toLowerCase(), 'tgs'];
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
    // Recovery proves possession only. Authentication and privilege need service evidence.
  }
  C._add_plaintext_credential = _add_plaintext_credential;

  function _parse_cracked_credentials(text, ws, command, source, facts) {
    var lc = (command || '').toLowerCase();
    var textLow = text.toLowerCase();
    var isHashcatCtx = lc.indexOf('hashcat') >= 0 || /Status\.+:\s*Cracked|Session\.+:\s*hashcat/i.test(text);
    var isJohnCtx = lc.indexOf('john') >= 0 || !!reSearch(C._JOHN_LOADED_RE, text) || !!reSearch(C._JOHN_CRACKED_FOOTER_RE, text);
    var zeroCracked = /\b0\s+password\s+hash(?:es)?\s+cracked\b/i.test(text) && !/\b[1-9]\d*\s+password\s+hash(?:es)?\s+cracked\b/i.test(text);
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line || line[0] === '#') return;
      var ll = line.toLowerCase();
      if (C._JOHN_NOISE_PREFIXES.some(function (p) { return ll.indexOf(p) === 0; })) return;
      if (/^\d+\s+password\s+hash(?:es)?\s+cracked\b/i.test(line)) return;

      if (ll.indexOf('$krb5asrep$') >= 0 || ll.indexOf('$krb5tgs$') >= 0) {
        // Hashcat's Hash.Target status line is often abbreviated. It is not a
        // recovered hash:password record, even when the session says Cracked.
        if (!/^(?:[^\s:$]+:)?\$krb5(?:asrep|tgs)\$/i.test(line)) return;
        var idx = line.lastIndexOf(':');
        if (idx < 0) return;
        var hashText = line.slice(0, idx), password = line.slice(idx + 1).trim();
        if (/^[0-9a-fA-F]{16,}\$[0-9a-fA-F]{32,}/.test(password) || (password.length > 64 && /^[0-9a-fA-F$]+$/.test(password))) return;
        var hu = _parse_hash_user(hashText);
        var rType = ll.indexOf('$krb5tgs$') >= 0 ? 'krb5tgs' : 'krb5asrep';
        var rUser = hu[0] || _user_for_roast(ws, rType, facts);
        _add_plaintext_credential(facts, ws, source, rUser, password, hu[1], isHashcatCtx ? 'hashcat' : 'john', hu[2] || (rType === 'krb5tgs' ? 'tgs' : 'asrep'));
        return;
      }

      var mDcc = _CRACKED_DCC2_RE.exec(line);
      if (mDcc && C._valid_password(mDcc.groups.pw.trim())) {
        var dccUser = C._clean_username(mDcc.groups.user);
        var dccPw = mDcc.groups.pw.trim();
        var dccVia = isJohnCtx ? 'john' : 'hashcat';
        if (C._valid_username(dccUser, false)) {
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_mscache2', user: dccUser, password: dccPw, via: dccVia }, S, source));
          _add_plaintext_credential(facts, ws, source, dccUser, dccPw, C._domain_from_facts(ws), dccVia, 'mscache2');
          return;
        }
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
            _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'keepass_master', password: passK, via: isHashcatCtx ? 'hashcat' : 'john' }, S, source));
            _add_plaintext_credential(facts, ws, source, 'keepass_master', passK, C._domain_from_facts(ws), isHashcatCtx ? 'hashcat' : 'john', 'keepass');
            return;
          }
        }
      }

      var mMod = _CRACKED_MODULAR_RE.exec(line);
      if (mMod && C._valid_password(mMod.groups.pw.trim())) {
        var modRawUser = (mMod.groups.user || '').replace(/^.*[\\/]/, '');
        var modUser = C._clean_username(modRawUser) || 'cracked';
        if (!C._valid_username(modUser, false)) modUser = 'cracked';
        var modPw = mMod.groups.pw.trim();
        var modVia = isJohnCtx ? 'john' : 'hashcat';
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_hash', user: modUser, password: modPw, via: modVia }, S, source));
        _add_plaintext_credential(facts, ws, source, modUser, modPw, C._domain_from_facts(ws), modVia, 'crypt');
        return;
      }

      if (C._JWT_HASHCAT_RE) {
        var mJwt = C._JWT_HASHCAT_RE.exec(line);
        if (mJwt && C._valid_password(mJwt.groups.secret.trim())) {
          var jwtSec = mJwt.groups.secret.trim();
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'jwt_signing_secret', secret: jwtSec, password: jwtSec, via: isJohnCtx ? 'john' : 'hashcat' }, S, source));
          _add(facts, mkFact('web.jwt_secret', 'host:' + ws.target, { secret: jwtSec }, S, source));
          return;
        }
      }

      if (isHashcatCtx || !lc) {
        var mNet = _HASHCAT_NETNTLM_RE.exec(line);
        if (mNet && C._valid_password(mNet.groups.pw)) {
          var netUser = C._clean_username(mNet.groups.user);
          var netDom = (mNet.groups.domain || '').trim() || C._domain_from_facts(ws);
          if (C._valid_username(netUser, false)) {
            _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_netntlm', user: netUser, password: mNet.groups.pw, domain: netDom }, S, source));
            _add_plaintext_credential(facts, ws, source, netUser, mNet.groups.pw, netDom, 'hashcat', 'netntlm');
            return;
          }
        }
        var m = _HASHCAT_NTLM_RE.exec(line);
        if (m && C._valid_password(m.groups.pw) && !/^[0-9a-fA-F]{32}$/.test(m.groups.pw.trim())) {
          var nthash = m.groups.hash.toLowerCase();
          var cred = { kind: 'cracked_ntlm', nthash: nthash, password: m.groups.pw };
          var u = (m.groups.user ? C._clean_username(m.groups.user) : '') || _user_for_nthash(ws, nthash);
          if (u && C._valid_username(u, false)) cred.user = u;
          else u = '';
          var ntDom = (m.groups.domain || '').trim() || C._domain_from_facts(ws);
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, cred, S, source));
          _add_plaintext_credential(facts, ws, source, u || 'cracked', m.groups.pw, ntDom, 'hashcat_ntlm', 'ntlm');
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

      if (isJohnCtx && !zeroCracked && (textLow.indexOf('krb5tgs') >= 0 || textLow.indexOf('krb5asrep') >= 0) && reSearch(C._JOHN_CRACKED_FOOTER_RE, text)) {
        var jm = /^\?:(?<pw>.+)$/.exec(line);
        if (jm && C._valid_password(jm.groups.pw)) {
          var htype = textLow.indexOf('krb5tgs') >= 0 ? 'krb5tgs' : 'krb5asrep';
          var cr = { kind: 'cracked_' + htype, password: jm.groups.pw };
          var ur = _user_for_roast(ws, htype, facts);
          if (ur) cr.user = ur;
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, cr, S, source));
          _add_plaintext_credential(facts, ws, source, ur || 'cracked', jm.groups.pw, C._domain_from_facts(ws), 'john', htype);
          return;
        }
      }

      if (isJohnCtx && !zeroCracked && reSearch(C._JOHN_LOADED_RE, text)) {
        var lm = C._JOHN_CRACKED_LIVE_RE.exec(line);
        if (lm && lm.groups.pw.indexOf(':') < 0 && C._valid_password(lm.groups.pw.trim())) {
          var pwTrim = lm.groups.pw.trim();
          var lbl = lm.groups.label ? lm.groups.label.trim() : '';
          var huLive = (lbl.indexOf('$krb5') >= 0) ? _parse_hash_user(lbl) : ['', '', ''];
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target,
            { kind: 'cracked_secret', password: pwTrim, label: lbl, via: 'john' }, S, source));
          var cleanLbl = huLive[0] || (lbl ? lbl.replace(/^.*[\\/]/, '').replace(/\.(?:zip|rar|7z|pfx|p12|kdbx|pdf|docx?|xlsx?)$/i, '') : '');
          var urLive = (cleanLbl && cleanLbl !== '?' && C._valid_username(cleanLbl, false)) ? cleanLbl : (_user_for_roast(ws, 'krb5tgs', facts) || _user_for_roast(ws, 'krb5asrep', facts) || 'cracked');
          var htypeLive = huLive[2] || ((textLow.indexOf('krb5tgs') >= 0) ? 'krb5tgs' : (textLow.indexOf('krb5asrep') >= 0 ? 'krb5asrep' : ''));
          _add_plaintext_credential(facts, ws, source, urLive, pwTrim, huLive[1] || C._domain_from_facts(ws), 'john', htypeLive);
          return;
        }
      }

      if (!isJohnCtx || zeroCracked) return;
      if (lc.indexOf('--show') < 0 && !reSearch(C._JOHN_CRACKED_FOOTER_RE, text)) return;
      var sm = C._JOHN_SHOW_RE.exec(line);
      if (!sm) return;
      if (!C._valid_password(sm.groups.password)) return;
      var showUser = sm.groups.user.replace(/^.*[\\/]/, '');
      if (!C._valid_username(showUser, false)) showUser = 'cracked';
      _add_plaintext_credential(facts, ws, source, showUser, sm.groups.password, C._domain_from_facts(ws), 'john', '');
    });
  }
  C._parse_cracked_credentials = _parse_cracked_credentials;

  var _HYDRA_RE = /\[(?<port>\d{1,5})\]\[(?<svc>[A-Za-z][\w-]*)\][^\n]*?\blogin:\s*(?<user>\S+)\s+password:\s*(?<pw>\S.*?)\s*$/gim;
  var _MEDUSA_RE = /ACCOUNT FOUND:\s*\[(?<svc>[A-Za-z][\w-]*)\]\s+Host:\s*\S+\s+User:\s*(?<user>\S+)\s+Password:\s*(?<pw>\S.*?)\s+\[SUCCESS\]/gim;
  var _NCRACK_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\s+(?<port>\d{1,5})\/(?:tcp|udp)\s+(?<svc>[A-Za-z][\w-]*):\s*'(?<user>[^']+)'\s+'(?<pw>[^']+)'/gim;
  var _CROWBAR_RE = /SUCCESS:\s*\S+:(?<port>\d{1,5})\s*-\s*(?<user>[^:\s]+):(?<pw>\S+)/gim;
  function _parse_hydra(text, ws, command, source, facts) {
    var h = 'host:' + ws.target, m, seen = {}, n = 0;
    function addBrute(svc, port, user, pw, line) {
      var hostMatch = /\bhost:\s*(\S+)/i.exec(line || '') || /\bHost:\s*(\S+)/i.exec(line || '') || /(?:^|SUCCESS:\s*)(\d{1,3}(?:\.\d{1,3}){3})(?=[:\s])/i.exec(line || '');
      var lineTarget = C._observed_host ? C._observed_host(ws, hostMatch && hostMatch[1]) : (hostMatch ? hostMatch[1] : ws.target);
      var lineWs = Object.assign({}, ws, { target: lineTarget });
      var key = lineTarget + '|' + svc + '|' + user + '|' + pw;
      if (seen[key]) return;
      seen[key] = 1; n++;
      var cred = { user: user, password: pw, service: svc, port: port || 0, via: 'online-brute' };
      if (C._auth_observation) cred = C._auth_observation(lineWs, cred);
      var scope = 'host:' + lineTarget;
      _add(facts, mkFact('credential.available', scope, cred, S, source));
      _add(facts, mkFact('credential.plaintext', scope, cred, S, source));
      var observed = Object.assign({}, cred, { outcome: 'accepted' });
      delete observed.password;
      _add(facts, mkFact('credential.validated', scope, observed, S, source));
    }
    _HYDRA_RE.lastIndex = 0;
    while ((m = _HYDRA_RE.exec(text))) addBrute(m.groups.svc, +m.groups.port, m.groups.user, m.groups.pw, m[0]);
    _MEDUSA_RE.lastIndex = 0;
    while ((m = _MEDUSA_RE.exec(text))) addBrute(m.groups.svc, 0, m.groups.user, m.groups.pw, m[0]);
    _NCRACK_RE.lastIndex = 0;
    while ((m = _NCRACK_RE.exec(text))) addBrute(m.groups.svc, +m.groups.port, m.groups.user, m.groups.pw, m[0]);
    _CROWBAR_RE.lastIndex = 0;
    while ((m = _CROWBAR_RE.exec(text))) addBrute('rdp', +m.groups.port, m.groups.user, m.groups.pw, m[0]);
    return n;
  }
  C._parse_hydra = _parse_hydra;

  var _LSA_CLEARTEXT_RE = /^\s*(?:(?<domain>[A-Za-z0-9._-]+)\\)?(?<user>[A-Za-z0-9._$-]+):(?<pw>[^\r\n:]+)\s*$/gm;
  var _DPAPI_KEY_RE = /^\s*dpapi_(?<type>machinekey|userkey):(?<key>0x[0-9a-fA-F]{40,})\s*$/gmi;

  function _parse_ntlm_dump(text, ws, command, source, facts) {
    var entries = [], seen = {}, krbtgtNt = '', domCounts = {};
    reAll(C._NTDS_HASH_RE, text).forEach(function (m) {
      var user = C._clean_username(m.groups.user);
      if (!user) return;
      var nt = m.groups.nt.toLowerCase();
      if (nt === '31d6cfe0d16ae931b73c59d7e0c089c0' && (/^(?:guest|defaultaccount|wdagutilityaccount)$/i.test(user) || user.endsWith('$'))) return;
      var key = user.toLowerCase() + '|' + nt;
      if (seen[key]) return;
      seen[key] = true;
      var edom = (m.groups.domain || '').trim();
      entries.push({ user: user, rid: parseInt(m.groups.rid, 10), nthash: nt, domain: edom });
      if (edom && edom.indexOf('.') >= 0) domCounts[edom] = (domCounts[edom] || 0) + 1;
      if (user.toLowerCase() === 'krbtgt') krbtgtNt = nt;
    });
    if (/Dumping LSA Secrets|\[\*\]\s*(?:_SC_|DefaultPassword|\$MACHINE\.ACC|DPAPI_SYSTEM)/i.test(text)) {
      _DPAPI_KEY_RE.lastIndex = 0;
      var dm;
      while ((dm = _DPAPI_KEY_RE.exec(text)) !== null) {
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'dpapi_masterkey', key_type: dm.groups.type.toLowerCase(), key: dm.groups.key, via: 'lsa-secrets' }, S, source));
      }
      _LSA_CLEARTEXT_RE.lastIndex = 0;
      var lm;
      while ((lm = _LSA_CLEARTEXT_RE.exec(text)) !== null) {
        var lsaUser = C._clean_username(lm.groups.user);
        var lsaPw = (lm.groups.pw || '').trim();
        var lsaDom = (lm.groups.domain || '').trim();
        if (/^(?:dpapi_machinekey|dpapi_userkey|NL\$KM|plain_password_hex|aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5)$/i.test(lsaUser)) continue;
        if (/^0x[0-9a-fA-F]+$/i.test(lsaPw) || /^[0-9a-fA-F]{32,128}$/.test(lsaPw)) continue;
        if (C._valid_username(lsaUser, false) && C._valid_password(lsaPw)) {
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'lsa_secret', user: lsaUser, password: lsaPw, domain: lsaDom }, S, source));
          _add_plaintext_credential(facts, ws, source, lsaUser, lsaPw, lsaDom || C._domain_from_facts(ws), 'lsa-secrets', '');
        }
      }
    }
    if (!entries.length) return;
    var lowered = text.toLowerCase(), lc = command.toLowerCase();
    var ntdsContext = !!krbtgtNt || lc.indexOf('--ntds') >= 0 || lc.indexOf('-just-dc') >= 0 ||
      ['ntds.dit', 'drsuapi', 'dumping domain credentials'].some(function (mk) { return lowered.indexOf(mk) >= 0; });
    var dumpDomain = Object.keys(domCounts).sort(function (a, b) { return domCounts[b] - domCounts[a]; })[0] || '';
    var domainName = ntdsContext ? (dumpDomain || C._domain_from_facts(ws) || '') : '';
    var scope = domainName ? ('domain:' + domainName) : ('host:' + ws.target);
    _add(facts, mkFact('hash.ntlm', scope, { count: entries.length, entries: entries }, S, source));
    _add(facts, mkFact('credential.candidate', scope, { kind: 'ntlm_hash', count: entries.length }, S, source));
    if (krbtgtNt) _add(facts, mkFact('hash.krbtgt', scope, { nthash: krbtgtNt }, S, source));
    if (ntdsContext) {
      _add(facts, mkFact('loot.ntds', scope, { count: entries.length, method: 'credential-dump' }, S, source));
      var admin = entries.filter(function (e) { return e.rid === 500; })[0]
        || entries.filter(function (e) { return e.user.toLowerCase() === 'administrator'; })[0];
      if (admin && admin.nthash && admin.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
        var av = { user: admin.user, nthash: admin.nthash, method: 'dcsync', hash_type: 'ntlm', accountType: 'domain' };
        var adom = admin.domain || domainName;
        if (adom) av.domain = adom;
        _add(facts, mkFact('credential.available', scope, av, S, source));
      }
    } else {
      _add(facts, mkFact('loot.sam', 'host:' + ws.target, { count: entries.length, method: 'sam-dump' }, S, source));
      var localAdmin = entries.filter(function (e) { return e.rid === 500; })[0]
        || entries.filter(function (e) { return e.user.toLowerCase() === 'administrator'; })[0];
      if (localAdmin && localAdmin.nthash && localAdmin.nthash !== '31d6cfe0d16ae931b73c59d7e0c089c0') {
        var lav = { user: localAdmin.user, nthash: localAdmin.nthash, method: 'sam-dump', hash_type: 'ntlm', accountType: 'local', targetBinding: ws.target };
        _add(facts, mkFact('credential.available', 'host:' + ws.target, lav, S, source));
      }
    }
  }
  C._parse_ntlm_dump = _parse_ntlm_dump;

  function _looks_like_sam_dump(text) {
    if (!text) return false;
    return /^(?:[a-zA-Z0-9._$-]+:\d{3,5}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::)/m.test(text);
  }
  C._looks_like_sam_dump = _looks_like_sam_dump;

  var _MIMI_SIG_RE = /sekurlsa::|lsadump::|crypto::capi|mimikatz\s+#|pypykatz|^Hash NTLM:|Authentication Id\s*:[\s\S]{1,400}?(?:\bmsv\s*:|\bwdigest\s*:|\bkerberos\s*:|\*\s*NTLM\s*:)/im;
  var _MIMI_USERNAME_RE = /^\s*\*\s*Username\s*:\s*(?<user>.+?)\s*$/i;
  var _MIMI_LSA_USER_RE = /^\s*User\s*:\s*(?<user>.+?)\s*$/i;
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
        if (u.indexOf('\\') >= 0) curDomain = u.split('\\')[0].trim();
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
        if (/^(?:[0-9a-fA-F]{2}\s+){3,}[0-9a-fA-F]{2}$/.test(pw)) return;
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
    if (lc.indexOf('lsadump') >= 0 || lowered.indexOf('lsadump::') >= 0) {
      _add(facts, mkFact('loot.ntds', h, { count: entries.length, method: 'lsadump' }, S, source));
    }
  }
  C._parse_mimikatz = _parse_mimikatz;

  var _DCC2_RE = /\$DCC2\$\d+#([^#\s:]+)#([0-9a-fA-F]{32})(?::([^\s:]+))?\b/g;
  function _looks_like_mscache(text) { return !!text && text.indexOf('$DCC2$') >= 0; }
  C._looks_like_mscache = _looks_like_mscache;

  function _parse_mscache(text, ws, command, source, facts) {
    if (!text || text.indexOf('$DCC2$') < 0) return;
    text = text.replace(C._ANSI_RE, '');
    var h = 'host:' + ws.target, entries = [], seen = {}, m;
    _DCC2_RE.lastIndex = 0;
    while ((m = _DCC2_RE.exec(text)) !== null) {
      if (m[3]) continue;
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

  var _RESPONDER_HASH_RE = /NTLMv[12](?:-SSP)? Hash\s*:\s*(?<hash>(?<user>[^:\s]+)::[^\s]+:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]+:[0-9A-Fa-f]+)/i;

  function _parse_responder(text, ws, source, facts) {
    var users = [];
    var isV1 = /NTLMv1(?:-SSP)? Hash/i.test(text);
    reAll(_RESPONDER_HASH_RE, text).forEach(function (m) {
      if (users.indexOf(m.groups.user) < 0) users.push(m.groups.user);
    });
    if (!users.length) return;
    var value = { kind: isV1 ? 'netntlmv1' : 'netntlmv2', via: 'responder', count: users.length, users: users.slice(0, 20) };
    _add(facts, mkFact('credential.candidate', 'host:' + ws.target, value, S, source));
    _add(facts, mkFact('credential.netntlm', 'host:' + ws.target, value, S, source));
  }
  C._parse_responder = _parse_responder;

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

  var _GENERIC_CRED_BLOCK_RE = /(?:^\s*Domain\s*:\s*(?<dom>[^\r\n]+)\s*\r?\n\s*)?^\s*User(?:name)?\s*:\s*(?<user>[^\r\n]+)\s*\r?\n\s*(?:Domain\s*:\s*(?<dom2>[^\r\n]+)\s*\r?\n\s*)?Password\s*:\s*(?<pw>[^\r\n]+)/gim;
  var _CMD_CRED_RE = /(?:^|\s|\/)(?:-u|--user|-username|--username|\/u|\/user)[:=\s]+['"]?(?<user>[a-zA-Z0-9._-]+)['"]?\s+(?:-p|--password|-pass|--pass|\/p|\/pass|\/password)[:=\s]+['"]?(?<pw>(?!-)[^\s'"]+)['"]?/gi;
  var _ATTACKER_CMD_LINE_RE = /^\s*(?:(?:\$|\#|└─\$|┌──|\[\*\]|\[\+\]|\[\-\]|PS\s+[A-Za-z]:\\[^>]*>|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^$#]*[$#])\s*)*(?:sudo\s+|proxychains\d?\s+)*(?:nxc|netexec|crackmapexec|cme|impacket-[\w.-]+|evil-winrm|xfreerdp|rdesktop|hydra|medusa|ncrack|sqlmap|gobuster|ffuf|feroxbuster|dirsearch|wfuzz|curl|wget|smbclient|smbmap|rpcclient|ldapsearch|bloodyAD|certipy|kerbrute|responder)\b/i;
  var _JSON_CRED_RE = /"(?:username|user)"\s*:\s*"(?<user>[^"]+)"[\s\S]{1,120}?"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"/gi;
  var _JSON_CRED_REV_RE = /"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"[\s\S]{1,120}?"(?:username|user)"\s*:\s*"(?<user>[^"]+)"/gi;
  var _URL_CRED_RE = /https?:\/\/(?<user>[a-zA-Z0-9._-]+):(?<pw>[^@\s'"]+)@/gi;
  var _KEEPASS_DUMP_RE = /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _MREMOTENG_DECRYPT_RE = /^\s*(?<user>[a-zA-Z0-9._$-]{1,64})@(?<host>[a-zA-Z0-9._-]{1,64})(?::\d+)?\s*\|\s*password\s+is:\s*(?<pw>\S+)/gim;
  var _CISCO_CONFIG_CRED_RE = /^\s*username\s+(?<user>[a-zA-Z0-9._-]+)(?:\s+privilege\s+\d+)?\s+(?:password\s+0|secret\s+0|password)\s+['"]?(?<pw>[^\r\n\s'"]+)['"]?/gmi;
  var _CISCO_DECRYPT_OUTPUT_RE = /(?:cisco-decrypt|decrypted\s*(?:cisco)?\s*password)\s*[:=->]\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _CONN_STRING_USER_RE = /(?:User ID|UID)\s*=\s*['"]?(?<user>[a-zA-Z0-9._-]+)['"]?/gi;
  var _CONN_STRING_PASS_RE = /(?:Password|PWD)\s*=\s*['"]?(?<pw>[^;'"\r\n]+)['"]?/gi;
  var _NOSQL_EXTRACT_RE = /(?:(?:extracted|recovered|found)\s*(?:nosql|user|admin|db)?\s*(?:password|passwd|creds?)\s*[:=->]|\[\+\]\s*(?:password|extracted)\s*[:=->])\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _PRTG_DBPASS_RE = /<(?:dbpassword|dbpass)>(?:<text>)?(?<pw>[^<]+)(?:<\/text>)?<\/(?:dbpassword|dbpass)>/gi;
  var _AMPORTAL_PASS_RE = /^\s*(?:AMPDBPASS|AMPMGRPASS)\s*=\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gmi;
  var _COLDFUSION_HASH_RE = /^\s*(?:password|encryptedPassword)\s*=\s*['"]?(?<hash>[a-fA-F0-9]{40})['"]?/gmi;
  var _ODAT_CRED_RE = /\[\+\]\s+Valid credentials found:\s*(?<user>[a-zA-Z0-9_$]+)\/(?<pw>\S+)/gi;

  function _looks_like_password_hash(s) {
    if (!s) return false;
    return /^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|\*[0-9a-fA-F]{40}|\$(?:1|2[abxy]|5|6|y|apr1|P|H|pbkdf2[^$]*|argon2[id]*)\$[^\s]+)$/.test(s);
  }

  function _looks_like_generic_dumped_credentials(text) {
    return !!text && (
      /(?:^\s*Domain\s*:\s*[^\r\n]+\s*\r?\n\s*)?^\s*User(?:name)?\s*:\s*[^\r\n]+\s*\r?\n\s*(?:Domain\s*:\s*[^\r\n]+\s*\r?\n\s*)?Password\s*:\s*[^\r\n]+/im.test(text) ||
      /(?:^|\s|\/)(?:-u|--user|-username|--username|\/u|\/user)[:=\s]+['"]?[a-zA-Z0-9._-]+['"]?\s+(?:-p|--password|-pass|--pass|\/p|\/pass|\/password)[:=\s]+['"]?(?!-)[^\s'"]+['"]?/i.test(text) ||
      /"(?:username|user)"\s*:\s*"[^"]+"[\s\S]{1,120}?"(?:password|pass)"\s*:\s*"[^"]+"/i.test(text) ||
      /"(?:password|pass)"\s*:\s*"[^"]+"[\s\S]{1,120}?"(?:username|user)"\s*:\s*"[^"]+"/i.test(text) ||
      /https?:\/\/[a-zA-Z0-9._-]+:[^@\s'"]+@/i.test(text) ||
      /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*[^\r\n]+/i.test(text) ||
      /^\s*[a-zA-Z0-9._$-]{1,64}@[a-zA-Z0-9._-]{1,64}(?::\d+)?\s*\|\s*password\s+is:/im.test(text) ||
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
    var hScope = 'host:' + ws.target;
    for (var i = 1; i < lines.length; i++) {
      var row = lines[i].split(sep).map(function (c) { return c.replace(/^["']|["']$/g, '').trim(); });
      if (row.length <= Math.max(userIdx, passIdx)) continue;
      var u = C._clean_username(row[userIdx]);
      var p = (row[passIdx] || '').trim();
      if (!C._valid_username(u, false)) continue;
      if (_looks_like_password_hash(p)) {
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'db_hash', user: u, hash: p, via: 'db_csv_dump' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: u, hash: p, via: 'db_csv_dump' }, S, source));
        _add(facts, mkFact('loot.material', hScope, { kind: 'db_hashes', user: u, hash: p }, S, source));
      } else if (C._valid_password(p)) {
        _add_plaintext_credential(facts, ws, source, u, p, C._domain_from_facts(ws), 'db_csv_dump', '');
      }
    }
  }

  function _parse_generic_dumped_credentials(text, ws, command, source, facts) {
    if (!text) return;
    text = text.replace(C._ANSI_RE, '');
    var hScope = 'host:' + ws.target;
    _GENERIC_CRED_BLOCK_RE.lastIndex = 0;
    var m;
    while ((m = _GENERIC_CRED_BLOCK_RE.exec(text)) !== null) {
      var rawUser = (m.groups.user || '').trim();
      var dom = (m.groups.dom || m.groups.dom2 || '').trim();
      if (rawUser.indexOf('\\') >= 0) {
        var parts = rawUser.split('\\');
        if (!dom) dom = parts[0].trim();
        rawUser = parts.slice(1).join('\\');
      }
      var user = C._clean_username(rawUser);
      var pw = (m.groups.pw || '').trim();
      if (!C._valid_username(user, false)) continue;
      if (_looks_like_password_hash(pw)) {
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'dumped_hash', user: user, hash: pw, via: 'dump' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: user, hash: pw, via: 'dump' }, S, source));
        continue;
      }
      if (!C._valid_password(pw)) continue;
      _add_plaintext_credential(facts, ws, source, user, pw, dom || C._domain_from_facts(ws), 'dump', '');
    }

    if (!/access denied|authentication fail|logon failure|login failed|STATUS_LOGON_FAILURE|ERROR 1045/i.test(text)) {
      text.split(/\r?\n/).forEach(function (line) {
        if (_ATTACKER_CMD_LINE_RE.test(line)) return;
        _CMD_CRED_RE.lastIndex = 0;
        var cm;
        while ((cm = _CMD_CRED_RE.exec(line)) !== null) {
          var cUser = C._clean_username(cm.groups.user);
          var cPw = (cm.groups.pw || '').trim();
          if (!C._valid_username(cUser, false) || !C._valid_password(cPw)) continue;
          _add_plaintext_credential(facts, ws, source, cUser, cPw, C._domain_from_facts(ws), 'process-leak', '');
        }
      });
    }

    _JSON_CRED_RE.lastIndex = 0;
    var jm;
    while ((jm = _JSON_CRED_RE.exec(text)) !== null) {
      var jUser = C._clean_username(jm.groups.user);
      var jPw = (jm.groups.pw || '').trim();
      if (!C._valid_username(jUser, false)) continue;
      if (_looks_like_password_hash(jPw)) {
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'api_hash', user: jUser, hash: jPw, via: 'api-leak' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: jUser, hash: jPw, via: 'api-leak' }, S, source));
        continue;
      }
      if (!C._valid_password(jPw)) continue;
      _add_plaintext_credential(facts, ws, source, jUser, jPw, C._domain_from_facts(ws), 'api-leak', '');
    }
    _JSON_CRED_REV_RE.lastIndex = 0;
    while ((jm = _JSON_CRED_REV_RE.exec(text)) !== null) {
      var jrUser = C._clean_username(jm.groups.user);
      var jrPw = (jm.groups.pw || '').trim();
      if (!C._valid_username(jrUser, false)) continue;
      if (_looks_like_password_hash(jrPw)) {
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'api_hash', user: jrUser, hash: jrPw, via: 'api-leak' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: jrUser, hash: jrPw, via: 'api-leak' }, S, source));
        continue;
      }
      if (!C._valid_password(jrPw)) continue;
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

    if (!/^\s*(?:SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+/im.test(text) && !/gpp_password|gpp-decrypt/i.test((command || '') + ' ' + (source || ''))) {
      _NOSQL_EXTRACT_RE.lastIndex = 0;
      var nsm;
      while ((nsm = _NOSQL_EXTRACT_RE.exec(text)) !== null) {
        var nsPw = (nsm.groups.pw || '').trim();
        if (C._valid_password(nsPw)) {
          _add_plaintext_credential(facts, ws, source, 'admin', nsPw, C._domain_from_facts(ws), 'nosql-blind', '');
        }
      }
    }
  }
  C._parse_generic_dumped_credentials = _parse_generic_dumped_credentials;

  var _FLAG_MARK_RE = /===FLAG:\s*(?<path>[^\r\n]*?)::(?<body>[^\r\n]*)/g;
  var _FLAG_TOKEN = '(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64}|(?:HTB|FLAG|THM|OSCP|PG|CTF)\\{[^}\\r\\n]{3,}\\}|\\{[0-9A-Za-z_@!#%.:\\-]{3,}\\}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})';
  var _FLAG_VALUE_ANCHORED = new RegExp('^' + _FLAG_TOKEN + '$', 'i');
  var _FLAG_FILE_IN_CMD_RE = /(?:\btype\b|\bcat\b|\bmore\b|\bhead\b|\btail\b|\bbat\b|\bless\b|\bgrep\b|Get-Content|\bgc\b|Select-String)\s+[^\r\n|]*?(?<file>(?:[a-zA-Z0-9._-]+\.txt:)?(?:local|proof|user|root|flag\d?)\.txt)/i;
  var _REMOTE_LEAD_RE = /^\s*(?:(?:sudo|command|exec|proxychains\d?|stdbuf|timeout|doas)\s+(?:-\S+\s+|\S+=\S+\s+)*|\w+=\S+\s+)*(?:nxc|netexec|crackmapexec|cme|impacket-[\w.]+|wmiexec(?:\.py)?|smbexec(?:\.py)?|atexec(?:\.py)?|dcomexec(?:\.py)?|psexec(?:\.py)?|smbclient|smbmap|winrs|evil-winrm|ssh|sshpass|plink|xfreerdp|rdesktop|rpcclient)\b/i;
  function _slot_for_flagfile(name) {
    var n = (name || '').toLowerCase();
    if (/proof\.txt|root\.txt/.test(n)) return 'root';
    if (/local\.txt|user\.txt/.test(n)) return 'local';
    return 'flag';
  }
  function _flag_kind(slot) { return slot === 'root' ? 'objective.root_flag' : (slot === 'local' ? 'objective.local_flag' : 'objective.flag'); }
  var _SPIDER_PATH_RE = /(?:\/\/|\\\\)[^\s/\\]+[/\\](?:([A-Za-z])\$|Users)[/\\]([^\s\[\]"']*?(?:local|proof|user|root|flag\d?)\.txt)(?=\s|$|\[|"|')/gi;
  function _strip_prompt(line) {
    return String(line)
      .replace(/^\s*(?:(?:SMB|WINRM|WMI|RPC|SSH|RDP|MSSQL)\s+\S+\s+\d+\s+\S+\s+)/i, '')
      .replace(/^\s*\*?Evil-WinRM\*?\s*PS\s+[A-Za-z]:\\[^>\r\n]*>\s*/i, '')
      .replace(/^\s*PS\s+[A-Za-z]:\\[^>\r\n]*>\s*/i, '')
      .replace(/^\s*[A-Za-z]:\\[^>\r\n]*>\s*/, '')
      .replace(/^\s*[└├]─?[$#]\s*/, '')
      .replace(/^\s*[\w.-]+@[\w.-]+:[^$#\r\n]*[$#]\s*/, '')
      .replace(/^\s*[$#]\s+/, '');
  }
  function _parse_flags(text, ws, command, source, facts) {
    var scope = 'host:' + ws.target, seen = {}, seenPath = {};
    var cmdRemote = !!(command && String(command).trim()) && _REMOTE_LEAD_RE.test(command);
    var hay = (text || '') + '\n' + (command || '');
    var isBulkEnumNoise = /Linux Privilege Escalation Awesome Script|linpeas|winpeas|══╣|\/etc\/machine-id|blkid|fstab|Dumping Domain Credentials|sekurlsa::/i.test(hay);
    var hasFlagFilenameCtx = /\b(?:local|proof|user|root|flag\d?)\.txt\b/i.test(hay) || /flag-hunt/i.test(String(source || '') + ' ' + String(command || ''));
    var hasRootCtx = /\b(?:proof\.txt|root\.txt)\b/i.test(hay) || (!isBulkEnumNoise && (/\b(?:uid=0\(root\)|nt authority\\system)\b/i.test(hay) || /^(?:root|nt authority\\system)\s*$/im.test(text || '')));
    function mint(path, flag, slotHint, onHost) {
      if (!flag || seen[flag]) return;
      seen[flag] = 1;
      var base = String(path || '').split(/[\\/]/).pop() || '';
      var slot = slotHint || _slot_for_flagfile(base);
      var isExec = command && /-[xX]\b|wmiexec|psexec|smbclient.*get/i.test(command);
      var kind = (onHost || isExec) ? _flag_kind(slot) : 'objective.flag_located';
      _add(facts, mkFact(kind, scope, { flag: flag, slot: slot, name: base, path: path || '' }, S, source));
      if (kind === 'objective.local_flag' || kind === 'objective.root_flag' || kind === 'objective.flag') {
        _add(facts, mkFact('proof.captured', scope, {
          kind: kind,
          slot: slot,
          flag: flag,
          name: base,
          path: path || '',
          interactive_ok: true,
          identity_ok: true,
          block: String(text || '').trim().slice(0, 4000),
        }, S, source));
      }
    }
    function mintPath(path, slot) {
      if (!path) return;
      var rawPath = String(path).trim();
      var isPosix = rawPath.charAt(0) === '/' && rawPath.charAt(1) !== '/';
      var clean = isPosix ? rawPath.replace(/\/+/g, '/') : rawPath.replace(/[/\\]+/g, '\\');
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
    var m; _FLAG_MARK_RE.lastIndex = 0;
    while ((m = _FLAG_MARK_RE.exec(text))) {
      var body = (m.groups.body || '').trim();
      if (_FLAG_VALUE_ANCHORED.test(body)) {
        mint(m.groups.path, body, _slot_for_flagfile(m.groups.path), true);
        mintPath(m.groups.path, _slot_for_flagfile(m.groups.path));
      }
    }
    var curFile = null, curSlot = null, curOnHost = false;
    var fm = _FLAG_FILE_IN_CMD_RE.exec(command || '');
    if (fm) { curFile = fm.groups.file; curSlot = _slot_for_flagfile(curFile); curOnHost = !cmdRemote; }
    var trimmedWhole = String(text || '').trim();
    var allLines = String(text || '').split(/\r?\n/);
    var hasUserCtx = hasFlagFilenameCtx || /^[0-9a-fA-F]{32}$/.test(trimmedWhole) || (!isBulkEnumNoise && allLines.length <= 25 && /\b(?:whoami|ip\s+a|ifconfig|ipconfig)\b/i.test(hay));
    allLines.forEach(function (l) {
      var bare = _strip_prompt(l);
      var flagMarkHdr = /^===FLAG:\s*([^\r\n]+?)::\s*(.*)$/i.exec(bare.trim());
      if (flagMarkHdr) {
        var fmPath = flagMarkHdr[1].trim();
        var fmBody = (flagMarkHdr[2] || '').trim();
        var fmSlot = _slot_for_flagfile(fmPath);
        mintPath(fmPath, fmSlot);
        if (fmBody && _FLAG_VALUE_ANCHORED.test(fmBody)) {
          mint(fmPath, fmBody, fmSlot, true);
          curFile = null; curSlot = null;
        } else {
          curFile = fmPath;
          curSlot = fmSlot;
          curOnHost = true;
        }
        return;
      }
      var dashHdr = /^---\s*(\/(?:[^/\r\n]+\/)+(?:local|proof|user|root|flag\d?)\.txt|[A-Za-z]:[\\/](?:[^\\/\r\n]+[\\/])+(?:local|proof|user|root|flag\d?)\.txt)\s*---$/i.exec(bare.trim());
      if (dashHdr) {
        curFile = dashHdr[1];
        curSlot = _slot_for_flagfile(curFile);
        curOnHost = !cmdRemote;
        mintPath(curFile, curSlot);
        return;
      }
      var fx = _FLAG_FILE_IN_CMD_RE.exec(bare);
      if (fx) { curFile = fx.groups.file; curSlot = _slot_for_flagfile(curFile); curOnHost = !_REMOTE_LEAD_RE.test(bare); return; }
      var tok = bare.trim();
      if (l !== bare && tok && !_FLAG_VALUE_ANCHORED.test(tok)) {
        curFile = null; curSlot = null;
      }
      if (curFile && _FLAG_VALUE_ANCHORED.test(tok)) {
        mint(curFile, tok, curSlot, curOnHost);
        curFile = null; curSlot = null;
      } else if (!curFile && _FLAG_VALUE_ANCHORED.test(tok)) {
        if (/^(?:HTB|FLAG|THM|OSCP|PG|CTF)\{[^}\r\n]{3,}\}$/i.test(tok)) {
          mint(hasRootCtx ? 'proof.txt' : 'user.txt', tok, hasRootCtx ? 'root' : 'local', true);
        } else if (/^[0-9a-fA-F]{32}$/.test(tok) && !isBulkEnumNoise) {
          if (hasRootCtx && (hasFlagFilenameCtx || allLines.length <= 25)) {
            mint('proof.txt', tok, 'root', true);
          } else if (hasUserCtx) {
            mint('local.txt', tok, 'local', true);
          }
        }
      }
    });
    // 3) LOCATE: a spider/dir listing of flag-file paths (no value) -> record each location + its exact path.
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
    // prompt is stripped), so a `type ...\user.txt` command echo or an `===FLAG:` marker is never caught here.
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
  var _KEEPASS_KDBX_RE = /\b(?!PATTERN\.kdbx\b)[A-Za-z0-9_$-][A-Za-z0-9_.\-]*\.kdbx\b/i;
  var _KEEPASS_HASH_RE = /\$keepass\$\*\d/i;
  var _KEEPASS_DUMP_RE = /\bkeepass[\w.]*\.(?:dmp|dump)\b|masterkey(?:\.txt)?\b.*keepass|keepass.*master\s*key/i;
  function _parse_keepass_dump(text, ws, command, source, facts) {
    if (!text && !command) return;
    var cleanLines = String(text || '').split(/\r?\n/).filter(function (ln) {
      return !/(?:spider_plus|PATTERN|\.kdbx['"]?\s*(?:-o|2>|\)|$)|-name\s+['"]?\*\.kdbx)/i.test(ln);
    }).join('\n');
    var cmdHay = /\b(?:spider_plus|find|dir|where|get-childitem)\b/i.test(command || '') ? '' : String(command || '');
    var hay = cleanLines + '\n' + cmdHay;
    var m = reSearch(_KEEPASS_HASH_RE, hay) || reSearch(_KEEPASS_KDBX_RE, hay) || reSearch(_KEEPASS_DUMP_RE, hay);
    if (!m) return;
    var h = 'host:' + ws.target;
    var kdbx = reSearch(_KEEPASS_KDBX_RE, hay);
    _add(facts, mkFact('loot.keepass_dump', h, { file: kdbx ? kdbx[0] : null, has_hash: !!reSearch(_KEEPASS_HASH_RE, hay), via: 'keepass' }, S, source));
  }
  C._parse_keepass_dump = _parse_keepass_dump;

  // Hash identifier output (hashid, hash-identifier, Name-That-Hash / nth, haiti): mints hash.type
  function _parse_hash_identify(text, ws, command, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var types = [], modes = {};
    var isHashIdCtx = /Possible Hashs?|Least Possible|Hash-Identifier|Analyzing\s+['"]?[0-9a-fA-F$]|Hashcat Mode/i.test(text) ||
      /\b(?:hashid|hash-identifier|nth|name-that-hash|haiti)\b/i.test(command || '');
    var mPlus = reAll(/^\s*\[\+\]\s*([A-Za-z0-9_.\-/ ()]+?)(?:\s*\[Hashcat Mode:\s*(\d+)\])?\s*$/gm, text);
    mPlus.forEach(function (m) {
      if (!m[2] && !isHashIdCtx) return;
      var t = m[1].trim();
      if (/^(?:Saving|Dumping|Impersonating|Found|Trying|Target|Authenticated|Connected|Using|Got|Success|Valid)\b/i.test(t)) return;
      if (t && types.indexOf(t) < 0) types.push(t);
      if (m[2]) modes[t] = parseInt(m[2], 10);
    });
    var mHc = reAll(/Hashcat(?:\s+Mode)?\s*[:#]?\s*(\d{1,5})\b/gi, text);
    mHc.forEach(function (m) {
      var mode = parseInt(m[1], 10);
      if (!isNaN(mode) && types.indexOf('mode:' + mode) < 0) types.push('mode:' + mode);
    });
    var mNth = reAll(/(?:Most Likely|Possible\s+types?)\s*[:\r\n]+\s*(?:-\s*)?([A-Za-z0-9_.\-/ ()]+)/gi, text);
    mNth.forEach(function (m) {
      var t = m[1].trim();
      if (t && types.indexOf(t) < 0) types.push(t);
    });
    if (types.length) {
      _add(facts, mkFact('hash.type', h, { types: types.slice(0, 10), modes: modes, via: 'hashid' }, S, source));
    }
  }
  C._parse_hash_identify = _parse_hash_identify;

  // IKE Aggressive Mode PSK hash output (ike-scan -A -P): mints hash.ike_psk and credential.candidate
  function _parse_ike_psk(text, ws, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var m = reSearch(/IKE PSK parameters[^\r\n]*?:\s*([0-9a-fA-F:]{40,})/i, text) ||
      reSearch(/^([0-9a-fA-F]+(?::[0-9a-fA-F]+){8})$/m, text);
    if (!m) return;
    var pskHash = m[1].trim();
    _add(facts, mkFact('hash.ike_psk', h, { hash: pskHash, via: 'ike-scan' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { username: 'ike-psk', hash: pskHash, kind: 'ike_psk', via: 'ike-scan' }, C.ProofState.PARTIAL, source));
  }
  C._parse_ike_psk = _parse_ike_psk;

  // IPMI 2.0 RAKP hash dump (metasploit ipmi_dumphashes, impacket, hashcat 7300 format): mints hash.candidate and credential.candidate
  function _parse_ipmi_rakp(text, ws, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var m = reSearch(/(?:\$rakp\$[^\s]+|([A-Za-z0-9_.-]+):([0-9a-fA-F]{40,}:[0-9a-fA-F]{40}))/i, text) ||
      reSearch(/RAKP-(?:HMAC-SHA1|Hash)[^:\r\n]*:\s*([^\r\n]+)/i, text);
    if (!m) return;
    var raw = (m[2] ? (m[1] + ':' + m[2]) : (m[1] || m[0])).trim();
    var user = m[1] && m[2] ? m[1] : 'admin';
    _add(facts, mkFact('hash.candidate', h, { user: user, hash: raw, format: 'rakp', hashcat_mode: 7300, via: 'ipmi' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { username: user, hash: raw, kind: 'ipmi_rakp', via: 'ipmi' }, C.ProofState.PARTIAL, source));
  }
  C._parse_ipmi_rakp = _parse_ipmi_rakp;

})(typeof globalThis !== 'undefined' ? globalThis : this);
