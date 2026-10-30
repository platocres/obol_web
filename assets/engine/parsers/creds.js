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

  var _HASHCAT_NTLM_RE = /^(?:(?:(?<domain>[^\\:\s]+)\\)?(?<user>[^:\s$]+):)?(?:\$NT\$)?(?<hash>[0-9a-fA-F]{16}|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})(?::(?<salt>[A-Za-z0-9./+$=_-]{1,64}))?:(?<pw>[^\r\n:]+)$/;
  var _HASHCAT_NETNTLM_RE = /^(?<user>[a-zA-Z0-9._$-]+)::(?<domain>[^:]*):[0-9a-fA-F:]+:(?<pw>[^\r\n]+)$/;
  var _HASHCAT_IPMI_RE = /^(?:[0-9a-fA-F]+:)?(?:(?<user>[a-zA-Z0-9._-]+):)?[0-9a-fA-F]{16,}:[0-9a-fA-F]{16,}:(?<pw>[^\r\n:]+)$/;
  var _CRACKED_DCC2_RE = /^(?:[^:\s]+:)?\$DCC2\$\d+#(?<user>[^#]+)#(?<hash>[0-9a-fA-F]{32}):(?<pw>[^\r\n]+)$/i;
  var _CRACKED_MODULAR_RE = /^(?:(?<user>[^:\s$]+):)?(?<hash>(?:\$(?:1|2[abxy]|5|6|y|apr1|P|H|S|pbkdf2[^$]*|pfx|pkzip2?|zip2|rar\d?|7z|office|pdf|sshng|ansible|PEM|keepass)\$[^\s:]+|pbkdf2_sha(?:1|256|512)\$\d+\$[^\s:]+|sha(?:1|256|512):\d+:[^:\s]+:[^:\s]+)):(?<pw>[^\r\n:]+)$/i;
  var _CRACKED_FILE_RE = /^\s*(?<file>[A-Za-z0-9_.-]+\.(?:psafe3|kdbx|pfx|p12|zip|rar|7z|pdf|docx?|xlsx?)):(?<pw>[^\r\n:]+)\s*$/i;

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
    _add(facts, mkFact('credential.password', scope, value, S, source));
    _add(facts, mkFact('credential.available', scope, value, S, source));
    // Recovery proves possession only. Authentication and privilege need service evidence.
  }
  C._add_plaintext_credential = _add_plaintext_credential;

  function _bind_bare_hashcat_target(ws, text, command, currentFacts) {
    var htLineM = /Hash\.Target\.+:\s*([^\r\n]+)/i.exec(text || '');
    var htVal = htLineM ? htLineM[1].trim() : '';
    if (htVal) {
      if (/\$krb5(?:asrep|tgs)\$/i.test(htVal)) {
        var hu = _parse_hash_user(htVal);
        var rt = /\$krb5tgs\$/i.test(htVal) ? 'krb5tgs' : 'krb5asrep';
        return { user: hu[0] || _user_for_roast(ws, rt, currentFacts), domain: hu[1] || '', type: rt };
      }
      var netM = /^([A-Za-z0-9_.$-]+)::([^:\s]*):/.exec(htVal);
      if (netM && C._valid_username(C._clean_username(netM[1]), false)) {
        return { user: C._clean_username(netM[1]), domain: netM[2] || '', type: 'netntlm' };
      }
    }
    var pool = [].concat((ws && (ws.seedFacts || ws.facts || ws.existing_facts)) || [], currentFacts || []);
    for (var i = pool.length - 1; i >= 0; i--) {
      var f = pool[i];
      if (!f || !f.value) continue;
      var v = f.value;
      if (f.kind === 'credential.netntlm') {
        var nu = C._clean_username((v.users && v.users[0]) || v.user || '');
        if (nu && C._valid_username(nu, false)) return { user: nu, domain: v.domain || '', type: v.kind || 'netntlmv2' };
      }
      if (f.kind === 'hash.tgs' || f.kind === 'hash.asrep') {
        var ru = C._clean_username(v.user || (v.users && v.users[0]) || '');
        if (ru && C._valid_username(ru, false)) return { user: ru, domain: v.domain || '', type: f.kind === 'hash.tgs' ? 'krb5tgs' : 'krb5asrep' };
      }
      if (f.kind === 'hash.crackable' || f.kind === 'hash.candidate') {
        var cu = C._clean_username(v.user || v.username || '');
        if (cu && C._valid_username(cu, false)) return { user: cu, domain: v.domain || '', type: v.format || 'hash' };
      }
    }
    var knownUsers = {};
    for (var ki = 0; ki < pool.length; ki++) {
      var kf = pool[ki];
      if (!kf || !kf.value) continue;
      if ((kf.kind === 'ad.user_list' || kf.kind === 'web.users') && Array.isArray(kf.value.users)) {
        kf.value.users.forEach(function (u) { if (u) knownUsers[String(u).toLowerCase()] = String(u); });
      } else if (kf.kind === 'credential.candidate' && kf.value.user) {
        knownUsers[String(kf.value.user).toLowerCase()] = String(kf.value.user);
      }
    }
    var fileHay = (htVal ? htVal + ' ' : '') + (command || '');
    var fileMatches = reAll(/(?:^|[\s/\\'"])([A-Za-z0-9_.$-]{2,32})\.(?:hash|hashes|ntlmv2|netntlm|tgs|asrep|krb5?|txt)\b/gi, fileHay);
    for (var fi = 0; fi < fileMatches.length; fi++) {
      var stem = C._clean_username(fileMatches[fi][1]);
      if (!stem || /^(?:hash|hashes|tgs|asrep|krb5?|ntlm|ntlmv2|netntlm|crack|cracked|out|output|rockyou|wordlist|users|passwords|kerberoast|asreproast|dump)$/i.test(stem)) continue;
      if (knownUsers[stem.toLowerCase()]) return { user: knownUsers[stem.toLowerCase()], domain: C._domain_from_facts(ws) || '', type: 'hashcat' };
      if (C._valid_username(stem, false)) return { user: stem, domain: C._domain_from_facts(ws) || '', type: 'hashcat' };
    }
    return { user: '', domain: C._domain_from_facts(ws) || '', type: 'hashcat' };
  }

  var _HASHCAT_STATUS_NOISE_RE = /^(?:hashcat\b|OpenCL\b|CUDA\b|HIP\b|Metal\b|Backend\b|Minimum\b|Maximum\b|Counting\b|Compared\b|Hashes:\s|Bitmaps:\s|Rules:\s|Applicable\b|Optimizers\b|Watchdog:\s|Host memory\s|Dictionary cache\s|Approaching final keyspace|Session\.+:|Status\.+:|Hash\.(?:Mode|Target)\.+:|Time\.(?:Started|Estimated)\.+:|Kernel\.Feature\.+:|Guess\.(?:Base|Queue|Mod|Mask)\.+:|Speed\.#\d+\.+:|Recovered\.+:|Progress\.+:|Rejected\.+:|Restore\.(?:Point|Sub\.#\d+)\.+:|Candidate\.Engine\.+:|Candidates\.#\d+\.+:|Hardware\.Mon\.#\d+\.+:|Started:\s|Stopped:\s|\*\s*Device\s*#\d+|\[\s*s\s*\]\s*tatus)/i;

  function _parse_cracked_credentials(text, ws, command, source, facts) {
    var factsBefore = facts.length;
    var lc = (command || '').toLowerCase();
    var textLow = text.toLowerCase();
    var isHashcatCtx = lc.indexOf('hashcat') >= 0 || /Status\.+:\s*Cracked|Session\.+:\s*hashcat/i.test(text);
    var johnDoneFooter = /^\s*[1-9]\d*g\s+\d+:\d{2}:\d{2}:\d{2}\s+DONE\b|\bUse the "--show" option to display all of the cracked passwords\b/im.test(text);
    var isJohnCtx = lc.indexOf('john') >= 0 || !!reSearch(C._JOHN_LOADED_RE, text) || !!reSearch(C._JOHN_CRACKED_FOOTER_RE, text) || johnDoneFooter;
    var zeroCracked = /\b0\s+password\s+hash(?:es)?\s+cracked\b/i.test(text) && !/\b[1-9]\d*\s+password\s+hash(?:es)?\s+cracked\b/i.test(text);
    var unwrappedText = (C._unwrap_kerberos_hashes ? C._unwrap_kerberos_hashes(text) : String(text || ''))
      .replace(/(\$krb5(?:asrep|tgs)\$[^\r\n:]+)\r?\n\s*([0-9a-fA-F]{16,}:[^\r\n]+)/g, '$1$2');
    if (isHashcatCtx && /Status\.+:\s*Cracked/i.test(unwrappedText)) {
      var htMatch = /Hash\.Target\.+:\s*(\$krb5(?:asrep|tgs)\$[^\r\n]+?)(?:\.{2,}([0-9a-fA-F]{3,}))?\s*$/im.exec(unwrappedText);
      if (htMatch) {
        var htPrefix = htMatch[1];
        unwrappedText = unwrappedText.replace(
          /(?:^|\r?\n)((?:[0-9a-fA-F]{32,}\r?\n)*[0-9a-fA-F]{16,}):([^\r\n:]+?)(?:\r?\n([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]{1,40}))?(?=\r?\n\s*\r?\n\s*Session\.+:\s*hashcat)/i,
          function (_, hexBlock, pwPart1, pwPart2) {
            var cleanHex = hexBlock.replace(/\s+/g, '');
            var fullPw = pwPart1.trim() + (pwPart2 ? pwPart2.trim() : '');
            return '\n' + htPrefix + '$' + cleanHex + ':' + fullPw;
          }
        );
      }
    }
    unwrappedText.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line || line[0] === '#') return;
      var ll = line.toLowerCase();
      if (C._JOHN_NOISE_PREFIXES.some(function (p) { return ll.indexOf(p) === 0; })) return;
      if (_HASHCAT_STATUS_NOISE_RE.test(line)) return;
      if (/^\d+\s+password\s+hash(?:es)?\s+cracked\b/i.test(line)) return;

      if (ll.indexOf('$krb5asrep$') >= 0 || ll.indexOf('$krb5tgs$') >= 0) {
        // Hashcat's Hash.Target status line is often abbreviated. It is not a
        // recovered hash:password record, even when the session says Cracked.
        if (!/^(?:[^\s:$]+:)?\$krb5(?:asrep|tgs)\$/i.test(line)) return;
        var idx = line.lastIndexOf(':');
        if (idx < 0) return;
        var hashText = line.slice(0, idx), password = line.slice(idx + 1).trim();
        if (!/[:$][0-9a-fA-F]{4,}$/.test(hashText)) return;
        if (password.indexOf('*$') >= 0 || /^[0-9a-fA-F]{16,}\$[0-9a-fA-F]{16,}/.test(password) || (password.length >= 32 && /^[0-9a-fA-F$]+$/.test(password))) return;
        var hu = _parse_hash_user(hashText);
        var rType = ll.indexOf('$krb5tgs$') >= 0 ? 'krb5tgs' : 'krb5asrep';
        var rUser = hu[0] || _user_for_roast(ws, rType, facts);
        if (C._valid_password(password)) {
          _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws, hu[1]), { kind: 'cracked_' + rType, user: rUser || 'cracked', password: password, domain: hu[1] || '' }, S, source));
        }
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
        if (idxK >= 0 && ll.slice(0, idxK).indexOf('$keepass$*') >= 0) {
          var passK = line.slice(idxK + 1).trim();
          if (C._valid_password(passK) && !/^\$keepass\$/i.test(passK)) {
            _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'keepass_master', password: passK, via: isHashcatCtx ? 'hashcat' : 'john' }, S, source));
            _add_plaintext_credential(facts, ws, source, 'keepass_master', passK, C._domain_from_facts(ws), isHashcatCtx ? 'hashcat' : 'john', 'keepass');
            return;
          }
        }
      }

      var mMod = _CRACKED_MODULAR_RE.exec(line);
      if (mMod && C._valid_password(mMod.groups.pw.trim()) && !/^\$(?:keepass|krb5|dcc2|sntp-ms)/i.test(mMod.groups.pw.trim())) {
        var modRawUser = (mMod.groups.user || '').replace(/^.*[\\/]/, '');
        var modUser = C._clean_username(modRawUser) || 'cracked';
        if (!C._valid_username(modUser, false)) modUser = 'cracked';
        var modPw = mMod.groups.pw.trim();
        var modVia = isJohnCtx ? 'john' : 'hashcat';
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_hash', user: modUser, password: modPw, via: modVia }, S, source));
        _add_plaintext_credential(facts, ws, source, modUser, modPw, C._domain_from_facts(ws), modVia, 'crypt');
        return;
      }

      var mFile = (!zeroCracked && (isHashcatCtx || isJohnCtx)) ? _CRACKED_FILE_RE.exec(line) : null;
      if (mFile && C._valid_password(mFile.groups.pw.trim())) {
        var fPw = mFile.groups.pw.trim();
        if (!/^\$[A-Za-z0-9]/.test(fPw) && !/\b(?:password\s+hash(?:es)?\s+cracked|no\s+password\s+hashes\s+loaded)\b/i.test(fPw)) {
          var fVia = isJohnCtx ? 'john' : 'hashcat';
          var fBase = mFile.groups.file.replace(/^.*[\\/]/, '');
          var isKeyOrArchiveFile = /^(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)(?:\b|\.)|\.(?:pfx|p12|kdbx|psafe3|zip|rar|7z|pdf|pem|key|hash|txt|docx?|xlsx?|bak|db|sql|gpg|asc)$/i.test(fBase);
          var fUser = isKeyOrArchiveFile ? '' : (C._clean_username(fBase.replace(/\.[^.]+$/, '')) || '');
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_file', file: mFile.groups.file, password: fPw, via: fVia }, S, source));
          _add(facts, mkFact('credential.password', 'host:' + ws.target, { password: fPw, file: mFile.groups.file, via: fVia }, S, source));
          _add(facts, mkFact('credential.plaintext', 'host:' + ws.target, { password: fPw, file: mFile.groups.file, via: fVia }, S, source));
          if (fUser && C._valid_username(fUser, false)) {
            _add_plaintext_credential(facts, ws, source, fUser, fPw, C._domain_from_facts(ws), fVia, 'archive');
          } else {
            _add(facts, mkFact('credential.available', 'host:' + ws.target, { password: fPw, file: mFile.groups.file, method: fVia, hash_type: 'archive' }, S, source));
          }
          return;
        }
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
        if (m && (!m.groups.salt || isHashcatCtx || isJohnCtx) && C._valid_password(m.groups.pw) && !/^[0-9a-fA-F]{32}$/.test(m.groups.pw.trim())) {
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
          var ipmiUser = C._clean_username(mIpmi.groups.user || '') || 'ipmi';
          if (C._valid_username(ipmiUser, false)) {
            _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_ipmi', user: ipmiUser, password: mIpmi.groups.pw }, S, source));
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

      if (isJohnCtx && !zeroCracked && (reSearch(C._JOHN_LOADED_RE, text) || reSearch(C._JOHN_CRACKED_FOOTER_RE, text) || johnDoneFooter)) {
        var lm = C._JOHN_CRACKED_LIVE_RE.exec(line);
        if (lm && lm.groups.pw.indexOf(':') < 0 && C._valid_password(lm.groups.pw.trim())) {
          var pwTrim = lm.groups.pw.trim();
          var lbl = lm.groups.label ? lm.groups.label.trim() : '';
          var huLive = (lbl.indexOf('$krb5') >= 0) ? _parse_hash_user(lbl) : ['', '', ''];
          _add(facts, mkFact('credential.candidate', 'host:' + ws.target,
            { kind: 'cracked_secret', password: pwTrim, label: lbl, via: 'john' }, S, source));
          var lblBase = lbl ? lbl.replace(/^.*[\\/]/, '') : '';
          var isKeyOrArchiveLbl = /^(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)(?:\b|\.)|\.(?:pfx|p12|kdbx|psafe3|zip|rar|7z|pdf|pem|key|hash|txt|docx?|xlsx?|bak|db|sql|gpg|asc)$/i.test(lblBase);
          var cleanLbl = huLive[0] || (!isKeyOrArchiveLbl && lblBase ? lblBase.replace(/\.(?:zip|rar|7z|pfx|p12|kdbx|pdf|docx?|xlsx?)$/i, '') : '');
          var urLive = (cleanLbl && cleanLbl !== '?' && C._valid_username(cleanLbl, false)) ? cleanLbl : (_user_for_roast(ws, 'krb5tgs', facts) || _user_for_roast(ws, 'krb5asrep', facts) || (isKeyOrArchiveLbl ? '' : 'cracked'));
          var htypeLive = huLive[2] || ((textLow.indexOf('krb5tgs') >= 0) ? 'krb5tgs' : (textLow.indexOf('krb5asrep') >= 0 ? 'krb5asrep' : ''));
          if (urLive) {
            _add_plaintext_credential(facts, ws, source, urLive, pwTrim, huLive[1] || C._domain_from_facts(ws), 'john', htypeLive);
          } else {
            _add(facts, mkFact('credential.password', 'host:' + ws.target, { password: pwTrim, file: lblBase || lbl, via: 'john' }, S, source));
            _add(facts, mkFact('credential.plaintext', 'host:' + ws.target, { password: pwTrim, file: lblBase || lbl, via: 'john' }, S, source));
            _add(facts, mkFact('credential.available', 'host:' + ws.target, { password: pwTrim, file: lblBase || lbl, method: 'john' }, S, source));
          }
          return;
        }
      }

      if (!isJohnCtx || zeroCracked) return;
      if (lc.indexOf('--show') < 0 && !reSearch(C._JOHN_CRACKED_FOOTER_RE, text)) return;
      var sm = C._JOHN_SHOW_RE.exec(line);
      if (!sm) return;
      if (!C._valid_password(sm.groups.password)) return;
      var showUser = sm.groups.user.replace(/^.*[\\/]/, '');
      var isKeyOrArchiveShow = /^(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)(?:\b|\.)|\.(?:pfx|p12|kdbx|psafe3|zip|rar|7z|pdf|pem|key|hash|txt|docx?|xlsx?|bak|db|sql|gpg|asc)$/i.test(showUser);
      if (isKeyOrArchiveShow) {
        var pwShow = sm.groups.password.trim();
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'cracked_file', file: showUser, password: pwShow, via: 'john' }, S, source));
        _add(facts, mkFact('credential.password', 'host:' + ws.target, { password: pwShow, file: showUser, via: 'john' }, S, source));
        _add(facts, mkFact('credential.plaintext', 'host:' + ws.target, { password: pwShow, file: showUser, via: 'john' }, S, source));
        _add(facts, mkFact('credential.available', 'host:' + ws.target, { password: pwShow, file: showUser, method: 'john' }, S, source));
        return;
      }
      if (!C._valid_username(showUser, false)) showUser = 'cracked';
      _add_plaintext_credential(facts, ws, source, showUser, sm.groups.password, C._domain_from_facts(ws), 'john', '');
    });

    if (facts.length === factsBefore && isHashcatCtx && !zeroCracked && /Status\.+:\s*Cracked/i.test(text)) {
      var rawLines = String(text || '').split(/\r?\n/);
      var sessIdx = -1;
      for (var si = 0; si < rawLines.length; si++) {
        if (/^\s*Session\.+:\s*hashcat\b/i.test(rawLines[si])) { sessIdx = si; break; }
      }
      if (sessIdx > 0) {
        var candLine = '';
        for (var pi = sessIdx - 1; pi >= 0; pi--) {
          var tLine = rawLines[pi].trim();
          if (!tLine) continue;
          if (_HASHCAT_STATUS_NOISE_RE.test(tLine)) break;
          candLine = tLine;
          break;
        }
        if (candLine) {
          var barePw = candLine;
          if (candLine.indexOf(':') >= 0 && /^[0-9a-fA-F$*]{8,}:[^\r\n:]+$/.test(candLine)) {
            barePw = candLine.slice(candLine.lastIndexOf(':') + 1).trim();
          }
          if (barePw && !/^[0-9a-fA-F]{32,}$/.test(barePw) && !/^\$krb5/i.test(barePw) && C._valid_password(barePw)) {
            var bound = _bind_bare_hashcat_target(ws, text, command, facts);
            var bUser = bound.user || 'cracked';
            var bDom = bound.domain || C._domain_from_facts(ws) || '';
            var bScope = C._scope_for_domain(ws, bDom);
            _add(facts, mkFact('credential.candidate', bScope, { kind: 'cracked_' + (bound.type || 'hash'), user: bUser, password: barePw, domain: bDom, method: 'hashcat', via: 'hashcat' }, S, source));
            _add_plaintext_credential(facts, ws, source, bUser, barePw, bDom, 'hashcat', bound.type || 'hashcat');
          }
        }
      }
    }
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
  var _SAM_PWDUMP_NOPW_RE = /^(?:[ \t]*(?:(?<domain>[A-Za-z0-9._-]+)\\)?(?<user>[^\s\\:]{1,128})):(?<rid>\d+):(?:NO PASSWORD\*+):(?<nt>[0-9a-fA-F]{32}):::/gmi;

  function _parse_ntlm_dump(text, ws, command, source, facts) {
    var entries = [], seen = {}, krbtgtNt = '', domCounts = {};
    var rawHits = reAll(C._NTDS_HASH_RE, text).concat(reAll(_SAM_PWDUMP_NOPW_RE, text));
    rawHits.forEach(function (m) {
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
      if (user.toLowerCase() === 'krbtgt' && nt !== '31d6cfe0d16ae931b73c59d7e0c089c0') krbtgtNt = nt;
    });
    var hasLsaBanner = /Dumping LSA Secrets|\[\*\]\s*(?:_SC_|DefaultPassword|\$MACHINE\.ACC|DPAPI_SYSTEM)/i.test(text);
    var hasSecretsdumpCtx = /\bsecretsdump\b/i.test((command || '') + '\n' + text);
    if (hasLsaBanner || hasSecretsdumpCtx) {
      _DPAPI_KEY_RE.lastIndex = 0;
      var dm;
      while ((dm = _DPAPI_KEY_RE.exec(text)) !== null) {
        _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'dpapi_masterkey', key_type: dm.groups.type.toLowerCase(), key: dm.groups.key, via: 'lsa-secrets' }, S, source));
      }
      _LSA_CLEARTEXT_RE.lastIndex = 0;
      var lm;
      while ((lm = _LSA_CLEARTEXT_RE.exec(text)) !== null) {
        var lsaDom = (lm.groups.domain || '').trim();
        if (!hasLsaBanner && (!lsaDom || lsaDom.length < 2)) continue;
        if (/^(?:BUILTIN|NT AUTHORITY|NT SERVICE|IIS APPPOOL|WINDOW MANAGER|FONT DRIVER HOST)$/i.test(lsaDom)) continue;
        var lsaUser = C._clean_username(lm.groups.user);
        var lsaPw = (lm.groups.pw || '').trim();
        if (/^(?:dpapi_machinekey|dpapi_userkey|NL\$KM|plain_password_hex|aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5|\$MACHINE\.ACC)$/i.test(lsaUser)) continue;
        if (/^0x[0-9a-fA-F]+$/i.test(lsaPw) || /^[0-9a-fA-F]{32,128}$/.test(lsaPw) || /^\d+$/.test(lsaPw)) continue;
        if (/^(?:\([A-Za-z0-9_,]+\))+$/.test(lsaPw)) continue;
        if (!hasLsaBanner && /\.(?:txt|xml|ini|cfg|conf|config|ps1|bat|cmd|log|exe|dll|py|sh|php|aspx?|json|ya?ml|md)$/i.test(lsaUser)) continue;
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
      entries.forEach(function (e) {
        if (!e || !e.nthash || e.nthash === '31d6cfe0d16ae931b73c59d7e0c089c0') return;
        if (e.rid === 501 || e.rid === 503 || e.rid === 504) return;
        if (/^(?:guest|defaultaccount|wdagutilityaccount)$/i.test(e.user) || /\$$/.test(e.user)) return;
        var lav = { user: e.user, nthash: e.nthash, method: 'sam-dump', hash_type: 'ntlm', accountType: 'local', targetBinding: ws.target };
        if (e.domain) lav.domain = e.domain;
        _add(facts, mkFact('credential.available', 'host:' + ws.target, lav, S, source));
        _add(facts, mkFact('credential.ntlm_hash', 'host:' + ws.target, lav, S, source));
      });
    }
  }
  C._parse_ntlm_dump = _parse_ntlm_dump;
  C._parse_sam_hashes = _parse_ntlm_dump;

  function _looks_like_sam_dump(text) {
    if (!text) return false;
    return /^(?:(?:[A-Za-z0-9._-]+\\)?[a-zA-Z0-9._$-]+:\d{3,6}:(?:[0-9a-fA-F]{32}|NO PASSWORD\*+|\.{2,4}|\*+):[0-9a-fA-F]{32}:::)/m.test(text);
  }
  C._looks_like_sam_dump = _looks_like_sam_dump;

  var _MIMI_SIG_RE = /sekurlsa::|lsadump::|token::elevate|->\s*Impersonated\s*!|crypto::capi|mimikatz\s+#|pypykatz|^\s*Hash NTLM:|^\s*SysKey\s*:[ \t]*[0-9a-fA-F]{32}\b|^\s*msv credentials\s*\r?\n\s*=+|\[\+\]\s*Running as SYSTEM\b|\b(?:creds_all|creds_msv|creds_wdigest|creds_kerberos|lsa_dump_sam|lsa_dump_secrets)\b|Authentication Id\s*:[\s\S]{1,400}?(?:\bmsv\s*:|\bwdigest\s*:|\bkerberos\s*:|\*\s*NTLM\s*:)/im;
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
    var h = 'host:' + ws.target;
    var entries = [], kiwiMsvEntries = [], seen = {}, plainSeen = {}, curUser = '', curDomain = '', curRid = null;
    var kiwiMode = '', kiwiHasRows = false;
    text.split(/\r?\n/).forEach(function (raw) {
      if (/^\s*msv credentials\s*$/i.test(raw)) { kiwiMode = 'msv'; kiwiHasRows = false; return; }
      if (/^\s*(?:wdigest|kerberos|tspkg|ssp|livessp)\s+credentials\s*$/i.test(raw)) { kiwiMode = 'plain'; kiwiHasRows = false; return; }
      if (kiwiMode) {
        if (/^\s*[=-]{4,}(?:\s+[=-]{4,})*\s*$/.test(raw)) return;
        if (/^\s*Username\s+Domain\s+(?:NTLM|Password)\b/i.test(raw)) return;
        if (!raw.trim()) { if (kiwiHasRows) { kiwiMode = ''; kiwiHasRows = false; } return; }
        if (/^\s*\[\*\]|\[\+\]|meterpreter\s*>/i.test(raw)) { kiwiMode = ''; kiwiHasRows = false; }
        else if (kiwiMode === 'msv') {
          var km = /^\s*(?<user>\S+)\s+(?<dom>\S+)\s+(?<nt>[0-9a-fA-F]{32})(?:\s+\S+){0,3}\s*$/.exec(raw);
          if (km) {
            kiwiHasRows = true;
            var ku = C._clean_username(km.groups.user), kdom = km.groups.dom.trim(), knt = km.groups.nt.toLowerCase();
            if (ku && C._valid_username(ku)) {
              var kkey = ku.toLowerCase() + '|' + knt;
              if (!seen[kkey]) {
                seen[kkey] = true;
                var ke = { user: ku, nthash: knt };
                if (kdom && kdom !== '(null)') ke.domain = kdom;
                entries.push(ke);
                kiwiMsvEntries.push(ke);
              }
            }
            return;
          }
        } else if (kiwiMode === 'plain') {
          if (/^\s{8,}/.test(raw)) return;
          var kpm = /^\s*(?<user>\S+)\s+(?<dom>\S+)\s+(?<pw>.+?)\s*$/.exec(raw);
          if (kpm) {
            kiwiHasRows = true;
            var kpu = C._clean_username(kpm.groups.user), kpdom = kpm.groups.dom.trim(), kpw = kpm.groups.pw.trim();
            if (kpu && !/\$$/.test(kpu) && C._valid_username(kpu) && !/(?:^|\s)(?:[0-9a-fA-F]{1,2}\s+){3,}[0-9a-fA-F]{1,2}(?:\s|$)/.test(kpw) && kpw !== '(null)' && kpw !== '<null>' && C._valid_password(kpw)) {
              var kpk = kpu.toLowerCase() + '|' + kpw;
              if (!plainSeen[kpk]) {
                plainSeen[kpk] = true;
                var kdomClean = (kpdom && kpdom.indexOf('.') >= 0) ? kpdom : '';
                _add_plaintext_credential(facts, ws, source, kpu, kpw, kdomClean, 'mimikatz', '');
              }
            }
            return;
          }
        }
      }
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
    var fullMimi = text + '\n' + (command || '');
    if (/\[\+\]\s*Running as SYSTEM\b/i.test(fullMimi) || /(?:token::elevate|Impersonated\s*!)[\s\S]{0,400}?(?:NT AUTHORITY\\SYSTEM|\bS-1-5-18\b)|(?:NT AUTHORITY\\SYSTEM|\bS-1-5-18\b)[\s\S]{0,240}?->\s*Impersonated\s*!/i.test(fullMimi)) {
      _add(facts, mkFact('access.system', h, { identity: 'nt authority\\system', method: 'token-impersonation', tool: 'mimikatz' }, S, source));
    }
    if (!entries.length) return;
    _add(facts, mkFact('hash.ntlm', h, { count: entries.length, entries: entries, via: 'mimikatz' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { kind: 'ntlm_hash', count: entries.length, via: 'mimikatz' }, S, source));
    var isDcsyncOrNtds = /lsadump::(?:dcsync|lsa\s+\/inject)/i.test(fullMimi)
      || /\bUser\s*:\s*krbtgt\b/i.test(text)
      || entries.some(function (e) { return e.user && e.user.toLowerCase() === 'krbtgt'; });
    var isSamDump = /(?:lsadump::sam|lsa_dump_sam)\b/i.test(fullMimi)
      || (/\bSAMKey\s*:/i.test(text) && (/\bRID\s*:\s*000001f4\s*\(500\)/i.test(text) || /\bSysKey\s*:[ \t]*[0-9a-fA-F]{32}\b/i.test(text)));
    if (isDcsyncOrNtds) {
      _add(facts, mkFact('loot.ntds', h, { count: entries.length, method: 'lsadump' }, S, source));
    } else if (isSamDump) {
      _add(facts, mkFact('loot.sam', h, { count: entries.length, method: 'mimikatz-lsadump-sam' }, S, source));
      entries.forEach(function (e) {
        if (!e || !e.nthash || e.nthash === '31d6cfe0d16ae931b73c59d7e0c089c0') return;
        if (e.rid === 501 || e.rid === 503 || e.rid === 504) return;
        if (/^(?:guest|defaultaccount|wdagutilityaccount)$/i.test(e.user) || /\$$/.test(e.user)) return;
        var lav = { user: e.user, nthash: e.nthash, method: 'sam-dump', hash_type: 'ntlm', accountType: 'local', targetBinding: ws.target };
        if (e.domain) lav.domain = e.domain;
        _add(facts, mkFact('credential.available', h, lav, S, source));
        _add(facts, mkFact('credential.ntlm_hash', h, lav, S, source));
      });
    }
    if (kiwiMsvEntries.length) {
      kiwiMsvEntries.forEach(function (e) {
        if (!e || !e.nthash || e.nthash === '31d6cfe0d16ae931b73c59d7e0c089c0') return;
        if (/^(?:guest|defaultaccount|wdagutilityaccount)$/i.test(e.user) || /\$$/.test(e.user)) return;
        var kScope = (e.domain && e.domain.indexOf('.') >= 0) ? C._scope_for_domain(ws, e.domain) : h;
        var kav = { user: e.user, nthash: e.nthash, method: 'kiwi-msv', hash_type: 'ntlm' };
        if (e.domain) kav.domain = e.domain;
        _add(facts, mkFact('credential.available', kScope, kav, S, source));
        _add(facts, mkFact('credential.ntlm_hash', kScope, kav, S, source));
      });
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
    var users = [], hashes = [];
    var isV1 = /NTLMv1(?:-SSP)? Hash/i.test(text);
    reAll(_RESPONDER_HASH_RE, text).forEach(function (m) {
      if (users.indexOf(m.groups.user) < 0) users.push(m.groups.user);
      if (m.groups.hash && hashes.indexOf(m.groups.hash) < 0) hashes.push(m.groups.hash);
    });
    if (!users.length) return;
    var fmt = isV1 ? 'netntlmv1' : 'netntlmv2';
    var h = 'host:' + ws.target;
    var value = { kind: fmt, via: 'responder', count: users.length, users: users.slice(0, 20) };
    _add(facts, mkFact('credential.candidate', h, value, S, source));
    _add(facts, mkFact('credential.netntlm', h, value, S, source));
    _add(facts, mkFact('hash.candidate', h, { user: users[0], users: users.slice(0, 20), hash: hashes[0] || '', format: fmt, via: 'responder' }, S, source));
    _add(facts, mkFact('hash.crackable', h, { user: users[0], users: users.slice(0, 20), hash: hashes[0] || '', format: fmt, via: 'responder' }, S, source));
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
  var _ATTACKER_CMD_LINE_RE = /^\s*(?:(?:\$|\#|└─\$|┌──|\[\*\]|\[\+\]|\[\-\]|PS\s+[A-Za-z]:\\[^>]*>|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^$#]*[$#])\s*)*(?:(?:sudo|proxychains4?|time|env|python[23]?(?:\.\d+)?|py|perl|ruby|bash|sh)\s+)*(?:[\w.~/-]+[\\/])?(?:nxc|netexec|crackmapexec|cme|impacket-[\w.-]+|targetedkerberoast(?:\.py)?|getuserspns(?:\.py)?|getnpusers(?:\.py)?|secretsdump(?:\.py)?|dacledit(?:\.py)?|owneredit(?:\.py)?|pywhisker(?:\.py)?|timeroast(?:\.py)?|addcomputer(?:\.py)?|gettgt(?:\.py)?|getst(?:\.py)?|rbcd(?:\.py)?|lookupsid(?:\.py)?|psexec(?:\.py)?|wmiexec(?:\.py)?|smbexec(?:\.py)?|atexec(?:\.py)?|dcomexec(?:\.py)?|mssqlclient(?:\.py)?|ticketer(?:\.py)?|finddelegation(?:\.py)?|evil-winrm|xfreerdp|rdesktop|hydra|medusa|ncrack|sqlmap|gobuster|ffuf|feroxbuster|dirsearch|wfuzz|curl|wget|smbclient|smbmap|rpcclient|ldapsearch|bloodyAD|certipy(?:-ad)?|bloodhound(?:-python)?|kerbrute|responder)\b/i;
  var _JSON_CRED_RE = /"(?:username|user)"\s*:\s*"(?<user>[^"]+)"[^{}]{1,160}?"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"/gi;
  var _JSON_CRED_REV_RE = /"(?:password|pass)"\s*:\s*"(?<pw>[^"]+)"[^{}]{1,160}?"(?:username|user)"\s*:\s*"(?<user>[^"]+)"/gi;
  var _URL_CRED_RE = /https?:\/\/(?<user>[a-zA-Z0-9._-]+):(?<pw>[^@\s'"]+)@/gi;
  var _KEEPASS_DUMP_RE = /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*['"]?(?<pw>[^\r\n'"]+)['"]?/gi;
  var _MREMOTENG_DECRYPT_RE = /^\s*(?<user>[a-zA-Z0-9._$-]{1,64})@(?<host>[a-zA-Z0-9._-]{1,64})(?::\d+)?\s*\|\s*password\s+is:\s*(?<pw>\S+)/gim;
  var _CISCO_CONFIG_CRED_RE = /^[ \t]*username[ \t]+(?<user>[a-zA-Z0-9._-]+)(?:[ \t]+privilege[ \t]+\d+)?[ \t]+(?:password[ \t]+0|secret[ \t]+0|password)[ \t]+['"]?(?<pw>[^\r\n\s'"]+)['"]?/gmi;
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

  var _FILE_READ_CMD_RE = /\b(?:cat|type|get-content|gc|more|head|tail|less|bat|batcat|strings)\b/i;
  var _NOTE_SCHEME_DENY_RE = /^(?:https?|ftp|sftp|smb|cifs|ldap|ldaps|ssh|ws|wss|file|mailto|git|svn|redis|mongodb|mysql|postgres|postgresql|mssql|path|dir|directory|location|endpoint|route|uri|url|proxy|server|content-type|accept|mime|type|protocol|port|subnet|network|cidr|netmask|gateway|interface)$/i;
  var _NOTE_USER_DENY_RE = /^(?:text|application|image|audio|video|multipart|font|model|inode|etc|var|usr|opt|tmp|bin|sbin|lib|lib64|proc|sys|dev|run|srv|mnt|media|boot|home|windows|programdata|users|system32|inetpub|null|none|true|false)$/i;
  var _NOTE_SECRET_EXT_DENY_RE = /^(?:tcp|udp|icmp|sctp)$|\.(?:html?|php|asp|aspx|jsp|js|css|json|xml|ya?ml|txt|log|conf|cfg|ini|sh|py|rb|pl|exe|dll|so|bak|zip|tar|gz)$/i;
  var _NETNTLM_BLOB_RE = /\b(?<user>[A-Za-z0-9_.$-]{1,48})::(?<dom>[A-Za-z0-9_.-]{1,64}):(?<chal>[0-9a-fA-F]{16}):(?<resp>[0-9a-fA-F]{32}|[0-9a-fA-F]{48}):(?<blob>[0-9a-fA-F]{32,})\b/g;

  function _decode_utf16le_hex_line(hexStr) {
    var parts = String(hexStr || '').trim().split(/\s+/);
    if (parts.length < 6 || parts.length % 2 !== 0) return '';
    var chars = [];
    for (var i = 0; i < parts.length; i += 2) {
      if (!/^[0-9a-fA-F]{2}$/.test(parts[i]) || !/^[0-9a-fA-F]{2}$/.test(parts[i + 1])) return '';
      var lo = parseInt(parts[i], 16), hi = parseInt(parts[i + 1], 16);
      if (hi !== 0) return '';
      if (lo === 0) break;
      if (lo < 0x20 || lo > 0x7e) return '';
      chars.push(String.fromCharCode(lo));
    }
    return chars.length >= 3 ? chars.join('') : '';
  }

  function _expects_cred_kind(ws, kind) {
    var ctx = (ws && ws.context) || {};
    var arr = [].concat(ctx.expectedKinds || [], ctx.produces || []);
    return arr.indexOf(kind) >= 0;
  }

  function _unwrap_format_list_lines(s) {
    var cur = String(s || '');
    if (cur.indexOf('\n') < 0) return cur;
    for (var pass = 0; pass < 4; pass++) {
      var next = cur.replace(/([^\r\n])\r?\n[ \t]{2,}(?![A-Za-z0-9_.-]+[ \t]*:[ \t])([^\s\r\n])/g, function (_m, prevCh, nextCh, offset, full) {
        var lineStart = full.lastIndexOf('\n', offset) + 1;
        var prevSeg = full.slice(lineStart, offset + 1);
        if (/[ \t]$/.test(prevSeg)) return prevCh + nextCh;
        if (/(?:^|\s)(?:-u|--user(?:name)?|\/u|\/user|-p|--pass(?:word)?|\/p|\/pass(?:word)?)$/i.test(prevSeg)) {
          return prevCh + ' ' + nextCh;
        }
        if (nextCh === '-' || nextCh === '"' || nextCh === "'") {
          return prevCh + ' ' + nextCh;
        }
        if (/^[ \t]*[A-Za-z0-9_.-]+[ \t]*:[ \t]/.test(prevSeg) || (lineStart > 0 && /^[ \t]{2,}/.test(prevSeg))) {
          return prevCh + nextCh;
        }
        return prevCh + ' ' + nextCh;
      });
      if (next === cur) break;
      cur = next;
    }
    return cur;
  }

  function _decode_cli_base64_secret(s) {
    var tok = String(s || '').trim();
    if (!/^(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/.test(tok)) return '';
    var hasPad = tok.charAt(tok.length - 1) === '=';
    var dec = '';
    try {
      if (C && typeof C.b64decode === 'function') dec = C.b64decode(tok);
      else if (typeof Buffer !== 'undefined') dec = Buffer.from(tok, 'base64').toString('binary');
      else if (typeof atob === 'function') dec = atob(tok);
    } catch (_e) { return ''; }
    if (!dec) return '';
    if (hasPad && /^[!-~]{4,64}(?:\r?\n)?$/.test(dec)) return dec.replace(/\r?\n$/, '');
    if (/^[!-~]{4,64}\r?\n$/.test(dec)) return dec.replace(/\r?\n$/, '');
    return '';
  }

  function _looks_like_generic_dumped_credentials(text, command, ws) {
    if (!text) return false;
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return false;
    var isReadCtx = _FILE_READ_CMD_RE.test(command || '') || _expects_cred_kind(ws, 'credential.plaintext');
    return !!(
      /(?:^\s*Domain\s*:\s*[^\r\n]+\s*\r?\n\s*)?^\s*User(?:name)?\s*:\s*[^\r\n]+\s*\r?\n\s*(?:Domain\s*:\s*[^\r\n]+\s*\r?\n\s*)?Password\s*:\s*[^\r\n]+/im.test(text) ||
      /^\s*(?:Nthash|Password)\s*:\s*\S+[\s\S]{1,240}?^\s*Login\s*:\s*\S+/im.test(text) ||
      /^\s*Login\s*:\s*\S+[\s\S]{1,240}?^\s*(?:Nthash|Password)\s*:\s*\S+/im.test(text) ||
      /\bDefaultPassword\s*:\s*(?:[0-9a-fA-F]{2}[ \t]+){3,}[0-9a-fA-F]{2}\b/i.test(text) ||
      (/ntlm/i.test(text) && /\b[A-Za-z0-9_.$-]{2,32}\b[^\r\n]{0,40}?\bNTLM\s*:\s*[0-9a-fA-F]{32}\b/i.test(text)) ||
      (text.indexOf('::') >= 0 && /\b[A-Za-z0-9_.$-]{1,48}::[A-Za-z0-9_.-]{1,64}:[0-9a-fA-F]{16}:(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}):[0-9a-fA-F]{32,}\b/.test(text)) ||
      (isReadCtx && text.indexOf('/') >= 0 && /^\s*[A-Za-z0-9_.-]{2,32}(?:[ \t]+[A-Za-z0-9_.-]{1,24}){0,2}\s*:\s*[A-Za-z0-9_.$-]{2,32}\/[^\s\/]{4,64}\s*$/m.test(text)) ||
      (/[-/][uU]/.test(text) && /(?:^|\s|\/)(?:-u|--user|-username|--username|\/u|\/user)[:=\s]+['"]?[a-zA-Z0-9._-]+['"]?\s+(?:-p|--password|-pass|--pass|\/p|\/pass|\/password)[:=\s]+['"]?(?!-)[^\s'"]+['"]?/i.test(_unwrap_format_list_lines(text))) ||
      (text.indexOf('"') >= 0 && (/"(?:username|user)"\s*:\s*"[^"]+"[^{}]{1,160}?"(?:password|pass)"\s*:\s*"[^"]+"/i.test(text) ||
        /"(?:password|pass)"\s*:\s*"[^"]+"[^{}]{1,160}?"(?:username|user)"\s*:\s*"[^"]+"/i.test(text))) ||
      (text.indexOf('://') >= 0 && /https?:\/\/[a-zA-Z0-9._-]+:[^@\s'"]+@/i.test(text)) ||
      /(?:Possible master password|Master password candidate|Extracted password|KeePass master password|KeePass password)\s*[:=]\s*[^\r\n]+/i.test(text) ||
      (text.indexOf('|') >= 0 && /^\s*[a-zA-Z0-9._$-]{1,64}@[a-zA-Z0-9._-]{1,64}(?::\d+)?\s*\|\s*password\s+is:/im.test(text)) ||
      (text.indexOf('<') >= 0 && /<(?:dbpassword|dbpass)>/i.test(text)) ||
      /\b(?:AMPDBPASS|AMPMGRPASS)\s*=/i.test(text) ||
      /\b(?:password|encryptedPassword)\s*=\s*[a-fA-F0-9]{40}\b/i.test(text) ||
      /\[\+\]\s+Valid credentials found:\s*[a-zA-Z0-9_$]+\/\S+/i.test(text) ||
      /^[+-]?\s*(?:(?:db_|admin_|app_|api_)?password|passwd|pwd)\s*[=:]\s*['"]?[^\r\n\s'"]+['"]/mi.test(text) ||
      (/^[ \t]*username[ \t]+[a-zA-Z0-9._-]+(?:[ \t]+privilege[ \t]+\d+)?[ \t]+(?:password|secret)[ \t]+\S/mi.test(text) && /\bprivilege[ \t]+\d+\b|\b(?:password|secret)[ \t]+[05789][ \t]+\S|\benable[ \t]+(?:secret|password)\b|^![ \t]*$/im.test(text)) ||
      /(?:cisco-decrypt|decrypted\s*(?:cisco)?\s*password)\s*[:=->]/i.test(text) ||
      /(?:User ID|UID)\s*=\s*[a-zA-Z0-9._-]+[\s\S]{1,150}?(?:Password|PWD)\s*=/i.test(text) ||
      /(?:Password|PWD)\s*=[^;\r\n]+[\s\S]{1,150}?(?:User ID|UID)\s*=/i.test(text) ||
      /(?:(?:extracted|recovered|found)\s*(?:nosql|user|admin|db)?\s*(?:password|passwd)|\[\+\]\s*password)\s*[:=->]/i.test(text) ||
      /^(?:["']?[a-zA-Z0-9_]+["']?[,\t])*(?:["']?(?:username|user|login)["']?[,\t])+(?:["']?[a-zA-Z0-9_]+["']?[,\t])*(?:["']?(?:password|pass|passwd|pwd)["']?)/mi.test(text) ||
      (/^\s*(?:#+\s*)?(?:[\w\s]{0,24}\b)?(?:passwords?|credentials?|logins?|accounts?)\s*:\s*$/im.test(text) && /^\s*[-*+]\s*[A-Za-z0-9_.\\@-]{2,64}\s*:\s*\S+/m.test(text)) ||
      (/(?:\$|\b)(?:[A-Za-z0-9_.-]*?(?:User(?:name)?|Login|Uid|Account))\s*[:=]/i.test(text) && /(?:\$|\b)(?:[A-Za-z0-9_.-]*?(?:Pass(?:word|wd)?|Pwd|Secret)|[A-Za-z0-9_]*[a-z0-9_]Pw|pw)\s*[:=]/i.test(text))
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
        _add(facts, mkFact('hash.crackable', hScope, { user: u, hash: p, via: 'db_csv_dump' }, S, source));
        _add(facts, mkFact('loot.material', hScope, { kind: 'db_hashes', user: u, hash: p }, S, source));
      } else if (C._valid_password(p)) {
        _add_plaintext_credential(facts, ws, source, u, p, C._domain_from_facts(ws), 'db_csv_dump', '');
      }
    }
  }

  function _parse_generic_dumped_credentials(text, ws, command, source, facts) {
    if (!text) return;
    if (C._is_public_reference_http_cmd && C._is_public_reference_http_cmd(command, ws)) return;
    text = text.replace(C._ANSI_RE, '');
    var hScope = 'host:' + ws.target;
    var hasInteractiveAuthFail = /(?:doesn't have UF_DONT_REQUIRE_PREAUTH set|KDC_ERR_PREAUTH_FAILED|su:\s*Authentication failure|Login incorrect|Sorry,\s*try again|Cannot authenticate)/i.test(text);
    _GENERIC_CRED_BLOCK_RE.lastIndex = 0;
    var m;
    while ((m = _GENERIC_CRED_BLOCK_RE.exec(text)) !== null) {
      if (hasInteractiveAuthFail && /^\s*(?:Enter\s+)?Password\s*:/im.test(m[0]) && !/^\s*Domain\s*:/im.test(m[0])) continue;
      var rawUser = (m.groups.user || '').trim();
      var dom = (m.groups.dom || m.groups.dom2 || '').trim();
      if (rawUser.indexOf('\\') >= 0) {
        var parts = rawUser.split('\\');
        if (!dom) dom = parts[0].trim();
        rawUser = parts.slice(1).join('\\');
      }
      var user = C._clean_username(rawUser);
      var pw = (m.groups.pw || '').trim().replace(/^(["'])(.*)\1$/, '$2').trim();
      if (!C._valid_username(user, false)) continue;
      if (_looks_like_password_hash(pw)) {
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'dumped_hash', user: user, hash: pw, via: 'dump' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: user, hash: pw, via: 'dump' }, S, source));
        _add(facts, mkFact('hash.crackable', hScope, { user: user, hash: pw, via: 'dump' }, S, source));
        continue;
      }
      if (!C._valid_password(pw)) continue;
      _add_plaintext_credential(facts, ws, source, user, pw, dom || C._domain_from_facts(ws), 'dump', '');
    }

    // Order-independent LaZagne credential blocks (Nthash/Password + Login) & UTF-16LE hex DefaultPassword
    if (/^\s*Login\s*:/im.test(text) || /\bDefaultPassword\s*:/i.test(text)) {
      var lzChunks = text.split(/\r?\n(?:\s*\r?\n|-{5,}[^\r\n]*|Password found\s*!+[^\r\n]*)/i);
      for (var lzi = 0; lzi < lzChunks.length; lzi++) {
        var lzBlk = lzChunks[lzi];
        var lzLoginM = /^\s*Login\s*:\s*([^\r\n]+?)\s*$/im.exec(lzBlk);
        var lzDomM = /^\s*(?:Domain|URL)\s*:\s*([^\r\n]+?)\s*$/im.exec(lzBlk);
        var lzNtM = /^\s*Nthash\s*:\s*([0-9a-fA-F]{32})\s*$/im.exec(lzBlk);
        var lzPwM = /^\s*Password\s*:\s*([^\r\n]+?)\s*$/im.exec(lzBlk);
        if (lzLoginM && (lzNtM || lzPwM)) {
          var lzRawU = lzLoginM[1].trim();
          var lzDom = lzDomM && !/^https?:/i.test(lzDomM[1].trim()) ? lzDomM[1].trim() : '';
          if (lzRawU.indexOf('\\') >= 0) {
            if (!lzDom) lzDom = lzRawU.split('\\')[0].trim();
            lzRawU = lzRawU.split('\\').slice(1).join('\\');
          }
          var lzUser = C._clean_username(lzRawU);
          if (lzUser && C._valid_username(lzUser, false) && !/\$$/.test(lzUser)) {
            var lzDomScope = (lzDom && lzDom.indexOf('.') >= 0) ? C._scope_for_domain(ws, lzDom) : hScope;
            if (lzNtM) {
              var lzNt = lzNtM[1].toLowerCase();
              if (lzNt !== '31d6cfe0d16ae931b73c59d7e0c089c0' && lzNt !== 'aad3b435b51404eeaad3b435b51404ee') {
                var lzVal = { user: lzUser, nthash: lzNt, method: 'lazagne', hash_type: 'ntlm' };
                if (lzDom) lzVal.domain = lzDom;
                _add(facts, mkFact('hash.ntlm', lzDomScope, { count: 1, entries: [{ user: lzUser, nthash: lzNt, domain: lzDom }], user: lzUser, nthash: lzNt, via: 'lazagne' }, S, source));
                _add(facts, mkFact('credential.ntlm_hash', lzDomScope, lzVal, S, source));
                _add(facts, mkFact('credential.available', lzDomScope, lzVal, S, source));
                _add(facts, mkFact('credential.candidate', lzDomScope, { kind: 'ntlm_hash', user: lzUser, nthash: lzNt, domain: lzDom, via: 'lazagne' }, S, source));
              }
            }
            if (lzPwM) {
              var lzPw = lzPwM[1].trim().replace(/^(["'])(.*)\1$/, '$2').trim();
              if (lzPw && !/^(?:none|\(null\)|null)$/i.test(lzPw) && !/^(?:[0-9a-fA-F]{2}\s+){3,}[0-9a-fA-F]{2}$/.test(lzPw)) {
                if (_looks_like_password_hash(lzPw)) {
                  _add(facts, mkFact('credential.candidate', hScope, { kind: 'dumped_hash', user: lzUser, hash: lzPw, via: 'lazagne' }, S, source));
                  _add(facts, mkFact('hash.candidate', hScope, { user: lzUser, hash: lzPw, via: 'lazagne' }, S, source));
                  _add(facts, mkFact('hash.crackable', hScope, { user: lzUser, hash: lzPw, via: 'lazagne' }, S, source));
                } else if (C._valid_password(lzPw)) {
                  _add(facts, mkFact('credential.candidate', lzDomScope, { kind: 'lazagne_password', user: lzUser, password: lzPw, domain: lzDom, via: 'lazagne' }, S, source));
                  _add_plaintext_credential(facts, ws, source, lzUser, lzPw, lzDom || C._domain_from_facts(ws), 'lazagne', '');
                }
              }
            }
          }
        }
      }
      var defUserRawM = /^\s*DefaultUserName\s*:\s*([^\r\n]+?)\s*$/im.exec(text);
      var defDomRawM = /^\s*DefaultDomainName\s*:\s*([^\r\n]+?)\s*$/im.exec(text);
      var defUser = defUserRawM ? (_decode_utf16le_hex_line(defUserRawM[1]) || defUserRawM[1].trim()) : '';
      var defDom = defDomRawM ? (_decode_utf16le_hex_line(defDomRawM[1]) || defDomRawM[1].trim()) : '';
      defUser = C._clean_username(defUser);
      var defHexRe = /^\s*DefaultPassword\s*:\s*((?:[0-9a-fA-F]{2}[ \t]+){3,}[0-9a-fA-F]{2})\s*$/gim, dhm;
      while ((dhm = defHexRe.exec(text)) !== null) {
        var decDefPw = _decode_utf16le_hex_line(dhm[1]);
        if (decDefPw && C._valid_password(decDefPw)) {
          var targetDefUser = (defUser && C._valid_username(defUser, false)) ? defUser : 'Administrator';
          _add(facts, mkFact('credential.candidate', hScope, { kind: 'autologon_default_password', user: targetDefUser, password: decDefPw, domain: defDom, via: 'lazagne-lsa' }, S, source));
          _add_plaintext_credential(facts, ws, source, targetDefUser, decDefPw, defDom || C._domain_from_facts(ws), 'lazagne-lsa', '');
        }
      }
    }

    // Structured operator/harvested credential notes: "<label>: <user>/<secret>" and "<user> ... NTLM: <32hex>"
    var isFileRead = _FILE_READ_CMD_RE.test(command || '') || _expects_cred_kind(ws, 'credential.plaintext');
    if (isFileRead) {
      var noteLines = text.split(/\r?\n/);
      for (var nli = 0; nli < noteLines.length; nli++) {
        var nm = /^\s*([A-Za-z0-9_.-]{2,32}(?:[ \t]+[A-Za-z0-9_.-]{1,24}){0,2})\s*:\s*([A-Za-z0-9_.$-]{2,32})\/([^\s\/]{4,64})\s*$/.exec(noteLines[nli]);
        if (!nm) continue;
        var nLabel = nm[1], nRawUser = nm[2], nSecret = nm[3];
        if (_NOTE_SCHEME_DENY_RE.test(nLabel)) continue;
        if (/^\d+$/.test(nRawUser) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(nRawUser) || _NOTE_USER_DENY_RE.test(nRawUser)) continue;
        if (_NOTE_SECRET_EXT_DENY_RE.test(nSecret)) continue;
        var nCleanU = C._clean_username(nRawUser);
        if (!C._valid_username(nCleanU, false) || !C._valid_password(nSecret)) continue;
        _add(facts, mkFact('credential.candidate', hScope, { kind: 'credential_note', label: nLabel, user: nCleanU, password: nSecret, via: 'cred-note' }, S, source));
        _add_plaintext_credential(facts, ws, source, nCleanU, nSecret, C._domain_from_facts(ws), 'cred-note', '');
      }
    }

    if (!/sekurlsa::|lsadump::|Authentication Id\s*:/i.test(text)) {
      var inlineNtRe = /^\s*(?:[-*+]\s*)?(?:([A-Za-z0-9_.-]{1,64})\\)?([A-Za-z0-9_.$-]{2,32})(?![A-Za-z0-9_.$\\-])[^\r\n]{0,40}?\bNTLM\s*:\s*([0-9a-fA-F]{32})\b/gim, inm;
      while ((inm = inlineNtRe.exec(text)) !== null) {
        var inExplicitDom = (inm[1] || '').trim(), inRawU = inm[2], inNt = inm[3].toLowerCase();
        if (/^(?:hash|ntlm|lm|sha1|md5|password|passwd|user|username|login|domain|rid|sid|nt)$/i.test(inRawU)) continue;
        if (inNt === '31d6cfe0d16ae931b73c59d7e0c089c0' || inNt === 'aad3b435b51404eeaad3b435b51404ee') continue;
        var inUser = C._clean_username(inRawU);
        if (!C._valid_username(inUser, false) || /\$$/.test(inUser)) continue;
        var inDom = (inExplicitDom && inExplicitDom.indexOf('.') >= 0 ? inExplicitDom : '') || C._domain_from_facts(ws);
        var inScope = C._scope_for_domain(ws, inDom);
        var inVal = { user: inUser, nthash: inNt, method: 'cred-note', hash_type: 'ntlm' };
        if (inDom) inVal.domain = inDom;
        _add(facts, mkFact('hash.ntlm', inScope, { count: 1, entries: [{ user: inUser, nthash: inNt }], user: inUser, nthash: inNt, via: 'cred-note' }, S, source));
        _add(facts, mkFact('credential.ntlm_hash', inScope, inVal, S, source));
        _add(facts, mkFact('credential.available', inScope, inVal, S, source));
        _add(facts, mkFact('credential.candidate', inScope, { kind: 'ntlm_hash', user: inUser, nthash: inNt, via: 'cred-note' }, S, source));
      }
    }

    if (!C._is_cracking_command(command || '') && !/Status\.+:\s*Cracked/i.test(text)) {
      _NETNTLM_BLOB_RE.lastIndex = 0;
      var nbm;
      while ((nbm = _NETNTLM_BLOB_RE.exec(text)) !== null) {
        var afterBlob = text.slice(nbm.index + nbm[0].length, nbm.index + nbm[0].length + 2);
        if (afterBlob.charAt(0) === ':' && afterBlob.charAt(1) && !/\s/.test(afterBlob.charAt(1))) continue;
        var nbUser = C._clean_username(nbm.groups.user);
        if (!nbUser || !C._valid_username(nbUser, false)) continue;
        var nbFmt = nbm.groups.resp.length === 48 ? 'netntlmv1' : 'netntlmv2';
        var nbDom = nbm.groups.dom || '';
        var nbFull = nbm[0];
        _add(facts, mkFact('credential.netntlm', hScope, { kind: nbFmt, user: nbUser, users: [nbUser], domain: nbDom, count: 1, via: 'netntlm' }, S, source));
        _add(facts, mkFact('credential.candidate', hScope, { kind: nbFmt, user: nbUser, domain: nbDom, hash: nbFull, via: 'netntlm' }, S, source));
        _add(facts, mkFact('hash.candidate', hScope, { user: nbUser, domain: nbDom, hash: nbFull, format: nbFmt, via: 'netntlm' }, S, source));
        _add(facts, mkFact('hash.crackable', hScope, { user: nbUser, domain: nbDom, hash: nbFull, format: nbFmt, via: 'netntlm' }, S, source));
      }
    }

    if (!/access denied|authentication fail|logon failure|login failed|STATUS_LOGON_FAILURE|ERROR 1045/i.test(text)) {
      _unwrap_format_list_lines(text).split(/\r?\n/).forEach(function (line) {
        if (_ATTACKER_CMD_LINE_RE.test(line)) return;
        _CMD_CRED_RE.lastIndex = 0;
        var cm;
        while ((cm = _CMD_CRED_RE.exec(line)) !== null) {
          var cUser = C._clean_username(cm.groups.user);
          var cPw = (cm.groups.pw || '').trim();
          if (/^(?:controlleduser|targetuser|username|user|victim|<user>)$/i.test(cUser) && (/^(?:itspassword|password|pass|<password>)$/i.test(cPw) || /\bdomain\.local\b/i.test(line))) continue;
          if (/^controlleduser$/i.test(cUser) || /^itspassword$/i.test(cPw)) continue;
          if (!C._valid_username(cUser, false)) continue;
          var decCliPw = _decode_cli_base64_secret(cPw);
          if (decCliPw && C._valid_password(decCliPw)) {
            _add(facts, mkFact('credential.candidate', hScope, { kind: 'process_cli_secret', user: cUser, password: decCliPw, encoded: cPw, via: 'process-leak' }, S, source));
            _add_plaintext_credential(facts, ws, source, cUser, decCliPw, C._domain_from_facts(ws), 'process-leak', '');
            continue;
          }
          if (!C._valid_password(cPw)) continue;
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
        _add(facts, mkFact('hash.crackable', hScope, { user: jUser, hash: jPw, via: 'api-leak' }, S, source));
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
        _add(facts, mkFact('hash.crackable', hScope, { user: jrUser, hash: jrPw, via: 'api-leak' }, S, source));
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

    if (/\bprivilege[ \t]+\d+\b|\b(?:password|secret)[ \t]+[05789][ \t]+\S|\benable[ \t]+(?:secret|password)\b|^![ \t]*$/im.test(text)) {
      _CISCO_CONFIG_CRED_RE.lastIndex = 0;
      var ciscoM;
      while ((ciscoM = _CISCO_CONFIG_CRED_RE.exec(text)) !== null) {
        var ciscoUser = C._clean_username(ciscoM.groups.user);
        var ciscoPw = (ciscoM.groups.pw || '').trim();
        if (C._valid_username(ciscoUser, false) && C._valid_password(ciscoPw)) {
          _add_plaintext_credential(facts, ws, source, ciscoUser, ciscoPw, C._domain_from_facts(ws), 'cisco-config', '');
        }
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
        _add(facts, mkFact('hash.candidate', 'host:' + ws.target, { user: 'admin', hash: cfHash, format: 'raw-sha1', via: 'coldfusion' }, S, source));
        _add(facts, mkFact('hash.crackable', 'host:' + ws.target, { user: 'admin', hash: cfHash, format: 'raw-sha1', via: 'coldfusion' }, S, source));
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

    // Headed bulleted credential lists (e.g., "Local Admin Passwords:\n- user: secret")
    if (!hasInteractiveAuthFail && /^\s*(?:#+\s*)?(?:[\w\s]{0,24}\b)?(?:passwords?|credentials?|logins?|accounts?)\s*:\s*$/im.test(text)) {
      var bLines = text.split(/\r?\n/);
      var inBulletSection = false;
      for (var bi = 0; bi < bLines.length; bi++) {
        var bLn = bLines[bi];
        if (/^\s*(?:#+\s*)?(?:[\w\s]{0,24}\b)?(?:passwords?|credentials?|logins?|accounts?)\s*:\s*$/i.test(bLn)) {
          inBulletSection = true;
          continue;
        }
        if (!inBulletSection) continue;
        if (!bLn.trim()) continue;
        var bm = /^\s*[-*+]\s*([A-Za-z0-9_.\\@-]{2,64})\s*:\s*([^\s'"]{3,80})\s*$/.exec(bLn);
        if (!bm) {
          inBulletSection = false;
          continue;
        }
        var bRawU = bm[1], bPw = bm[2].trim(), bDom = '';
        if (bRawU.indexOf('\\') >= 0) {
          var bParts = bRawU.split('\\');
          bDom = bParts[0].trim();
          bRawU = bParts.slice(1).join('\\');
        }
        if (_NOTE_SCHEME_DENY_RE.test(bRawU) || _NOTE_USER_DENY_RE.test(bRawU)) continue;
        if (/^(?:active|inactive|enabled|disabled|locked|unlocked|expired|valid|invalid|present|absent|yes|no|true|false|none|null|n\/a|tbd|todo|unknown|standard|member|owner)$/i.test(bPw)) continue;
        var bCleanU = C._clean_username(bRawU);
        if (!C._valid_username(bCleanU, false) || !C._valid_password(bPw)) continue;
        var bScope = (bDom && bDom.indexOf('.') >= 0) ? C._scope_for_domain(ws, bDom) : hScope;
        _add(facts, mkFact('credential.candidate', bScope, { kind: 'credential_list', user: bCleanU, password: bPw, domain: bDom, via: 'bulleted-list' }, S, source));
        _add_plaintext_credential(facts, ws, source, bCleanU, bPw, bDom || C._domain_from_facts(ws), 'bulleted-list', '');
      }
    }

    // Paired variable/config assignments within 5 lines (*Login / *Pw, *_user / *_pass, .cfg user= / pass=)
    if (!hasInteractiveAuthFail && !/^\s*(?:SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+/im.test(text)) {
      var kvLines = text.split(/\r?\n/);
      var userVars = [], passVars = [];
      var isCodeLike = /\b(?:function|def|class|import|require|return)\b/.test(text);
      for (var kvi = 0; kvi < kvLines.length; kvi++) {
        var kvLn = kvLines[kvi];
        if (!kvLn || kvLn.length > 240 || _ATTACKER_CMD_LINE_RE.test(kvLn) || /^\s*(?:\/\/|\/\*|\*|--|;)/.test(kvLn)) continue;
        var kvM = /^\s*(?:(?:var|let|const|my|local|export|set|private|public|string|String)\s+)?(\$?[A-Za-z][A-Za-z0-9_.-]{1,48})\s*[:=]\s*(?:(['"])([^'"\r\n]{2,96})\2|([^\s'"#;,()[\]{}]{2,96}))\s*[;,]?\s*$/.exec(kvLn);
        if (!kvM) continue;
        var rawKey = kvM[1].replace(/^\$/, '');
        var isQuoted = !!kvM[2];
        var rawVal = (isQuoted ? kvM[3] : kvM[4] || '').trim();
        if (!rawVal || (!isQuoted && (isCodeLike || /^\$/.test(kvM[1]) || /^(?:args|opts|options|self|this|req|request|params|form|data|env|os|sys|config|cfg|row|item|obj)\./i.test(rawVal)))) continue;
        if (/^(?:\$[A-Za-z_]|{{|<[A-Za-z_]|%[A-Za-z_]|env\(|os\.|process\.env)/i.test(rawVal) || /\$\(|\$\{|`/.test(rawVal) || (!isQuoted && /^[A-Za-z0-9_.-]+:$/.test(rawVal))) continue;
        var isUserKey = /(?:[a-z0-9](?:User(?:name)?|Login|Uid|Account))$/.test(rawKey) || /(?:^|[._-])(?:user(?:name)?|login|uid|account)$/i.test(rawKey);
        var isPassKey = /(?:[a-z0-9](?:Pass(?:word|wd)?|Pwd|Pw|Secret))$/.test(rawKey) || /(?:^|[._-])(?:pass(?:word|wd)?|pwd|pw|secret)$/i.test(rawKey);
        if (isUserKey && !isPassKey) userVars.push({ line: kvi, key: rawKey, val: rawVal });
        else if (isPassKey && !isUserKey) passVars.push({ line: kvi, key: rawKey, val: rawVal });
      }
      if (userVars.length && passVars.length) {
        var usedPass = {};
        for (var uvi = 0; uvi < userVars.length; uvi++) {
          var uv = userVars[uvi], bestPv = null, bestDist = 99;
          for (var pvi = 0; pvi < passVars.length; pvi++) {
            if (usedPass[pvi]) continue;
            var dist = Math.abs(uv.line - passVars[pvi].line);
            if (dist <= 5 && dist < bestDist) { bestDist = dist; bestPv = pvi; }
          }
          if (bestPv === null) continue;
          usedPass[bestPv] = true;
          var pvVal = passVars[bestPv].val;
          var uvRaw = uv.val, uvDom = '';
          if (uvRaw.indexOf('\\') >= 0) {
            var uvParts = uvRaw.split('\\');
            uvDom = uvParts[0].trim();
            uvRaw = uvParts.slice(1).join('\\');
          }
          var uvClean = C._clean_username(uvRaw);
          if (/^(?:controlleduser|targetuser|your_?user(?:name)?|example|placeholder)$/i.test(uvClean) || /^(?:itspassword|your_?pass(?:word)?|changeme|placeholder)$/i.test(pvVal)) continue;
          if (!C._valid_username(uvClean, false)) continue;
          if (_looks_like_password_hash(pvVal)) {
            _add(facts, mkFact('credential.candidate', hScope, { kind: 'config_hash', user: uvClean, hash: pvVal, via: 'config-pair' }, S, source));
            _add(facts, mkFact('hash.candidate', hScope, { user: uvClean, hash: pvVal, via: 'config-pair' }, S, source));
            _add(facts, mkFact('hash.crackable', hScope, { user: uvClean, hash: pvVal, via: 'config-pair' }, S, source));
          } else if (C._valid_password(pvVal)) {
            var kvScope = (uvDom && uvDom.indexOf('.') >= 0) ? C._scope_for_domain(ws, uvDom) : hScope;
            _add(facts, mkFact('credential.candidate', kvScope, { kind: 'config_pair', user: uvClean, password: pvVal, domain: uvDom, via: 'config-pair' }, S, source));
            _add_plaintext_credential(facts, ws, source, uvClean, pvVal, uvDom || C._domain_from_facts(ws), 'config-pair', '');
          }
        }
      }
    }
  }
  C._parse_generic_dumped_credentials = _parse_generic_dumped_credentials;

  function _looks_like_tshark_http(text, command) {
    return !!text && (/\btshark\b/i.test(command || '') || /HTML Form URL Encoded:/i.test(text) || (/^Frame \d+:/m.test(text) && /Form item:\s*"/i.test(text)));
  }
  C._looks_like_tshark_http = _looks_like_tshark_http;

  function _parse_tshark_http_creds(text, ws, command, source, facts) {
    if (!_looks_like_tshark_http(text, command)) return;
    text = text.replace(C._ANSI_RE, '');
    var hScope = 'host:' + ws.target;
    var hasHttpOk = /HTTP\/1\.[01]\s+(?:200|302)\b/.test(text);
    var frames = /^Frame \d+:/m.test(text) ? text.split(/^Frame \d+:/m) : text.split(/HTML Form URL Encoded:/i);
    var seenPair = {};
    for (var fi = 0; fi < frames.length; fi++) {
      var blk = frames[fi];
      if (!/Form item:\s*"/i.test(blk)) continue;
      var fUser = '', fPass = '', fm;
      var formRe = /^\s*Form item:\s*"([^"]+)"\s*=\s*"([^"]*)"/gim;
      while ((fm = formRe.exec(blk)) !== null) {
        var fKey = fm[1].trim(), fVal = fm[2].trim();
        if (!fVal) continue;
        if (!fUser && /^(?:user(?:name|_name)?|login|email|e-mail|uid|uname|account|userid)$/i.test(fKey)) fUser = fVal;
        else if (!fPass && /^(?:pass(?:word|wd)?|pwd|secret|user_pass|login_pass)$/i.test(fKey)) fPass = fVal;
      }
      if (!fUser || !fPass) continue;
      var fDom = '';
      if (fUser.indexOf('\\') >= 0) {
        var fp = fUser.split('\\');
        fDom = fp[0].trim();
        fUser = fp.slice(1).join('\\');
      }
      var cleanU = C._clean_username(fUser);
      if (!C._valid_username(cleanU, false) || !C._valid_password(fPass)) continue;
      var pk = cleanU.toLowerCase() + '|' + fPass;
      if (seenPair[pk]) continue;
      seenPair[pk] = true;
      var fScope = (fDom && fDom.indexOf('.') >= 0) ? C._scope_for_domain(ws, fDom) : hScope;
      _add(facts, mkFact('credential.candidate', fScope, { kind: 'http_form', user: cleanU, password: fPass, domain: fDom, http_response_seen: hasHttpOk, via: 'tshark-http-form' }, S, source));
      _add_plaintext_credential(facts, ws, source, cleanU, fPass, fDom || C._domain_from_facts(ws), 'tshark-http-form', '');
    }
  }
  C._parse_tshark_http_creds = _parse_tshark_http_creds;

  var _FLAG_MARK_RE = /===FLAG:\s*(?<path>[^\r\n]*?)::(?<body>[^\r\n]*)/g;
  var _FLAG_TOKEN = '(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64}|(?:HTB|FLAG|THM|OSCP|PG|CTF)\\{[^}\\r\\n]{3,}\\}|\\{[0-9A-Za-z_@!#%.:\\-]{3,}\\}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})';
  var _FLAG_VALUE_ANCHORED = new RegExp('^' + _FLAG_TOKEN + '$', 'i');
  var _FLAG_FILE_IN_CMD_RE = /(?:\btype\b|\bcat\b|\bmore\b|\bhead\b|\btail\b|\bbat\b|\bless\b|\bgrep\b|Get-Content|\bgc\b|Select-String|--get-file|\bget\b)\s+['"]?(?<file>(?:[A-Za-z]:[\\/](?:[^\\/<>:"'|?*&;)\r\n]+[\\/])+|\/(?:[^/"'\s&|;)\r\n]+\/)+|(?:[a-zA-Z0-9._-]+\.txt:))?(?:local|proof|user|root|flag\d?)\.txt)/i;
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
    var s = String(line);
    if (!/[>$#%└├]|\b(?:SMB|WINRM|WMI|RPC|SSH|RDP|MSSQL)\s+/i.test(s)) return s;
    return s
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
    var hay = (text || '') + '\n' + (command || '');
    var hasTxtSub = hay.indexOf('.txt') >= 0 || hay.indexOf('.TXT') >= 0 || /\.txt/i.test(command || '');
    var hasFlagFilenameCtx = (hasTxtSub && /\b(?:local|proof|user|root|flag\d?)\.txt\b/i.test(hay)) || /flag-hunt/i.test(String(source || '') + ' ' + String(command || ''));
    var hasFlagMark = !!(text && text.indexOf('===FLAG:') >= 0);
    var hasBraceFlag = (text && text.indexOf('{') >= 0) ? /\{[^}\r\n]{3,}\}/.test(text) : false;
    var isShortPaste = !text || text.length < 24000;
    if (!isShortPaste && !hasFlagFilenameCtx && !hasFlagMark && !hasBraceFlag && !/root|system|administrator/i.test(hay)) return;
    var textRemote = /^\s*(?:SMB|WINRM|WMI|RPC|SSH|RDP|MSSQL|LDAP|FTP)\s+\S+\s+\d+\s+/im.test(text || '')
      || /\[\+\]\s*Spidering\b|\bvia\s+(?:wmiexec|smbexec|psexec|atexec|dcomexec)\b/i.test(text || '');
    var cmdRemote = (!!(command && String(command).trim()) && _REMOTE_LEAD_RE.test(command)) || textRemote;
    var isBulkEnumNoise = /Linux Privilege Escalation Awesome Script|linpeas|winpeas|══╣|\/etc\/machine-id|blkid|fstab|Dumping Domain Credentials|sekurlsa::/i.test(hay);
    var hasRootCtx = (hasTxtSub && /\b(?:proof\.txt|root\.txt)\b/i.test(hay)) || /flag-hunt-root/i.test(String(source || '') + ' ' + String(command || '')) || (!isBulkEnumNoise && /root|system|administrator/i.test(hay) && (/\b(?:uid=0\(root\)|nt authority\\system)\b/i.test(hay) || /^(?:root|nt authority\\system|(?:[A-Za-z0-9._-]+\\)?administrator)\s*$/im.test(text || '')));
    function mint(path, flag, slotHint, onHost, forceCaptureKind) {
      if (!flag) return;
      var base = String(path || '').split(/[\\/]/).pop() || '';
      var slot = slotHint || _slot_for_flagfile(base);
      var seenKey = (slot || '') + ':' + flag;
      if (seen[seenKey]) return;
      seen[seenKey] = 1;
      var isExec = command && /-[xX]\b|--get-file|wmiexec|psexec|smbexec|atexec|dcomexec|smbclient.*get|evil-winrm|\bssh\b/i.test(command);
      var kind = (onHost || isExec || forceCaptureKind) ? _flag_kind(slot) : 'objective.flag_located';
      _add(facts, mkFact(kind, scope, { flag: flag, slot: slot, name: base, path: path || '', on_host: !!onHost }, S, source));
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
    function mintPath(path, slot, forceRemote) {
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
      var isOnHost = !(cmdRemote || forceRemote);
      _add(facts, mkFact('objective.flag_located', scope, { slot: actualSlot, name: base, path: clean, on_host: isOnHost }, S, source));
      if (actualSlot === 'root' || actualSlot === 'local') {
        _add(facts, mkFact('objective.flag_located_' + actualSlot, scope, { slot: actualSlot, name: base, path: clean, on_host: isOnHost }, S, source));
      }
    }
    function _smbRelToWinPath(relPath) {
      var rel = String(relPath || '').trim().replace(/^[/\\]+/, '').replace(/[/\\]+/g, '\\');
      if (!rel || rel.indexOf('\\') === -1) return '';
      if (/^[A-Za-z]:\\/.test(rel)) return rel;
      if (/^Users\\/i.test(rel)) return 'C:\\' + rel;
      var shareDrive = /(?:\/\/|\\\\)[^\s/\\]+[/\\]([A-Za-z])\$(?:\b|$)|--share\s+['"]?([A-Za-z])\$['"]?/i.exec(hay);
      if (shareDrive) {
        var drv = (shareDrive[1] || shareDrive[2] || 'C').toUpperCase();
        return drv + ':\\' + rel;
      }
      return 'C:\\Users\\' + rel;
    }
    var smbGetBySlot = {};
    if (hasFlagFilenameCtx) {
      var _SMB_GET_REL_RE = /(?:getting file\s+[\\/]|(?:\[\+\]\s*File|\[\*\]\s*Copying)\s+['"]?|--get-file\s+['"]?|\bget\s+['"])(?<rel>[A-Za-z0-9_.\-\\/ ]+?[\\/](?:local|proof|user|root|flag\d?)\.txt)(?=['"\s]|$)/gi;
      var sgm;
      while ((sgm = _SMB_GET_REL_RE.exec(hay)) !== null) {
        var sgWin = _smbRelToWinPath(sgm.groups.rel);
        if (sgWin) {
          var sgSlot = _slot_for_flagfile(sgWin);
          smbGetBySlot[sgSlot] = sgWin;
          mintPath(sgWin, sgSlot, true);
        }
      }
    }
    if (hasFlagMark) {
      var m; _FLAG_MARK_RE.lastIndex = 0;
      while ((m = _FLAG_MARK_RE.exec(text))) {
        var body = (m.groups.body || '').trim();
        if (_FLAG_VALUE_ANCHORED.test(body)) {
          mint(m.groups.path, body, _slot_for_flagfile(m.groups.path), true);
          mintPath(m.groups.path, _slot_for_flagfile(m.groups.path));
        }
      }
    }
    var curFiles = [];
    if (hasFlagFilenameCtx && command) {
      var cmdRe = new RegExp(_FLAG_FILE_IN_CMD_RE.source, 'gi'), cm;
      while ((cm = cmdRe.exec(command)) !== null) {
        var cmSlot = _slot_for_flagfile(cm.groups.file);
        var cmFile = (cm.groups.file.indexOf('\\') === -1 && cm.groups.file.indexOf('/') === -1 && smbGetBySlot[cmSlot]) ? smbGetBySlot[cmSlot] : cm.groups.file;
        curFiles.push({ file: cmFile, slot: cmSlot, onHost: !cmdRemote });
      }
    }
    var trimmedWhole = (text && text.length <= 128) ? String(text).trim() : '';
    var allLines = null;
    var hasUserCtx = hasFlagFilenameCtx || (trimmedWhole.length === 32 && /^[0-9a-fA-F]{32}$/.test(trimmedWhole));
    if (!hasUserCtx && !isBulkEnumNoise && isShortPaste && /\b(?:whoami|ip\s+a|ifconfig|ipconfig)\b/i.test(hay)) {
      allLines = String(text || '').split(/\r?\n/);
      if (allLines.length <= 120) hasUserCtx = true;
    }
    if (hasFlagFilenameCtx || hasFlagMark || hasUserCtx || hasRootCtx || hasBraceFlag) {
      if (!allLines) allLines = String(text || '').split(/\r?\n/);
      if (hasFlagFilenameCtx && text && text.indexOf('"') >= 0) {
        var joinedLines = [];
        for (var li = 0; li < allLines.length; li++) {
          var curL = allLines[li];
          if (curL.indexOf('"') >= 0 && ((curL.match(/"/g) || []).length % 2 === 1) && li + 1 < allLines.length && /\b(?:type|cat|more|head|tail|Get-Content|gc)\b/i.test(curL) && /\.txt["']?/i.test(allLines[li + 1])) {
            curL = curL + allLines[++li];
          }
          joinedLines.push(curL);
        }
        allLines = joinedLines;
      }
      allLines.forEach(function (l) {
        if (!l || l.length > 1024) return;
        var bare = _strip_prompt(l);
        var tok = bare.trim();
        if (!tok) return;
        if (hasFlagMark && tok.indexOf('===FLAG:') === 0) {
          var flagMarkHdr = /^===FLAG:\s*([^\r\n]+?)::\s*(.*)$/i.exec(tok);
          if (flagMarkHdr) {
            var fmPath = flagMarkHdr[1].trim();
            var fmBody = (flagMarkHdr[2] || '').trim();
            var fmSlot = _slot_for_flagfile(fmPath);
            mintPath(fmPath, fmSlot);
            if (fmBody && _FLAG_VALUE_ANCHORED.test(fmBody)) {
              mint(fmPath, fmBody, fmSlot, true);
              curFiles = [];
            } else {
              curFiles = [{ file: fmPath, slot: fmSlot, onHost: true }];
            }
            return;
          }
        }
        if (hasFlagFilenameCtx) {
          var dashHdr = tok.indexOf('---') === 0 ? /^---\s*["']?(\/(?:[^/\r\n]+\/)+(?:local|proof|user|root|flag\d?)\.txt|[A-Za-z]:[\\/](?:[^\\/\r\n]+[\\/])+(?:local|proof|user|root|flag\d?)\.txt)["']?\s*---$/i.exec(tok) : null;
          if (dashHdr) {
            curFiles = [{ file: dashHdr[1], slot: _slot_for_flagfile(dashHdr[1]), onHost: !cmdRemote }];
            mintPath(dashHdr[1], _slot_for_flagfile(dashHdr[1]));
            return;
          }
          var bareRe = new RegExp(_FLAG_FILE_IN_CMD_RE.source, 'gi'), bm, bareMatched = [];
          while ((bm = bareRe.exec(bare)) !== null) {
            var bmSlot = _slot_for_flagfile(bm.groups.file);
            var bmFile = (bm.groups.file.indexOf('\\') === -1 && bm.groups.file.indexOf('/') === -1 && smbGetBySlot[bmSlot]) ? smbGetBySlot[bmSlot] : bm.groups.file;
            bareMatched.push({ file: bmFile, slot: bmSlot, onHost: !_REMOTE_LEAD_RE.test(bare) });
          }
          if (bareMatched.length) { curFiles = bareMatched; return; }
          if (!/[<>|]/.test(tok)) {
            if (_BARE_WIN_FLAGPATH_RE.test(tok)) { mintPath(tok.replace(/[/]+/g, '\\'), _slot_for_flagfile(tok.split(/[\\/]/).pop())); return; }
            if (_BARE_NIX_FLAGPATH_RE.test(tok)) { mintPath(tok, _slot_for_flagfile(tok.split(/[\\/]/).pop())); return; }
          }
        }
        if (l !== bare && tok && !_FLAG_VALUE_ANCHORED.test(tok)) {
          curFiles = [];
        }
        if (curFiles.length && _FLAG_VALUE_ANCHORED.test(tok)) {
          var cf = curFiles.shift();
          mint(cf.file, tok, cf.slot, cf.onHost);
          if (cf.file && /[\\/]/.test(cf.file)) mintPath(cf.file, cf.slot, !cf.onHost);
        } else if (!curFiles.length && _FLAG_VALUE_ANCHORED.test(tok)) {
          var hasInteractivePromptInText = /^\s*(?:\*?Evil-WinRM\*?\s*PS\s+[A-Za-z]:\\|PS\s+[A-Za-z]:\\|[A-Za-z]:\\[^>\r\n]*>|[\w.-]+@[\w.-]+:[^$#\r\n]*[$#])/im.test(text || '');
          var defaultOnHost = !cmdRemote || hasInteractivePromptInText;
          if (/^(?:HTB|FLAG|THM|OSCP|PG|CTF)\{[^}\r\n]{3,}\}$/i.test(tok)) {
            mint(smbGetBySlot[hasRootCtx ? 'root' : 'local'] || (hasRootCtx ? 'proof.txt' : 'user.txt'), tok, hasRootCtx ? 'root' : 'local', defaultOnHost, true);
          } else if (/^[0-9a-fA-F]{32}$/.test(tok) && !isBulkEnumNoise) {
            if (hasRootCtx && (hasFlagFilenameCtx || allLines.length <= 120)) {
              mint(smbGetBySlot.root || 'proof.txt', tok, 'root', defaultOnHost, true);
            } else if (hasUserCtx) {
              mint(smbGetBySlot.local || 'local.txt', tok, 'local', defaultOnHost, true);
            }
          }
        }
      });
    }
    if (hasFlagFilenameCtx) {
      // 3) LOCATE: a spider/dir listing of flag-file paths (no value) -> record each location + its exact path.
      var sp; _SPIDER_PATH_RE.lastIndex = 0;
      while ((sp = _SPIDER_PATH_RE.exec(text))) {
        var drive = sp[1] ? (sp[1].toUpperCase() + ':\\') : 'C:\\Users\\';
        var winPath = drive + String(sp[2]).replace(/[/\\]+/g, '\\');
        var pbase = winPath.split(/[\\/]/).pop() || '';
        mintPath(winPath, _slot_for_flagfile(pbase), true);
      }
      // 3b) LOCATE from smbclient -c 'recurse; ls' or smbmap -R directory listings
      var curSmbDir = '';
      var _SMB_DIR_HDR_RE = /^(?:\.[\\/]|\\)([A-Za-z0-9_.\-\\/ ]+?)\s*$/;
      var _SMB_FILE_ROW_RE = /^(?:-[rwx-]{9}\s+\d+\s+[^\r\n]+?\s+(?<f1>(?:local|proof|user|root|flag\d?)\.txt)|(?<f2>(?:local|proof|user|root|flag\d?)\.txt)\s+(?:[ADHSRN]+\s+)?\d+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b.*)$/i;
      allLines.forEach(function (rawLine) {
        var trimmedLine = String(rawLine || '').trim();
        if (!trimmedLine) return;
        var dm = _SMB_DIR_HDR_RE.exec(trimmedLine);
        if (dm) {
          curSmbDir = dm[1].trim().replace(/[/\\]+/g, '\\');
          return;
        }
        if (curSmbDir) {
          var fm = _SMB_FILE_ROW_RE.exec(trimmedLine);
          if (fm) {
            var fn = fm.groups.f1 || fm.groups.f2;
            var fullWin = _smbRelToWinPath(curSmbDir + '\\' + fn);
            if (fullWin) mintPath(fullWin, _slot_for_flagfile(fn), true);
          }
        }
      });
      // 3c) LOCATE from Windows dir /r (Alternate Data Streams)
      var _ADS_DIR_R_RE = /(?<![a-zA-Z0-9._-])(?<fn>[a-zA-Z0-9._-]{1,120}\.txt):(?<stream>(?:local|proof|user|root|flag\d?)\.txt):\$DATA\b/gi;
      var adsMatch;
      while ((adsMatch = _ADS_DIR_R_RE.exec(text)) !== null) {
        var adsTarget = adsMatch.groups.fn + ':' + adsMatch.groups.stream;
        mintPath(adsTarget, _slot_for_flagfile(adsTarget.split(':').pop()));
      }
      // 3d) LOCATE from parsed on-host / share directory listings (cmd dir / PowerShell Get-ChildItem)
      facts.forEach(function (lf) {
        if (!lf || lf.kind !== 'loot.files' || !lf.value) return;
        var isSmbShare = lf.value.via === 'smb-share';
        var rawEntries = Array.isArray(lf.value.entries) ? lf.value.entries.map(function (e) { return e && e.path; }) : (lf.value.files || []);
        rawEntries.forEach(function (fp) {
          if (!fp || !/[\\/]/.test(fp)) return;
          if (!/(?:^|[\\/])(?:local|proof|user|root|flag\d?)\.txt$/i.test(fp)) return;
          var locPath = isSmbShare ? _smbRelToWinPath(fp) : fp;
          if (locPath) mintPath(locPath, _slot_for_flagfile(locPath.split(/[\\/]/).pop()), isSmbShare);
        });
      });
    }
    _parse_backdoor_created(text, ws, command, source, facts);
  }
  // A bare flag-file path on its own line, as a recursive search prints it. Anchored start-to-end so only a
  // whole-line path matches (never a path embedded in a `type`/`cat` command echo or an `===FLAG:` marker).
  var _BARE_WIN_FLAGPATH_RE = /^[A-Za-z]:[\\/](?:[^\\/\r\n]+[\\/])+(?:local|proof|user|root|flag\d?)\.txt$/i;
  var _BARE_NIX_FLAGPATH_RE = /^\/(?:[^/\r\n]+\/)+(?:local|proof|user|root|flag\d?)\.txt$/i;
  C._parse_flags = _parse_flags;

  // Auto-mint created backdoor accounts (net user <u > <pw> /add or bloodyAD add user <u> <pw>)
  var _NET_USER_ADD_RE = /\bnet\s+user\s+["']?(?<user>[A-Za-z0-9_.-]+)["']?\s+["']?(?<pw>[^\s"'&|;]+)["']?\s+(?:\/domain\s+)?\/add(?<domAfter>\s+\/domain)?\b/gi;
  var _BLOODYAD_ADD_USER_RE = /\bbloodyAD\b[^\r\n]*?\badd\s+user\s+["']?(?<user>[A-Za-z0-9_.-]+)["']?\s+["']?(?<pw>[^\s"'&|;]+)["']?/gi;
  function _escapeRegExp(s) { return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function _parse_backdoor_created(text, ws, command, source, facts) {
    var hay = String(command || '') + '\n' + String(text || '');
    if (!/\bnet\s+user\b|\bbloodyAD\b|\bnet\s+localgroup\b|\bnet\s+group\b|fDenyTSConnections|Remote\s+Desktop\s+Users|TermService|Remote\s+Management\s+Users|winrm\s+quickconfig|Enable-PSRemoting|AllowAutoConfig|WinRMInit/i.test(hay)) return;
    var outText = String(text || '');
    var scope = 'host:' + ((ws && ws.target) || 'target');
    var defaultDom = (C._domain_from_facts && C._domain_from_facts(ws)) || (ws && ws.domainSeed) || '';
    var domMatch = /\s-d\s+["']?([A-Za-z0-9._-]+)["']?/i.exec(hay);
    if (domMatch && domMatch[1]) defaultDom = domMatch[1];

    var winrmFail = /\b(?:Set-WSManQuickConfig\s*:\s*Access is denied|WsManError|WSManFault|Microsoft\.WSMan\.Management\.SetWSManQuickConfigCommand)\b|Errno::ECONNREFUSED[^\r\n]*5985/i.test(outText);
    var rdpFail = /\b(?:OpenSCManager\s+FAILED\s+5)\b|reg:\s*ERROR:\s*Access is denied/i.test(outText);
    var opSuccess = /The (?:command|operation) completed successfully|WinRM (?:service )?is already|WinRM has been updated|SUCCESS:\s*The scheduled task|\[\+\]\s*Executed command/i.test(outText);
    if (opSuccess) {
      if (!rdpFail && /fDenyTSConnections[^\r\n]*\/d\s+0\b|Set-ItemProperty[^\r\n]*fDenyTSConnections[^\r\n]*0\b|net\s+localgroup\s+["']?Remote\s+Desktop\s+Users["']?[^\r\n]*\/add/i.test(hay)) {
        _add(facts, mkFact('host.rdp_enabled', scope, { enabled: true, via: 'remote-enable' }, S, source));
      }
      if (!winrmFail && /net\s+localgroup\s+["']?Remote\s+Management\s+Users["']?[^\r\n]*\/add|\bwinrm\s+quickconfig\b|\bEnable-PSRemoting\b|\bAllowAutoConfig\b|\bWinRMInit\b/i.test(hay)) {
        _add(facts, mkFact('host.winrm_enabled', scope, { enabled: true, via: 'remote-enable' }, S, source));
      }
    }

    function mintBackdoor(user, pw, dom, checkGroupsHay) {
      if (!user || !pw) return;
      var domVal = dom || '';
      _add(facts, mkFact('credential.available', scope, {
        username: user,
        user: user,
        password: pw,
        domain: domVal,
        secret_kind: 'password',
        source: 'backdoor-created'
      }, S, source));
      _add(facts, mkFact('credential.password', scope, {
        username: user,
        user: user,
        password: pw,
        domain: domVal,
        source: 'backdoor-created'
      }, S, source));
      _add(facts, mkFact('credential.plaintext', scope, {
        username: user,
        user: user,
        password: pw,
        domain: domVal,
        source: 'backdoor-created'
      }, S, source));
      _add(facts, mkFact('credential.validated', scope, {
        username: user,
        user: user,
        domain: domVal,
        service: 'smb',
        outcome: 'accepted'
      }, S, source));

      var uEsc = _escapeRegExp(user);
      var adminGrpRe = new RegExp(
        '(?:net\\s+localgroup\\s+["\']?Administrators["\']?\\s+["\']?' + uEsc + '["\']?\\s+\\/add'
        + '|net\\s+group\\s+["\']?Domain\\s+Admins["\']?\\s+["\']?' + uEsc + '["\']?\\s+\\/add'
        + '|bloodyAD\\b[^\\r\\n]*?\\badd\\s+groupMember\\s+["\']?(?:Domain\\s+Admins|Administrators)["\']?\\s+["\']?' + uEsc + '["\']?'
        + '|\\[\\+\\]\\s*["\']?' + uEsc + '["\']?\\s+added\\s+to\\s+["\']?(?:Domain\\s+Admins|Administrators)["\']?)',
        'i'
      );
      if (adminGrpRe.test(checkGroupsHay)) {
        _add(facts, mkFact('access.admin', scope, {
          username: user,
          user: user,
          via: 'backdoor-account'
        }, S, source));
      }
      var rdpGrpRe = new RegExp('net\\s+localgroup\\s+["\']?Remote\\s+Desktop\\s+Users["\']?\\s+["\']?' + uEsc + '["\']?\\s+\\/add', 'i');
      if (rdpGrpRe.test(checkGroupsHay)) {
        _add(facts, mkFact('host.rdp_enabled', scope, { enabled: true, user: user, via: 'backdoor-account' }, S, source));
      }
      var winrmGrpRe = new RegExp('net\\s+localgroup\\s+["\']?Remote\\s+Management\\s+Users["\']?\\s+["\']?' + uEsc + '["\']?\\s+\\/add', 'i');
      if (winrmGrpRe.test(checkGroupsHay)) {
        _add(facts, mkFact('host.winrm_enabled', scope, { enabled: true, user: user, via: 'backdoor-account' }, S, source));
      }
    }

    var netSuccess = /The command completed successfully\.|\[\+\]\s*Executed command/i.test(outText);
    if (netSuccess) {
      _NET_USER_ADD_RE.lastIndex = 0;
      var nm;
      while ((nm = _NET_USER_ADD_RE.exec(hay)) !== null) {
        var nUser = nm.groups.user;
        var nPw = nm.groups.pw;
        var isDom = /\/domain\b/i.test(nm[0]);
        mintBackdoor(nUser, nPw, isDom ? defaultDom : '', hay);
      }
    }

    _BLOODYAD_ADD_USER_RE.lastIndex = 0;
    var bm;
    while ((bm = _BLOODYAD_ADD_USER_RE.exec(hay)) !== null) {
      var bUser = bm.groups.user;
      var bPw = bm.groups.pw;
      var createdRe = new RegExp('\\[\\+\\]\\s*' + _escapeRegExp(bUser) + '\\s+has\\s+been\\s+created', 'i');
      if (createdRe.test(outText)) {
        mintBackdoor(bUser, bPw, defaultDom, hay);
      }
    }
  }
  C._parse_backdoor_created = _parse_backdoor_created;

  // A KeePass database/dump in hand: a located .kdbx file, a keepass2john hash
  // ($keepass$*...), or a master-key recovery dump. Mints loot.keepass_dump so
  // the recover/crack move leads precisely instead of riding the generic "you
  // have loot files" gate. A bare mention with no artifact mints nothing.
  var _KEEPASS_KDBX_RE = /(?:[A-Za-z]:\\[^\r\n"'<>|*?\s]*?\.kdbx|\/[^\r\n"'<>|*?\s]*?\.kdbx|(?<![A-Za-z0-9_.\-$])(?!PATTERN\.kdbx\b)[A-Za-z0-9_$-][A-Za-z0-9_.\-]{0,120}\.kdbx)\b/i;
  var _KEEPASS_HASH_RE = /\$keepass\$\*\d/i;
  var _KEEPASS_FULL_HASH_RE = /\$keepass\$\*\d+\*[^\s'":]+/gi;
  var _KEEPASS_DUMP_RE = /\bkeepass[\w.]*\.(?:dmp|dump)\b|masterkey(?:\.txt)?\b.*keepass|keepass.*master\s*key/i;
  function _parse_keepass_dump(text, ws, command, source, facts) {
    if (!text && !command) return;
    var cleanLines = String(text || '').split(/\r?\n/).filter(function (ln) {
      return !/(?:spider_plus|PATTERN|\*\.kdbx|\.kdbx['"]?\s*(?:-o|2>|\))|-name\s+['"]?\*\.kdbx|-Include\s+['"]?\*\.kdbx)/i.test(ln);
    }).join('\n');
    var cmdHay = /\b(?:spider_plus|find|dir|where|get-childitem|gci|ls|tree)\b/i.test(command || '') ? '' : String(command || '');
    var hay = cleanLines + '\n' + cmdHay;
    var m = reSearch(_KEEPASS_HASH_RE, hay) || reSearch(_KEEPASS_KDBX_RE, hay) || reSearch(_KEEPASS_DUMP_RE, hay);
    if (!m) return;
    var h = 'host:' + ws.target;
    var kdbx = reSearch(_KEEPASS_KDBX_RE, hay);
    var kdbxFile = kdbx ? kdbx[0] : null;
    var hasHash = !!reSearch(_KEEPASS_HASH_RE, hay);
    _add(facts, mkFact('loot.keepass_dump', h, { file: kdbxFile, path: kdbxFile, has_hash: hasHash, via: 'keepass' }, S, source));
    if (hasHash) {
      _KEEPASS_FULL_HASH_RE.lastIndex = 0;
      var khm, seenKp = {};
      while ((khm = _KEEPASS_FULL_HASH_RE.exec(cleanLines)) !== null) {
        var afterCh = cleanLines.charAt(khm.index + khm[0].length);
        if (afterCh === ':') continue;
        var kpHash = khm[0];
        if (seenKp[kpHash]) continue;
        seenKp[kpHash] = true;
        _add(facts, mkFact('hash.crackable', h, { hash: kpHash, format: 'keepass', mode: 13400, via: 'keepass2john' }, S, source));
        _add(facts, mkFact('hash.candidate', h, { hash: kpHash, format: 'keepass', mode: 13400, via: 'keepass2john' }, S, source));
      }
    }
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
    var m = reSearch(/(?:\$rakp\$[^\s]+|(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{40,}:[0-9a-fA-F]{40}))/i, text) ||
      reSearch(/RAKP-(?:HMAC-SHA1|Hash)[^:\r\n]*:\s*([^\r\n]+)/i, text);
    if (!m) return;
    var raw = (m[2] ? (m[1] + ':' + m[2]) : (m[1] || m[0])).trim();
    var user = m[1] && m[2] ? m[1] : 'admin';
    _add(facts, mkFact('hash.candidate', h, { user: user, hash: raw, format: 'rakp', hashcat_mode: 7300, via: 'ipmi' }, S, source));
    _add(facts, mkFact('hash.crackable', h, { user: user, hash: raw, format: 'rakp', hashcat_mode: 7300, via: 'ipmi' }, S, source));
    _add(facts, mkFact('credential.candidate', h, { username: user, hash: raw, kind: 'ipmi_rakp', via: 'ipmi' }, C.ProofState.PARTIAL, source));
  }
  C._parse_ipmi_rakp = _parse_ipmi_rakp;

})(typeof globalThis !== 'undefined' ? globalThis : this);
