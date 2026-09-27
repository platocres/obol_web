/*!
 * obol engine — parsers/directory.js  (AD / directory-services parsers)
 * NOTE: this file was renamed from `ad.js` because content/ad blockers (AdBlock Plus, uBlock)
 * block a script literally named `ad.js` by filename, which silently broke ALL evidence parsing.
 * Faithful JS port of the fixture-reachable parsers in obol-local/obol/parsers/ad.py:
 * nxc/LDAP/SMB enumeration, credential validation, kerberos roast/crack material, evil-winrm,
 * BloodHound collection/analysis, and the ACL/Kerberos/gMSA/LAPS abuse primitives.
 * Proof discipline: roast hash = crackable material, gMSA/LAPS = candidate, a control right
 * or ticket = available material — none is a validated credential or proven access.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED, REF = C.ProofState.REFUTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function _parse_nxc_common(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    C._add_os_from_text(text, ws, source, facts, 'nxc', 'high', true);
    var domain = '';
    var dm = reSearch(C._DOMAIN_RE, text);
    if (dm) {
      domain = dm[1].trim();
      if (domain && domain !== 'None' && domain !== '-') {
        _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
        _add(facts, mkFact('ad.base_dn', 'domain:' + domain, { base_dn: C._base_dn_from_domain(domain) }, S, source));
        _add(facts, mkFact('host.domain', h, { domain: domain }, S, source));
      } else { domain = ''; }
    }
    var nm = reSearch(C._NAME_RE, text);
    if (nm) _add(facts, mkFact('host.hostname', h, { name: nm[1].trim() }, S, source));
    if (nm || domain) {
      var value = { host: ws.target };
      if (nm) value.name = nm[1].trim();
      if (domain) value.domain = domain;
      _add(facts, mkFact('ad.dc_candidate', h, value, S, source));
    }
    var signing = reSearch(C._NXC_SIGNING_RE, text);
    if (signing) {
      var enabled = signing.groups.enabled.toLowerCase() === 'true';
      _add(facts, mkFact('smb.signing', h, { enabled: enabled, tool: 'nxc', flags: enabled ? [] : ['smb_signing_disabled'] }, S, source));
    }
    var smbv1 = reSearch(C._NXC_SMBV1_RE, text);
    if (smbv1) _add(facts, mkFact('smb.smbv1', h, { enabled: smbv1.groups.enabled.toLowerCase() === 'true', tool: 'nxc' }, S, source));

    reAll(C._NXC_PROTO_REACHABLE_RE, text).forEach(function (m) {
      var proto = m.groups.proto.toLowerCase();
      if (['ldap', 'smb', 'winrm', 'rdp', 'ssh', 'ftp'].indexOf(proto) >= 0) _add(facts, mkFact(proto + '.reachable', h, { tool: 'nxc' }, S, source));
      if (proto === 'winrm' || proto === 'rdp') C._add_os_observation(facts, ws, source, 'windows', m[0].trim(), proto === 'winrm' ? 'high' : 'medium', 'nxc', proto === 'winrm');
    });
    if (/^LDAP\s+.*\[\+\].*(?:\\\\:|anonymous|'')/im.test(text)) _add(facts, mkFact('ad.anonymous_bind', C._scope_for_domain(ws, domain), { tool: 'nxc' }, S, source));
  }
  C._parse_nxc_common = _parse_nxc_common;

  function _parse_nxc_smb_session(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var anonymousCommand = command.indexOf("-u ''") >= 0 || command.indexOf('-u ""') >= 0;
    var guestCommand = /\s-u\s+guest\b/i.test(command);
    text.split(/\r?\n/).forEach(function (line) {
      if (!/^\s*SMB\s+/i.test(line) || line.indexOf('[+]') < 0) return;
      var auth = line.split('[+]')[1].trim();
      var authL = auth.toLowerCase();
      if (guestCommand || authL.indexOf('guest') >= 0) _add(facts, mkFact('smb.guest_session', h, { tool: 'nxc' }, S, source));
      if (anonymousCommand || /(?:^|\\):(?:\s|$)/.test(auth) || auth === ':' || auth === '\\:' || auth === '') _add(facts, mkFact('smb.null_session', h, { tool: 'nxc' }, S, source));
    });
  }
  C._parse_nxc_smb_session = _parse_nxc_smb_session;

  function _parse_user_list(text, ws, source, facts, opts) {
    opts = opts || {};
    var users = C._usernames(text);
    if (!users.length) return;
    var domain = opts.domain_hint || C._domain_from_facts(ws);
    _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: users, count: users.length }, S, source));
    if (opts.prove_anonymous_ldap) _add(facts, mkFact('ad.anonymous_bind', C._scope_for_domain(ws, domain), { tool: 'nxc' }, S, source));
  }
  C._parse_user_list = _parse_user_list;

  var _KERBRUTE_USER_RE = /\[\+\]\s+VALID USERNAME:\s*(?<u>[A-Za-z0-9._-]+)(?:@(?<dom>[A-Za-z0-9.-]+))?/;
  var _KERBRUTE_LOGIN_RE = /\[\+\]\s+VALID LOGIN:\s*(?<u>[A-Za-z0-9._-]+)(?:@(?<dom>[A-Za-z0-9.-]+))?:(?<p>\S.*?)\s*$/m;

  function _add_valid_login_credential(ws, source, facts, user, password, domain, method) {
    user = C._clean_username(user);
    if (!C._valid_username(user, false) || !C._valid_password(password)) return;
    var value = { user: user, password: password, method: method };
    if (domain) value.domain = domain;
    _add(facts, mkFact('credential.available', C._scope_for_domain(ws, domain), value, S, source));
  }
  C._add_valid_login_credential = _add_valid_login_credential;

  function _parse_kerbrute(text, ws, source, facts, opts) {
    opts = opts || {};
    var users = [], domain = opts.domain_hint || C._domain_from_facts(ws);
    reAll(_KERBRUTE_USER_RE, text).forEach(function (m) {
      users.push(C._clean_username(m.groups.u));
      domain = domain || (m.groups.dom || '').toLowerCase();
    });
    var seen = {}, uu = [];
    users.forEach(function (u) { if (u && !seen[u]) { seen[u] = true; uu.push(u); } });
    if (uu.length) _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: uu, count: uu.length, method: 'kerbrute' }, S, source));
    reAll(_KERBRUTE_LOGIN_RE, text).forEach(function (m) {
      var dom = (m.groups.dom || domain || '').toLowerCase();
      _add_valid_login_credential(ws, source, facts, m.groups.u, m.groups.p.trim(), dom, 'kerbrute');
    });
  }
  C._parse_kerbrute = _parse_kerbrute;

  var _LOOT_NAME_HINTS = ['password', 'passwд', 'passwd', 'cred', 'secret', 'unattend', 'sysprep', 'web.config', 'connection', 'id_rsa', 'id_ed25519', '.ppk', '.kdbx', '.key', 'vnc', 'vpn', '.bak', 'backup', '.ntds', 'ntds.dit', 'sam', '.vmdk', '.ovpn', 'notes', 'todo', 'database', 'db-connection', '.pfx', '.ps1'];
  var _SMBMAP_FILE_RE = /^\s*fr[-rwxd]{8}\s+(?<size>\d+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s+(?<name>.+?)\s*$/m;
  var _SMBMAP_SECTION_RE = /^\s*\.\\(?<path>[^*\r\n]*)\*\s*$/m;

  function _looks_sensitive(name) {
    var low = name.toLowerCase();
    return _LOOT_NAME_HINTS.some(function (hh) { return low.indexOf(hh) >= 0; });
  }

  function _parse_share_inventory(text, ws, command, source, facts) {
    var h = 'host:' + ws.target, files = [];
    var brace = text.indexOf('{');
    if (brace !== -1) {
      var data = null;
      try { data = JSON.parse(text.slice(brace)); } catch (e) { data = null; }
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        Object.keys(data).forEach(function (share) {
          var entries = data[share];
          if (!entries || typeof entries !== 'object') return;
          Object.keys(entries).forEach(function (path) {
            var meta = entries[path];
            var size = (meta && typeof meta === 'object') ? String(meta.size !== undefined ? meta.size : '') : '';
            files.push({ share: String(share), path: String(path), size: size });
          });
        });
      }
    }
    if (!files.length && command.toLowerCase().indexOf('smbmap') >= 0) {
      var mShare = reSearch(/^\s*(?<name>[A-Za-z0-9_$.-]+)\s+READ/m, text);
      var share = mShare ? mShare.groups.name : '';
      var cur = '';
      text.split(/\r?\n/).forEach(function (line) {
        var sec = reSearch(_SMBMAP_SECTION_RE, line);
        if (sec) { cur = C.stripChars(sec.groups.path, '\\/'); return; }
        var fm = reSearch(_SMBMAP_FILE_RE, line);
        if (fm && fm.groups.name !== '.' && fm.groups.name !== '..') {
          var rel = cur ? (cur + '/' + fm.groups.name).replace(/^\/+/, '') : fm.groups.name;
          files.push({ share: share, path: rel, size: fm.groups.size });
        }
      });
    }
    if (!files.length) return;
    function nameOf(f) {
      var path = String(f.path).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
      var share = String(f.share).replace(/^\/+|\/+$/g, '');
      if (!share || path.indexOf(share + '/') === 0 || path === share) return path;
      return share + '/' + path;
    }
    var names = C.uniqueSortedCI(files.map(nameOf));
    var sensitive = C.uniqueSortedCI(names.filter(_looks_sensitive));
    var tool = command.toLowerCase().indexOf('spider_plus') >= 0 ? 'spider_plus' : (command.toLowerCase().indexOf('smbmap') >= 0 ? 'smbmap' : 'share');
    _add(facts, mkFact('loot.files', h, { files: names, count: names.length, tool: tool, entries: files, sensitive: sensitive, via: 'smb-share' }, S, source));
  }
  C._parse_share_inventory = _parse_share_inventory;

  function _parse_rid_user_list(text, ws, source, facts, opts) {
    opts = opts || {};
    var users = C._rid_usernames(text);
    if (!users.length) return;
    var domain = opts.domain_hint || C._domain_from_facts(ws);
    _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: users, count: users.length, method: 'smb-rid' }, S, source));
  }
  C._parse_rid_user_list = _parse_rid_user_list;

  function _parse_ldapsearch(text, ws, source, facts) {
    var dns = C.uniqueSortedCI(reAll(C._BASE_DN_RE, text).map(function (m) { return m[1]; }));
    dns.forEach(function (baseDn) {
      var domain = baseDn.split(',').filter(function (p) { return p.toUpperCase().indexOf('DC=') === 0; }).map(function (p) { return p.split('=').slice(1).join('='); }).join('.');
      var scope = domain ? 'domain:' + domain : C._scope_for_domain(ws);
      var value = { base_dn: baseDn };
      if (domain) {
        value.domain = domain;
        _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
        _add(facts, mkFact('host.domain', 'host:' + ws.target, { domain: domain }, S, source));
      }
      _add(facts, mkFact('ad.base_dn', scope, value, S, source));
      _add(facts, mkFact('ldap.reachable', 'host:' + ws.target, { tool: 'ldapsearch' }, S, source));
    });
  }
  C._parse_ldapsearch = _parse_ldapsearch;

  function _parse_smb_shares(text, ws, source, facts) {
    var shares = [], seen = {};
    function addShare(name, permission, shareType, readable) {
      name = name.trim();
      if (!name || C._SHARE_HEADER_WORDS.has(name.toLowerCase()) || name[0] === '[') return;
      if (!/^[A-Za-z0-9_$.-]{2,}$/.test(name)) return;
      var key = name.toUpperCase() + '|' + (permission || '').toUpperCase() + '|' + (shareType || '').toUpperCase();
      if (seen[key]) return;
      seen[key] = true;
      var row = { name: name };
      if (permission) row.permission = permission;
      if (shareType) row.type = shareType;
      if (readable !== undefined && readable !== null) row.readable = readable;
      shares.push(row);
    }
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      if (/^SMB\s+/i.test(line)) {
        var parts = line.split(/\s+/);
        if (parts.length < 6) return;
        var share = parts[4], perm = parts[5].toUpperCase();
        if (perm === 'NO' && parts.length > 6 && parts[6].toUpperCase() === 'ACCESS') perm = 'NO ACCESS';
        if (!C._SHARE_PERMISSION_WORDS.has(perm)) return;
        addShare(share, perm, '', perm.indexOf('READ') >= 0 || perm.indexOf('WRITE') >= 0);
        return;
      }
      var p2 = line.split(/\s+/);
      if (p2.length >= 2 && ['Disk', 'IPC', 'Printer'].indexOf(p2[1]) >= 0) addShare(p2[0], '', p2[1]);
    });
    if (shares.length) {
      _add(facts, mkFact('smb.shares', 'host:' + ws.target, { shares: shares, count: shares.length }, S, source));
      var readableDomain = shares.filter(function (sh) { return ['SYSVOL', 'NETLOGON'].indexOf((sh.name || '').toUpperCase()) >= 0 && sh.readable === true; }).map(function (sh) { return sh.name; }).sort();
      if (readableDomain.length) _add(facts, mkFact('config.review', 'host:' + ws.target, { kind: 'readable_domain_shares', shares: readableDomain }, S, source));
    }
  }
  C._parse_smb_shares = _parse_smb_shares;

  function _parse_gpp_artifacts(text, ws, source, facts) {
    var files = C.uniqueSortedCI(reAll(C._GPP_FILE_RE, text).map(function (m) { return m[0]; }));
    if (files.length) _add(facts, mkFact('config.review', 'host:' + ws.target, { kind: 'gpp_xml', files: files }, S, source));
    var cps = {};
    reAll(C._CPASSWORD_RE, text).forEach(function (m) { cps[m[1]] = true; });
    var cpasswords = Object.keys(cps).sort();
    if (cpasswords.length) _add(facts, mkFact('credential.candidate', 'host:' + ws.target, { kind: 'gpp_cpassword', count: cpasswords.length, values: cpasswords }, S, source));
  }
  C._parse_gpp_artifacts = _parse_gpp_artifacts;

  function _parse_asrep_hashes(text, ws, source, facts) {
    var hashes = C.uniqueSortedCI(reAll(C._ASREP_RE, text).map(function (m) { return m[1]; }));
    if (!hashes.length) return;
    _add(facts, mkFact('hash.asrep', C._scope_for_domain(ws), { hashes: hashes, count: hashes.length }, S, source));
    _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), { kind: 'asrep_hash', count: hashes.length }, S, source));
  }
  C._parse_asrep_hashes = _parse_asrep_hashes;

  function _parse_tgs_hashes(text, ws, source, facts) {
    var hashes = C.uniqueSortedCI(reAll(C._TGS_RE, text).map(function (m) { return m[1]; }));
    if (!hashes.length) return;
    _add(facts, mkFact('hash.tgs', C._scope_for_domain(ws), { hashes: hashes, count: hashes.length }, S, source));
    _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), { kind: 'tgs_hash', count: hashes.length }, S, source));
  }
  C._parse_tgs_hashes = _parse_tgs_hashes;

  function _parse_auth_material(auth) {
    auth = auth.replace(/\s+\([^)]*\)\s*$/, '').trim();
    var m = reSearch(C._AUTH_MATERIAL_RE, auth);
    if (!m) return ['', '', ''];
    return [(m.groups.domain || '').trim(), C._clean_username(m.groups.user), m.groups.secret.trim()];
  }
  C._parse_auth_material = _parse_auth_material;

  function _add_authenticated_service(facts, ws, source, proto, user, secret, domain, admin) {
    user = C._clean_username(user);
    if (!C._valid_username(user, false)) return;
    var nthash = C._nt_hash(secret);
    if (!nthash && !C._valid_password(secret)) return;
    var domainName = domain || C._domain_from_facts(ws);
    var value = { user: user, service: proto, method: nthash ? 'pth' : 'nxc' };
    if (nthash) value.nthash = nthash; else value.password = secret;
    if (domainName) value.domain = domainName;
    _add(facts, mkFact('credential.available', C._scope_for_domain(ws, domainName), value, S, source));
    _add(facts, mkFact(proto + '.authenticated', 'host:' + ws.target, value, S, source));
    if (proto === 'winrm') {
      _add(facts, mkFact('winrm.reachable', 'host:' + ws.target, { tool: 'nxc' }, S, source));
      _add(facts, mkFact('foothold.windows', 'host:' + ws.target, value, S, source));
    }
    if (admin) _add(facts, mkFact('access.admin', 'host:' + ws.target, value, S, source));
  }
  C._add_authenticated_service = _add_authenticated_service;

  function _parse_nxc_auth_validation(text, ws, source, facts) {
    reAll(C._NXC_AUTH_RE, text).forEach(function (m) {
      var proto = m.groups.proto.toLowerCase();
      var auth = m.groups.auth.trim();
      var parsed = _parse_auth_material(auth);
      var domain = parsed[0], user = parsed[1], secret = parsed[2];
      if (!user || !secret) return;
      var admin = auth.toLowerCase().indexOf('pwn3d') >= 0 && proto === 'smb';
      _add_authenticated_service(facts, ws, source, proto, user, secret, domain, admin);
    });
  }
  C._parse_nxc_auth_validation = _parse_nxc_auth_validation;

  function _parse_auth_failures(text, ws, source, facts) {
    var lowered = text.toLowerCase();
    Object.keys(C._FAILURE_REASONS).forEach(function (marker) {
      if (lowered.indexOf(marker) >= 0) _add(facts, mkFact('credential.validation', 'host:' + ws.target, { reason: C._FAILURE_REASONS[marker] }, REF, source));
    });
  }
  C._parse_auth_failures = _parse_auth_failures;

  function _parse_evil_winrm(text, ws, command, source, facts) {
    var low = text.toLowerCase();
    if (low.indexOf('winrmauthorizationerror') >= 0 || low.indexOf('winrmhttptransporterror') >= 0 || /\b401\b/.test(text) || low.indexOf('unauthorized') >= 0) return;
    if (!(reSearch(C._EW_PROMPT_RE, text) || low.indexOf('evil-winrm shell') >= 0)) return;
    var h = 'host:' + ws.target;
    var user = C._command_arg(command, ['-u', '--user', '--username']);
    var password = C._command_arg(command, ['-p', '--password']);
    var nthash = C._nt_hash(C._command_arg(command, ['-H', '--hash']));
    var domain = C._command_arg(command, ['-r', '--realm', '-d', '--domain']);
    var value = { service: 'winrm', tool: 'evil-winrm' };
    if (user) value.user = C._clean_username(user);
    if (nthash) value.nthash = nthash; else if (password) value.password = password;
    if (domain) value.domain = domain;
    _add(facts, mkFact('winrm.authenticated', h, value, S, source));
    _add(facts, mkFact('foothold.windows', h, value, S, source));
    C._add_os_observation(facts, ws, source, 'windows', 'evil-winrm authenticated shell', 'high', 'evil-winrm', true);
    if (user && (nthash || (password && C._valid_password(password)))) {
      var cred = { user: C._clean_username(user), service: 'winrm', method: nthash ? 'pth' : 'evil-winrm' };
      if (nthash) cred.nthash = nthash; else cred.password = password;
      if (domain) cred.domain = domain;
      _add(facts, mkFact('credential.available', C._scope_for_domain(ws, domain), cred, S, source));
    }
  }
  C._parse_evil_winrm = _parse_evil_winrm;

  function _parse_bloodhound_collection(text, ws, source, facts) {
    var lowered = text.toLowerCase();
    var zips = C.uniqueSortedCI(reAll(C._BH_ZIP_RE, text).map(function (m) { return m[0]; }));
    var jsons = C.uniqueSortedCI(reAll(C._BH_JSON_RE, text).map(function (m) { return m[0]; }));
    var collected = (zips.length || jsons.length) && ['bloodhound', 'sharphound', 'compressing', 'collection', 'saved'].some(function (mk) { return lowered.indexOf(mk) >= 0; });
    if (!collected) return;
    var value = { tool: 'bloodhound' };
    if (zips.length) value.archives = zips;
    if (jsons.length) value.files = jsons;
    _add(facts, mkFact('ad.graph.collected', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_bloodhound_collection = _parse_bloodhound_collection;

  var _AD_PATH_ARROW_RE = /-+\[?\s*([A-Za-z]+)\s*\]?-+>/;
  var _ABUSABLE_EDGES = new Set(['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'AddMember', 'AddSelf', 'ForceChangePassword', 'AllExtendedRights', 'AddKeyCredentialLink', 'WriteSPN', 'AddAllowedToAct', 'WriteAccountRestrictions', 'Contains', 'SyncLAPSPassword']);
  var _MEMBER_EDGES = new Set(['AddMember', 'AddSelf']);

  function _extract_attack_path(text) {
    var parts = text.split(_AD_PATH_ARROW_RE);
    if (parts.length < 3) return [[], null];
    var nodes = [], edges = [];
    for (var i = 0; i < parts.length; i++) {
      if (i % 2 === 0) {
        var p = parts[i].trim();
        nodes.push(p ? p.split(/\r?\n/).pop().split(': ').pop().trim() : '');
      } else edges.push(parts[i].trim());
    }
    var hops = [];
    edges.forEach(function (edge, i) {
      var frm = nodes[i], to = i + 1 < nodes.length ? nodes[i + 1] : '';
      if (frm && to) hops.push({ from: frm, edge: edge, to: to });
    });
    var first = null;
    for (var j = 0; j < hops.length; j++) {
      if (_ABUSABLE_EDGES.has(hops[j].edge)) {
        first = { edge: hops[j].edge, target: hops[j].to.split('@')[0].trim(), kind: _MEMBER_EDGES.has(hops[j].edge) ? 'group' : 'object' };
        break;
      }
    }
    return [hops, first];
  }

  function _parse_bloodhound_analysis(text, ws, source, facts) {
    var res = _extract_attack_path(text), hops = res[0], first = res[1];
    if (!(reSearch(C._ATTACK_PATH_RE, text) || hops.length)) return;
    var value = { tool: 'bloodhound', evidence: 'analysis_output' };
    if (hops.length) {
      value.path = hops;
      value.goal = hops[hops.length - 1].to;
      if (first) value.first_action = first;
    }
    _add(facts, mkFact('ad.attack_paths', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_bloodhound_analysis = _parse_bloodhound_analysis;

  function _is_ad_abuse_command(command) {
    var l = command.toLowerCase();
    return ['bloodyad', 'dacledit', 'addcomputer', 'impacket-rbcd', 'rbcd.py', 'impacket-getst', 'getst.py', 'impacket-gettgt', 'gettgt.py', 'gmsadumper', 'msds-managedpassword', ' ms-mcs-admpwd', ' laps', ' -m laps', 'get-adcomputer', 'get-adserviceaccount', 'rubeus', 'klist', 'kinit'].some(function (t) { return l.indexOf(t) >= 0; });
  }
  C._is_ad_abuse_command = _is_ad_abuse_command;

  function _canonical_right(right) {
    var map = { writedacl: 'WriteDACL', genericall: 'GenericAll', genericwrite: 'GenericWrite', writeowner: 'WriteOwner', fullcontrol: 'FullControl', allextendedrights: 'AllExtendedRights', forcechangepassword: 'ForceChangePassword', addmember: 'WriteMembers', writemembers: 'WriteMembers', dcsync: 'DCSync', getchanges: 'DCSync', getchangesall: 'DCSync', readgmsapassword: 'ReadGMSAPassword', 'msds-allowedtoactonbehalfofotheridentity': 'RBCD', allowedtoact: 'RBCD', rbcd: 'RBCD' };
    var key = right.trim().toLowerCase();
    return map[key] || right.trim();
  }
  C._canonical_right = _canonical_right;

  function _ad_abuse_tool(command) {
    var l = command.toLowerCase();
    var tools = ['bloodyad', 'dacledit', 'addcomputer', 'rbcd', 'getst', 'gettgt', 'gmsadumper', 'rubeus'];
    for (var i = 0; i < tools.length; i++) if (l.indexOf(tools[i]) >= 0) return tools[i];
    if (l.indexOf('laps') >= 0) return 'laps';
    return 'ad-abuse';
  }
  C._ad_abuse_tool = _ad_abuse_tool;

  function _parse_ad_control_paths(text, ws, command, source, facts) {
    var lc = command.toLowerCase();
    // `get writable` ENUMERATION is handled by _parse_bloodyad_writable, not here — so skip it. But the
    // dispatch label can carry BOTH the move's preferred `get writable` command AND the abuse command the
    // operator actually ran (paste recovery widens the label), so only bail when NO abuse verb is present;
    // otherwise a real group-join / owner-seize / dcsync-grant would be silently dropped.
    var abuseVerb = ['groupmember', 'set owner', 'writeowner', 'genericall', 'dacledit', '-action write',
      'add dcsync', '-rights dcsync', 'rights:dcsync', 'add rbcd', 'add uac', 'set password', 'add computer'
    ].some(function (k) { return lc.indexOf(k) >= 0; });
    if (lc.indexOf('get writable') >= 0 && !abuseVerb) return;
    var rightsSet = {};
    reAll(C._AD_CONTROL_RIGHT_RE, text).forEach(function (m) { rightsSet[_canonical_right(m[1])] = true; });
    var operation = '';
    if (lc.indexOf('add dcsync') >= 0 || lc.indexOf('-rights dcsync') >= 0 || lc.indexOf('rights:dcsync') >= 0) { operation = 'dcsync_grant'; rightsSet.DCSync = true; }
    else if (lc.indexOf('groupmember') >= 0 || lc.indexOf('add groupmember') >= 0) { operation = 'group_member_write'; rightsSet.WriteMembers = true; }
    else if (lc.indexOf('set owner') >= 0 || lc.indexOf('writeowner') >= 0) { operation = 'owner_write'; rightsSet.WriteOwner = true; }
    else if (lc.indexOf('genericall') >= 0 || lc.indexOf('dacledit') >= 0) { operation = 'dacl_write'; rightsSet.GenericAll = true; }
    else if (lc.indexOf('rbcd') >= 0 || text.toLowerCase().indexOf('msds-allowedtoact') >= 0) { operation = 'rbcd_write'; rightsSet.RBCD = true; }

    var evidence = [];
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      if (reSearch(C._AD_CONTROL_RIGHT_RE, line) || reSearch(C._AD_CONTROL_SUCCESS_RE, line)) evidence.push(line.slice(0, 220));
      if (evidence.length >= 5) break;
    }
    var opError = reSearch(/\b(error|failed|denied|unauthorized|insufficient|traceback|not recognized|access is denied|constraint|cannot|invalid)\b/i, text);
    // A group sweep (`for g in …; do add groupMember "$g" …`) prints a success line for every group that
    // stuck AND a failure line for every group that did not — the failures must NOT suppress the wins, so
    // an explicit join line counts as success on its own, independent of the generic error gate.
    var hasJoinLine = operation === 'group_member_write' && /(?:\badded to\b|^\s*\[\+\]\s*joined:)/im.test(text);
    var success = hasJoinLine || evidence.length > 0 || !!reSearch(C._AD_CONTROL_SUCCESS_RE, text) || (!!operation && !!text.trim() && !opError);
    if (!success) return;

    var successMatch = reSearch(C._AD_CONTROL_SUCCESS_RE, text);
    var defaultEvidence = successMatch ? [C._line_for_match(text, successMatch)] : [((text.trim().split(/\r?\n/)[0]) || 'control path granted').slice(0, 220)];
    if (operation === 'group_member_write') {
      // Evidence-driven: mint one ad.group_joined per group the OUTPUT actually confirms was joined —
      // `[+] <principal> added to <group>` (bloodyAD) or `[+] JOINED: <group>` (obol's sweep echo). The
      // command may be a loop over many candidates, so the winning group(s) live in the output, never in
      // the template's `$g`. Each denied group simply produces no fact — that IS "try all, keep the wins".
      var joins = [], seenJ = {};
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim(); if (!line) return;
        var body = line.replace(/^\[\d[\d:]*\]\s*(?:INFO|WARN(?:ING)?|DEBUG|ERROR)?\s*/i, '').replace(/^\[[-*+!]\]\s*/, '');
        var g = '', principal = '', mj = /^joined:\s*(.+)$/i.exec(body);
        if (mj) { g = mj[1].trim(); }
        else { var ma = /^(.+?)\s+added to (?:group\s+)?(.+?)\.?$/i.exec(body); if (ma) { principal = ma[1].trim(); g = ma[2].trim(); } }
        if (!g || g.indexOf('$') >= 0) return;
        var key = g.toLowerCase(); if (seenJ[key]) return; seenJ[key] = true;
        joins.push({ group: C.stripChars(g, "'\""), principal: C.stripChars(principal, "'\""), line: line.slice(0, 220) });
      });
      if (!joins.length) {
        // No explicit success line — fall back to the command's own concrete group (never the sweep's
        // literal $g), and only on a clean run with no error.
        var m = /groupmember\s+(?:'([^']+)'|"([^"]+)"|(\S+))/i.exec(command);
        var cg = m ? (m[1] || m[2] || m[3] || '') : '';
        if (cg && cg.indexOf('$') < 0 && !opError) {
          var toks = command.split(/\s+/);
          joins.push({ group: C.stripChars(cg, "'\""), principal: toks.length ? C.stripChars(toks[toks.length - 1], "'\"") : '', line: (evidence[0] || defaultEvidence[0] || '') });
        }
      }
      joins.forEach(function (j) {
        _add(facts, mkFact('ad.group_joined', C._scope_for_domain(ws),
          { group: j.group, principal: j.principal, method: _ad_abuse_tool(command), evidence: [j.line] }, S, source));
      });
      return;
    }
    var rights = Object.keys(rightsSet);
    var value = { rights: rights.length ? C.uniqueSortedCI(rights) : ['control_path'], method: _ad_abuse_tool(command), evidence: evidence.length ? evidence : defaultEvidence };
    if (operation) value.operation = operation;
    var target = C._command_arg(command, ['--target', '-target', '-delegate-to']) || C._command_arg(command, ['-target-sam']);
    if (target) value.target = C.stripChars(target, "'\"");
    var principal = C._command_arg(command, ['-principal', '--principal', '-delegate-from']);
    if (principal) value.principal = C.stripChars(principal, "'\"");
    _add(facts, mkFact('ad.control_paths', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_ad_control_paths = _parse_ad_control_paths;

  function _parse_added_computer(text, ws, command, source, facts) {
    var lowered = (text + '\n' + command).toLowerCase();
    if (lowered.indexOf('addcomputer') < 0 && lowered.indexOf('machine account') < 0 && lowered.indexOf('computer account') < 0) return;
    if (/\b(error|failed|denied|constraint|already exists)\b/i.test(text)) return;
    var success = !!reSearch(C._ADD_COMPUTER_SUCCESS_RE, text) || /\b(success|created|added)\b/i.test(text);
    if (!success) return;
    var name = C._command_arg(command, ['-computer-name', '--computer-name']) || '';
    var m = reSearch(C._ADD_COMPUTER_SUCCESS_RE, text);
    if (!name && m) name = m.groups.name;
    name = C.stripChars(name, "'\"");
    if (name && !name.endsWith('$')) name = name + '$';
    if (!C._valid_username(name)) return;
    var value = { computer: name, method: 'addcomputer' };
    var password = C._command_arg(command, ['-computer-pass', '--computer-pass']);
    if (C._valid_password(password)) {
      value.password_set = true;
      _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), { kind: 'machine_account', user: name, password: password, method: 'addcomputer' }, S, source));
    }
    _add(facts, mkFact('ad.computer_added', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_added_computer = _parse_added_computer;

  function _parse_kerberos_ticket_material(text, ws, command, source, facts) {
    var lowered = text.toLowerCase();
    var files = C.uniqueSortedCI(reAll(C._TICKET_FILE_RE, text).map(function (m) { return m.groups.file.replace(/\\/g, '/'); }));
    var klistSuccess = lowered.indexOf('default principal:') >= 0 && (lowered.indexOf('krbtgt/') >= 0 || lowered.indexOf('service principal') >= 0);
    var ticketSignal = files.length > 0 || lowered.indexOf('got tgt') >= 0 || (lowered.indexOf('ticket') >= 0 && lowered.indexOf('saved') >= 0) || klistSuccess;
    if (!ticketSignal) return;
    var principal = C._command_arg(command, ['-impersonate', '--impersonate']);
    var m = reSearch(C._IMPERSONATE_RE, text);
    if (!principal && m) principal = m.groups.user;
    if (!principal) principal = C._command_arg(command, ['-u', '--user', '--username']) || C._command_arg(command, ['user']);
    var value = { method: _ad_abuse_tool(command) };
    if (files.length) value.files = files;
    if (principal) value.principal = C._clean_username(principal);
    var spn = C._command_arg(command, ['-spn', '--spn']);
    if (spn) value.spn = C.stripChars(spn, "'\"");
    _add(facts, mkFact('kerberos.tickets', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_kerberos_ticket_material = _parse_kerberos_ticket_material;

  function _parse_gmsa_material(text, ws, command, source, facts) {
    var lowered = (text + '\n' + command).toLowerCase();
    if (lowered.indexOf('gmsa') < 0 && lowered.indexOf('msds-managedpassword') < 0) return;
    var entries = [], seen = {};
    reAll(C._GMSA_HASH_RE, text).forEach(function (m) {
      var user = C._clean_username(m.groups.user);
      var nt = m.groups.nt.toLowerCase();
      if (!C._valid_username(user) || seen[user.toLowerCase() + '|' + nt]) return;
      seen[user.toLowerCase() + '|' + nt] = true;
      var item = { user: user, nthash: nt, method: 'gmsa' };
      var domain = m.groups.domain || C._domain_from_facts(ws);
      if (domain) item.domain = domain;
      entries.push(item);
      _add(facts, mkFact('credential.ntlm_hash', C._scope_for_domain(ws, domain), item, S, source));
    });
    if (entries.length) {
      _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), { kind: 'gmsa_ntlm_hash', count: entries.length, users: entries.map(function (e) { return e.user; }) }, S, source));
    } else if (/msds-managedpassword/i.test(text) && !reSearch(C._GMSA_READ_ERROR_RE, text)) {
      _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), { kind: 'gmsa_managed_password_blob' }, S, source));
    }
  }
  C._parse_gmsa_material = _parse_gmsa_material;

  function _extract_laps_computer(line) {
    var m = reSearch(C._LAPS_COMPUTER_RE, line);
    if (m) return m.groups.computer;
    var before = line.split(/\b(?:ms-Mcs-AdmPwd|msLAPS-Password|LAPS\s+Password|Password)\b/i)[0];
    var tokens = reAll(/\b[A-Za-z0-9_.-]+\$?\b/, before).map(function (mm) { return mm[0]; });
    for (var i = tokens.length - 1; i >= 0; i--) {
      var token = tokens[i];
      if (['LDAP', 'SMB', 'WINRM', 'PASSWORD', 'ADMINISTRATOR'].indexOf(token.toUpperCase()) >= 0) continue;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)) continue;
      if (/^\d+$/.test(token)) continue;
      return token;
    }
    return '';
  }
  C._extract_laps_computer = _extract_laps_computer;

  function _parse_laps_material(text, ws, command, source, facts) {
    var lowered = (text + '\n' + command).toLowerCase();
    if (lowered.indexOf('laps') < 0 && lowered.indexOf('ms-mcs-admpwd') < 0 && lowered.indexOf('mslaps-password') < 0) return;
    var currentComputer = '', currentUser = 'Administrator', creds = [], seen = {};
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      var computer = _extract_laps_computer(line) || currentComputer;
      var userMatch = reSearch(C._LAPS_USER_RE, line);
      if (userMatch) currentUser = C._clean_username(userMatch.groups.user) || currentUser;
      var pwMatch = reSearch(C._LAPS_PASSWORD_RE, line);
      if (reSearch(C._LAPS_COMPUTER_RE, line)) currentComputer = _extract_laps_computer(line) || currentComputer;
      if (!pwMatch) return;
      var password = C.stripChars(pwMatch.groups.pw.trim(), "'\"");
      if (!C._valid_password(password)) return;
      computer = C.stripChars(computer.trim(), "'\"");
      if (computer && !computer.endsWith('$')) computer = computer + '$';
      if (!C._valid_username(computer)) return;
      var key = computer.toLowerCase() + '|' + currentUser.toLowerCase() + '|' + password;
      if (seen[key]) return;
      seen[key] = true;
      creds.push({ kind: 'laps_password', computer: computer, user: currentUser, password: password });
    });
    creds.forEach(function (cred) { _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), cred, S, source)); });
  }
  C._parse_laps_material = _parse_laps_material;

  var _UNCONSTRAINED_RE = /\b(TRUSTED_FOR_DELEGATION|unconstrained\s+delegation)\b/i;
  var _GMSA_DISCOVER_RE = /(msDS-GroupMSAMembership|GroupManagedServiceAccount|msDS-ManagedPasswordId|\bgMSA\b)/i;

  function _parse_ad_delegation_surface(text, ws, command, source, facts) {
    var um = reSearch(_UNCONSTRAINED_RE, text);
    if (um) _add(facts, mkFact('ad.unconstrained', C._scope_for_domain(ws), { evidence: [C._line_for_match(text, um)] }, S, source));
    var gm = reSearch(_GMSA_DISCOVER_RE, text);
    if (gm && !reSearch(C._GMSA_READ_ERROR_RE, text)) _add(facts, mkFact('ad.gmsa', C._scope_for_domain(ws), { evidence: [C._line_for_match(text, gm)] }, S, source));
  }
  C._parse_ad_delegation_surface = _parse_ad_delegation_surface;

  // bloodyAD `get writable [--detail]` prints, per object, a `distinguishedName:` line then a run of
  // `<attribute>: <PERMISSION>` lines (WRITE / CREATE_CHILD). These attributes are escalation primitives.
  var _BLOODY_WRITABLE_ATTR_RIGHT = {
    member: 'WriteMembers',                                 // add yourself to the group
    ntsecuritydescriptor: 'WriteDACL',                      // rewrite the DACL → grant yourself anything
    owner: 'WriteOwner',
    'msds-allowedtoactonbehalfofotheridentity': 'RBCD',     // resource-based constrained delegation
  };
  // Membership in these groups is itself privilege escalation, so "you can add yourself to X" is a lead
  // worth surfacing (adding yourself to Guests is not). Exchange Windows Permissions holds WriteDacl over
  // the domain object → grant DCSync → dump the Administrator hash.
  var _ABUSABLE_GROUP_CN = {
    'exchange windows permissions': 1, 'organization management': 1,
    'account operators': 1, 'backup operators': 1, 'server operators': 1, 'print operators': 1,
    'dnsadmins': 1, 'administrators': 1, 'domain admins': 1, 'enterprise admins': 1, 'schema admins': 1,
    'group policy creator owners': 1, 'key admins': 1, 'enterprise key admins': 1,
    'remote management users': 1, 'distributed com users': 1,
  };
  var _ACL_LEAD_NOTES = {
    'exchange windows permissions':
      'you can add yourself to Exchange Windows Permissions, which holds WriteDacl over the domain '
      + '→ grant yourself DCSync (getchanges/getchangesall) → secretsdump the Administrator hash',
  };
  function _cn_from_dn(dn) {
    var head = (dn || '').split(',')[0];
    return head.indexOf('=') >= 0 ? head.split('=').slice(1).join('=').trim() : head.trim();
  }

  // bloodyAD `get writable` output is recognizable from CONTENT alone: `distinguishedName:` blocks whose
  // attribute lines carry a bare permission token (only WRITE / CREATE_CHILD are ever emitted). Sniffing it
  // lets the parser fire when the operator ATTACHES the output file with no command set (the common case for
  // this multi-thousand-line dump) rather than pasting a prompt-anchored `bloodyAD ... get writable` line.
  var _BLOODY_WRITABLE_PERM_RE = /^[A-Za-z][\w-]*:[ \t]*(?:WRITE|CREATE_CHILD)[ \t]*$/;
  function _looks_like_bloodyad_writable(text) {
    if (!text || text.toLowerCase().indexOf('distinguishedname:') < 0) return false;
    var lines = text.split(/\r?\n/), hits = 0;
    for (var i = 0; i < lines.length; i++) {
      if (_BLOODY_WRITABLE_PERM_RE.test(lines[i].trim()) && ++hits >= 2) return true;
    }
    return false;
  }
  C._looks_like_bloodyad_writable = _looks_like_bloodyad_writable;

  function _parse_bloodyad_writable(text, ws, command, source, facts) {
    if (command.toLowerCase().indexOf('get writable') < 0 && !_looks_like_bloodyad_writable(text)) return;
    var memberT = [], daclT = [], ownerT = [], gpoT = [], rights = {}, notes = [];
    text.split(/\n[ \t]*\n/).forEach(function (block) {
      var lines = block.split(/\r?\n/).map(function (l) { return l.replace(/\s+$/, ''); }).filter(function (l) { return l.trim(); });
      if (!lines.length || lines[0].toLowerCase().indexOf('distinguishedname:') !== 0) return;
      var dn = lines[0].split(':').slice(1).join(':').trim();
      var cn = _cn_from_dn(dn), cnl = cn.toLowerCase(), attrs = {};
      for (var i = 1; i < lines.length; i++) {
        var ln = lines[i];
        if (ln.indexOf(':') >= 0) attrs[ln.split(':')[0].trim().toLowerCase()] = ln.split(':').slice(1).join(':').trim().toUpperCase();
      }
      var isDomainRoot = !!dn && dn.split(',').every(function (p) { return p.trim().toLowerCase().indexOf('dc=') === 0; });
      var isComputer = cn.charAt(cn.length - 1) === '$' || dn.indexOf(',CN=Computers,') >= 0;
      // A writable Group Policy Container (under CN=Policies,CN=System) is the gpo-abuse sink.
      if (dn.toLowerCase().indexOf('cn=policies,cn=system') >= 0
          && Object.keys(attrs).some(function (a) { return attrs[a].indexOf('WRITE') >= 0 || attrs[a].indexOf('CREATE') >= 0; })) {
        gpoT.push(cn);
      }
      Object.keys(_BLOODY_WRITABLE_ATTR_RIGHT).forEach(function (attr) {
        var right = _BLOODY_WRITABLE_ATTR_RIGHT[attr], perm = attrs[attr] || '';
        if (perm.indexOf('WRITE') < 0 && perm.indexOf('CREATE') < 0) return;
        if (right === 'WriteMembers') {
          if (_ABUSABLE_GROUP_CN[cnl]) {
            rights[right] = 1; memberT.push(cn);
            var note = _ACL_LEAD_NOTES[cnl];
            if (note && notes.indexOf(note) < 0) notes.push(note);
          }
        } else if (right === 'RBCD') {
          if (isComputer) { rights[right] = 1; ownerT.push(cn); }
        } else if (isDomainRoot || isComputer || _ABUSABLE_GROUP_CN[cnl]) {
          rights[right] = 1;
          (right === 'WriteDACL' ? daclT : ownerT).push(isDomainRoot ? 'the domain object' : cn);
        }
      });
    });
    var seenG = {};
    gpoT.forEach(function (g) { if (!seenG[g]) { seenG[g] = 1; _add(facts, mkFact('ad.gpo_writable', C._scope_for_domain(ws), { gpo: g, method: 'bloodyad' }, S, source)); } });
    var seenT = {}, targets = [];
    memberT.concat(daclT, ownerT).forEach(function (t) { if (!seenT[t]) { seenT[t] = 1; targets.push(t); } });
    var rightList = Object.keys(rights);
    if (!(rightList.length && targets.length)) return;
    if (!notes.length) notes.push('enumerated control right (lead) — cash it in with the ACL-abuse move; not a granted control path yet');
    _add(facts, mkFact('ad.acl_lead', C._scope_for_domain(ws), {
      rights: rightList.sort(function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; }),
      targets: targets.slice(0, 10), method: 'bloodyad', note: notes.join(' · '),
    }, S, source));
  }
  C._parse_bloodyad_writable = _parse_bloodyad_writable;

  // sccmhunter / SharpSCCM. Site-server and management-point discovery proves nothing on its own and
  // earns no fact — only a recovered Network Access Account credential (a secret to try) does, and it is
  // candidate material, not validated access. A run that finds no SCCM (`No results found` — the common
  // case, since most boxes run no SCCM) correctly mints nothing: that is the honest outcome, not a
  // parse failure. Ported from obol-local's conservative _parse_sccm.
  var _SCCM_NAA_USER_RE = /NetworkAccess(?:Username|Account)\s*[:=]\s*\S/i;
  var _SCCM_NAA_PASS_RE = /NetworkAccessPassword\s*[:=]\s*\S/i;
  var _SCCM_NAA_GENERIC_RE = /\bNAA\b.*(?:cred|password|username)/i;
  function _parse_sccm(text, ws, source, facts) {
    var users = reAll(_SCCM_NAA_USER_RE, text);
    var hasPass = !!reSearch(_SCCM_NAA_PASS_RE, text);
    var generic = !!reSearch(_SCCM_NAA_GENERIC_RE, text);
    if (!((users.length && hasPass) || (generic && hasPass))) return;
    _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws),
      { kind: 'sccm_naa', count: Math.max(users.length, 1) }, S, source));
  }
  C._parse_sccm = _parse_sccm;

  function _parse_ad_abuse_output(actionId, text, ws, command, source, facts) {
    if (!(_is_ad_abuse_command(command) || C._AD_ABUSE_ACTION_IDS.has(actionId))) return;
    _parse_ad_control_paths(text, ws, command, source, facts);
    _parse_bloodyad_writable(text, ws, command, source, facts);
    _parse_added_computer(text, ws, command, source, facts);
    _parse_kerberos_ticket_material(text, ws, command, source, facts);
    _parse_gmsa_material(text, ws, command, source, facts);
    _parse_laps_material(text, ws, command, source, facts);
  }
  C._parse_ad_abuse_output = _parse_ad_abuse_output;

})(typeof globalThis !== 'undefined' ? globalThis : this);
