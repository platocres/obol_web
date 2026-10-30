/*!
 * obol engine - parsers/directory.js  (AD / directory-services parsers)
 * NOTE: this file was renamed from `ad.js` because content/ad blockers (AdBlock Plus, uBlock)
 * block a script literally named `ad.js` by filename, which silently broke ALL evidence parsing.
 * Faithful JS port of the fixture-reachable parsers in 
 * nxc/LDAP/SMB enumeration, credential validation, kerberos roast/crack material, evil-winrm,
 * BloodHound collection/analysis, and the ACL/Kerberos/gMSA/LAPS abuse primitives.
 * Proof discipline: roast hash = crackable material, gMSA/LAPS = candidate, a control right
 * or ticket = available material - none is a validated credential or proven access.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var C = OBOL._parserCommon;
  var mkFact = C.mkFact, _add = C._add, S = C.ProofState.SUPPORTED, REF = C.ProofState.REFUTED;
  var reAll = C.reAll, reSearch = C.reSearch;

  function credentialFingerprint(value) {
    value = value || {};
    return OBOL.facts.fingerprint(JSON.stringify([
      String(value.domain || value.realm || value.authRealm || '').trim().toLowerCase().replace(/\.$/, ''),
      String(value.user || value.username || '').trim().toLowerCase(),
      value.nthash ? 'nthash' : 'password', value.nthash ? String(value.nthash).toLowerCase() : String(value.password || value.secret || '')
    ]));
  }
  C.credentialFingerprint = credentialFingerprint;
  function observedHost(ws, host) { return (((ws || {}).context || {}).forceTarget) || host || (ws || {}).target; }
  C._observed_host = observedHost;

  // Authentication observations describe one identity on one host/service. A selected
  // credential ID is attached only when the output agrees with the supplied attempt.
  function _auth_observation(ws, value) {
    var out = Object.assign({}, value || {}), ctx = (ws && ws.context) || {};
    var target = String((ws && ws.target) || 'target');
    var realm = String(out.domain || out.realm || '').toLowerCase().replace(/\.$/, '');
    var user = String(out.user || '').toLowerCase();
    var service = String(out.service || '').toLowerCase();
    out.target = target;
    if (ws.observedTarget && ws.observedTarget !== target) out.observedTarget = ws.observedTarget;
    if (realm) out.realm = realm;
    if (user) out.principal = (realm ? realm + '\\' : '') + user;
    var selected = ctx.principal || '';
    if (selected && typeof selected === 'object') selected = (selected.realm || selected.domain || ctx.authRealm || '') + '\\' + (selected.user || selected.username || '');
    selected = String(selected).toLowerCase().replace(/\.$/, '');
    var expected = String(ctx.authRealm || '').toLowerCase().replace(/\.$/, '');
    var selectedUser = selected.replace(/^.*[\\/]/, '').replace(/@.*$/, '');
    var selectedRealm = selected.indexOf('\\') >= 0 ? selected.split('\\')[0] : (selected.indexOf('@') >= 0 ? selected.split('@')[1] : expected);
    var agrees = (!ctx.target || String(ctx.target).toLowerCase() === target.toLowerCase()) &&
      (!ctx.service || !service || String(ctx.service).toLowerCase() === service) &&
      (!selectedUser || !user || selectedUser === user) && (!selectedRealm || !realm || selectedRealm === realm);
    if (agrees && !user && selectedUser) {
      user = selectedUser; realm = selectedRealm || expected;
      out.user = user; out.association = 'attempt';
      if (realm) out.domain = realm;
      out.principal = (realm ? realm + '\\' : '') + user;
    }
    if (agrees && !realm && user && selectedUser === user && selectedRealm) {
      realm = selectedRealm;
      out.principal = realm + '\\' + user;
      out.association = 'attempt';
    }
    if (realm) { out.realm = realm; out.authRealm = realm; }
    if (out.password || out.nthash) out.credentialFingerprint = credentialFingerprint(out);
    var selectedCredential = ctx.credential && (ctx.credential.value || ctx.credential);
    if (selectedCredential && (out.password || out.nthash)) {
      var expectedHash = C._nt_hash(selectedCredential.nthash || selectedCredential.ntlm || '');
      var expectedPassword = selectedCredential.password || (selectedCredential.secretType === 'password' ? selectedCredential.secret : '') || '';
      if ((out.nthash && expectedHash && out.nthash !== expectedHash) || (out.password && expectedPassword && out.password !== expectedPassword)) agrees = false;
    }
    if (ctx.credentialFingerprint && out.credentialFingerprint && ctx.credentialFingerprint !== out.credentialFingerprint) agrees = false;
    if (agrees && ctx.credentialId && user && selectedUser === user) out.credentialId = ctx.credentialId;
    if (agrees && ctx.attemptKey) out.attemptKey = ctx.attemptKey;
    return out;
  }
  C._auth_observation = _auth_observation;

  var _NXC_ROW_PORT_RE = /^\s*(?<proto>LDAP|LDAPS|SMB|WINRM|RDP|SSH|FTP|MSSQL|WMI|VNC|NFS)\s+(?<host>\S+)\s+(?<port>\d+)\s+/i;
  var _NXC_DC_PORTS = { 88: 1, 389: 1, 636: 1, 3268: 1, 3269: 1 };
  var _NXC_DC_SHARE_RE = /(?:^\s*SMB\s+\S+\s+\d+\s+\S+\s+[^\r\n]*?\b(?:SYSVOL|NETLOGON)\b|^\s*(?:SYSVOL|NETLOGON)\s+(?:READ|WRITE|NO\s+ACCESS|Disk)\b|\\\\[^\\\s]+\\(?:SYSVOL|NETLOGON)\b)/im;
  var _NXC_DC_NAME_RE = /^(?:[a-z0-9]+[-_])?dc\d*(?:[-_][a-z0-9]+)?$/i;
  var _NXC_DC_SVC_TEXT_RE = /\b(?:Domain Controller|Active Directory Domain Services|Global Catalog|rootDomainNamingContext|defaultNamingContext|krbtgt)\b/i;

  function _nxc_has_dc_evidence(hostAddr, hostName, domain, protosMap, portsMap, checkText, ws, facts) {
    var pMap = protosMap[hostAddr] || {};
    if (pMap.ldap || pMap.ldaps) return true;
    var ptMap = portsMap[hostAddr] || {};
    var ptKeys = Object.keys(ptMap);
    for (var i = 0; i < ptKeys.length; i++) {
      if (_NXC_DC_PORTS[ptKeys[i]]) return true;
    }
    if (_NXC_DC_SHARE_RE.test(checkText || '')) return true;
    var scope = 'host:' + hostAddr;
    var known = (facts || []).concat((ws && ws.seedFacts) || []);
    for (var fi = 0; fi < known.length; fi++) {
      var f = known[fi];
      if (!f || f.scope !== scope) continue;
      if (f.kind === 'kerberos.reachable' || f.kind === 'ldap.reachable' || f.kind === 'ad.dc_candidate') return true;
      if (f.kind === 'port:88' || f.kind === 'port:389' || f.kind === 'port:636' || f.kind === 'port:3268' || f.kind === 'port:3269') return true;
      if (f.kind === 'ports.open' && f.value && Array.isArray(f.value.ports)) {
        for (var pi = 0; pi < f.value.ports.length; pi++) {
          if (_NXC_DC_PORTS[f.value.ports[pi]]) return true;
        }
      }
      if (f.kind === 'smb.shares' && f.value && Array.isArray(f.value.shares)) {
        for (var si = 0; si < f.value.shares.length; si++) {
          var sh = String(f.value.shares[si] || '').toLowerCase();
          if (sh === 'sysvol' || sh === 'netlogon') return true;
        }
      }
    }
    if (hostName && _NXC_DC_NAME_RE.test(hostName) && (domain || _NXC_DC_SVC_TEXT_RE.test(checkText || ''))) return true;
    return false;
  }

  function _parse_nxc_common(text, ws, source, facts) {
    var h = 'host:' + ws.target;
    var protoMatches = reAll(C._NXC_PROTO_REACHABLE_RE, text);
    var hostSet = {}, protosByHost = {}, portsByHost = {}, linesByHost = {};
    protoMatches.forEach(function (m) {
      if (m.groups && m.groups.host && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(m.groups.host)) hostSet[m.groups.host] = 1;
      var lineHost = observedHost(ws, m.groups && m.groups.host);
      var line = text.slice(m.index).split(/\r?\n/)[0];
      var pr = (m.groups && m.groups.proto || '').toLowerCase();
      var pm = _NXC_ROW_PORT_RE.exec(line);
      var rowPort = (pm && pm.groups && pm.groups.port) ? parseInt(pm.groups.port, 10) : 0;
      if (pr === 'smb' && (rowPort === 5985 || rowPort === 5986)) pr = 'winrm';
      if (pr) (protosByHost[lineHost] = protosByHost[lineHost] || {})[pr] = 1;
      if (rowPort) (portsByHost[lineHost] = portsByHost[lineHost] || {})[rowPort] = 1;
      (linesByHost[lineHost] = linesByHost[lineHost] || []).push(line);
    });
    var multiHost = Object.keys(hostSet).length > 1;
    if (Object.keys(hostSet).length === 1) h = 'host:' + observedHost(ws, Object.keys(hostSet)[0]);
    var singleHostAddr = h.slice(5);
    var domain = '';
    var dm = reSearch(C._DOMAIN_RE, text);
    var nm = reSearch(C._NAME_RE, text);
    var isWorkgroup = !!(dm && nm && dm[1].trim().toLowerCase() === nm[1].trim().toLowerCase()) || !!(dm && /^workgroup$/i.test(dm[1].trim()));
    if (dm && !isWorkgroup) {
      domain = dm[1].trim();
      if (domain && domain !== 'None' && domain !== '-') {
        _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
        _add(facts, mkFact('ad.base_dn', 'domain:' + domain, { base_dn: C._base_dn_from_domain(domain) }, S, source));
        if (!multiHost) _add(facts, mkFact('host.domain', h, { domain: domain }, S, source));
      } else { domain = ''; }
    }
    if (!multiHost) {
      var singleName = nm ? nm[1].trim() : '';
      if (singleName) _add(facts, mkFact('host.hostname', h, { name: singleName }, S, source));
      if (!isWorkgroup && (singleName || domain) && _nxc_has_dc_evidence(singleHostAddr, singleName, domain, protosByHost, portsByHost, text, ws, facts)) {
        var value = { host: singleHostAddr };
        if (singleName) value.name = singleName;
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
    }

    protoMatches.forEach(function (m) {
      var proto = m.groups.proto.toLowerCase();
      var lineHost = observedHost(ws, m.groups && m.groups.host);
      var lh = 'host:' + lineHost;
      var lineWs = lineHost === ws.target ? ws : Object.assign({}, ws, { target: lineHost });
      var line = text.slice(m.index).split(/\r?\n/)[0];
      var rowPm = _NXC_ROW_PORT_RE.exec(line);
      var rowPort2 = (rowPm && rowPm.groups && rowPm.groups.port) ? parseInt(rowPm.groups.port, 10) : 0;
      if (proto === 'smb' && (rowPort2 === 5985 || rowPort2 === 5986)) proto = 'winrm';
      C._add_os_from_text(line, lineWs, source, facts, 'nxc', 'high', true);
      var reachProto = proto === 'ldaps' ? 'ldap' : proto;
      if (['ldap', 'smb', 'winrm', 'rdp', 'ssh', 'ftp'].indexOf(reachProto) >= 0) _add(facts, mkFact(reachProto + '.reachable', lh, { tool: 'nxc' }, S, source));
      if (proto === 'mssql') {
        _add(facts, mkFact('service.ms-sql-s', lh, { tool: 'nxc' }, S, source));
        _add(facts, mkFact('mssql.reachable', lh, { tool: 'nxc' }, S, source));
      }
      if (proto === 'winrm' || proto === 'rdp' || proto === 'wmi' || proto === 'mssql') C._add_os_observation(facts, lineWs, source, 'windows', line.trim(), (proto === 'winrm' || proto === 'wmi') ? 'high' : 'medium', 'nxc', proto === 'winrm' || proto === 'wmi');
      if (multiHost) {
        var ldm = reSearch(C._DOMAIN_RE, line);
        var lnm = reSearch(C._NAME_RE, line);
        var lIsWorkgroup = !!(ldm && lnm && ldm[1].trim().toLowerCase() === lnm[1].trim().toLowerCase()) || !!(ldm && /^workgroup$/i.test(ldm[1].trim()));
        var ldom = (!lIsWorkgroup && ldm && ldm[1].trim() && ldm[1].trim() !== 'None' && ldm[1].trim() !== '-') ? ldm[1].trim() : '';
        var lname = lnm ? lnm[1].trim() : '';
        if (ldom) _add(facts, mkFact('host.domain', lh, { domain: ldom }, S, source));
        if (lname) _add(facts, mkFact('host.hostname', lh, { name: lname }, S, source));
        var hostBlockText = (linesByHost[lineHost] || [line]).join('\n');
        if (!lIsWorkgroup && (lname || ldom) && _nxc_has_dc_evidence(lineHost, lname, ldom, protosByHost, portsByHost, hostBlockText, lineWs, facts)) {
          var lval = { host: lineHost };
          if (lname) lval.name = lname;
          if (ldom) lval.domain = ldom;
          _add(facts, mkFact('ad.dc_candidate', lh, lval, S, source));
        }
        var lsig = reSearch(C._NXC_SIGNING_RE, line);
        if (lsig) {
          var lenabled = lsig.groups.enabled.toLowerCase() === 'true';
          _add(facts, mkFact('smb.signing', lh, { enabled: lenabled, tool: 'nxc', flags: lenabled ? [] : ['smb_signing_disabled'] }, S, source));
        }
        var lsmbv1 = reSearch(C._NXC_SMBV1_RE, line);
        if (lsmbv1) _add(facts, mkFact('smb.smbv1', lh, { enabled: lsmbv1.groups.enabled.toLowerCase() === 'true', tool: 'nxc' }, S, source));
      }
    });
    var anonSearchDenied = /(?:searchRequest\s*->\s*operationsError|a successful bind must be completed)/i.test(text) && /^LDAP\s+/im.test(text);
    if (!anonSearchDenied && /^LDAP\s+.*\[\+\].*(?:\\:|anonymous|'')/im.test(text)) {
      _add(facts, mkFact('ad.anonymous_bind', C._scope_for_domain(ws, domain), { tool: 'nxc' }, S, source));
    }
  }
  C._parse_nxc_common = _parse_nxc_common;

  function _parse_nxc_smb_session(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var cmdHay = (command || '') + ' ' + (source || '') + '\n' + (text || '');
    var anonymousCommand = cmdHay.indexOf("-u ''") >= 0 || cmdHay.indexOf('-u ""') >= 0;
    var guestCommand = /\s-u\s+['"]?guest['"]?\b/i.test(cmdHay) || /^\s*SMB\s+.*\[[+-]\].*\\guest:/im.test(text);
    var hasNamedUser = /\s-u\s+(?!''\b|""\b|['"]?guest['"]?\b)\S+/i.test(cmdHay)
      || /^\s*SMB\s+.*\[[+-]\]\s*(?:[^\\\s]+\\)?(?!guest\b|anonymous\b)[A-Za-z0-9._$-]+:/im.test(text);
    var gotSession = false;
    if (!hasNamedUser && !guestCommand && /\(Null Auth:True\)/i.test(text)) { _add(facts, mkFact('smb.null_session', h, { tool: 'nxc', null_auth: true }, S, source)); gotSession = true; }
    text.split(/\r?\n/).forEach(function (line) {
      if (!/^\s*SMB\s+/i.test(line) || /^\s*SMB\s+\S+\s+(?:5985|5986)\b/i.test(line) || line.indexOf('[+]') < 0) return;
      var auth = line.split('[+]')[1].trim();
      var credPart = auth.replace(/(?:[ \t]+\([^)\r\n]*\))+[ \t]*$/, '').trim();
      var isGuest = guestCommand || /\(guest\)/i.test(auth) || /^(?:[^\\]+\\)?guest:/i.test(credPart);
      var isAnon = !isGuest && (anonymousCommand || /\(null auth:true\)/i.test(auth) || /^(?:[^\\]*\\)?(?:anonymous)?:$/i.test(credPart) || credPart === '');
      if (isGuest) { _add(facts, mkFact('smb.guest_session', h, { tool: 'nxc' }, S, source)); gotSession = true; }
      if (isAnon) { _add(facts, mkFact('smb.null_session', h, { tool: 'nxc' }, S, source)); gotSession = true; }
    });
    var isSamrAnonProbe = /--(?:rid-brute|users|groups|local-groups|loggedon-users|sessions)\b|\b(?:samr|lsarpc|enumdomusers|lookupnames|querydispinfo|Error enumerating\s+(?:domain\s+)?(?:users|groups)|(?:LSAD|SAMR)\s+SessionError)\b/i.test(cmdHay) && !/--shares\b/i.test(cmdHay);
    if (anonymousCommand && !gotSession && !isSamrAnonProbe && /^\s*SMB\s+.*\[-\].*(?:STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE)/im.test(text)) {
      _add(facts, mkFact('blocker.smb_null_denied', h, { tool: 'nxc' }, S, source));
    }
    if (anonymousCommand && isSamrAnonProbe && /(?:STATUS_ACCESS_DENIED|NT_STATUS_ACCESS_DENIED)/i.test(text)) {
      _add(facts, mkFact('blocker.samr_null_denied', h, { tool: 'samr-anon', stage: 'authorization' }, S, source));
    }
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

  var _PV_SAM_RE = /^\s*samaccountname\s*:\s*(?<v>[^\s,;]+)\s*$/im;
  var _PV_CN_RE = /^\s*cn\s*:\s*(?<v>[^\s,;]+)\s*$/im;
  var _PV_MEMBER_RE = /^\s*(?:member|membername)\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_USER_QUERY_RE = /get-(?:net|domain|ad)(?:user|groupmember)/i;
  var _PV_OTHER_QUERY_RE = /get-(?:net|domain|ad)(?:group\b|computer)/i;
  var _PV_DOMAIN_QUERY_RE = /\bget-(?:net|domain|ad)domain(?:controller)?\b/i;
  var _PV_SHAREFINDER_RE = /^\s*\\\\(?<host>[A-Za-z0-9_.-]+)\\(?<share>[^\s\\]+)(?:[ \t]+-[ \t]*(?<comment>[^\r\n]*))?\s*$/im;
  var _PV_TABLE_COL_SET = { cn: 1, samaccountname: 1, userprincipalname: 1, member: 1, membername: 1, dnshostname: 1 };

  function _parse_ps_format_table(text, isCompQuery) {
    var lines = String(text || '').split(/\r?\n/);
    var usersSet = {}, compsSet = {}, inferredDomain = '';
    for (var i = 0; i < lines.length - 1; i++) {
      var hdrLine = lines[i], dashLine = lines[i + 1];
      if (!hdrLine.trim() || !/^\s*-+(?:\s+-+)*\s*$/.test(dashLine)) continue;
      var colSpans = [], dm, dRe = /-+/g;
      while ((dm = dRe.exec(dashLine)) !== null) {
        colSpans.push({ start: dm.index });
      }
      if (!colSpans.length) continue;
      var cols = [];
      for (var c = 0; c < colSpans.length; c++) {
        var cStart = colSpans[c].start;
        var cEnd = (c + 1 < colSpans.length) ? colSpans[c + 1].start : hdrLine.length;
        cols.push(hdrLine.slice(cStart, cEnd).trim().toLowerCase());
      }
      if (!cols.some(function (cn) { return _PV_TABLE_COL_SET[cn]; })) continue;
      var hasExplicitUserCol = cols.some(function (cn) { return cn === 'samaccountname' || cn === 'userprincipalname' || cn === 'member' || cn === 'membername'; });
      var treatCnAsComp = isCompQuery || (!hasExplicitUserCol && cols.indexOf('dnshostname') >= 0);
      for (var r = i + 2; r < lines.length; r++) {
        var rLine = lines[r];
        if (!rLine.trim()) break;
        if (/^\s*(?:PS\s+[A-Za-z]:\\|\*Evil-WinRM\*\s+PS\b|[A-Za-z]:\\[^>\r\n]*>)/i.test(rLine)) break;
        if (r + 1 < lines.length && /^\s*-+(?:\s+-+)*\s*$/.test(lines[r + 1])) break;
        for (var cc = 0; cc < cols.length; cc++) {
          var colName = cols[cc];
          if (!_PV_TABLE_COL_SET[colName]) continue;
          var sStart = colSpans[cc].start;
          if (sStart >= rLine.length) continue;
          var sEnd = (cc + 1 < colSpans.length) ? colSpans[cc + 1].start : rLine.length;
          var rawVal = rLine.slice(sStart, sEnd).trim();
          if (!rawVal || /^-+$/.test(rawVal)) continue;
          if (/^cn=/i.test(rawVal)) {
            var dnHead = rawVal.split(',')[0];
            rawVal = dnHead.indexOf('=') >= 0 ? dnHead.split('=').slice(1).join('=').trim() : rawVal;
          }
          if (colName === 'dnshostname') {
            if (/^[A-Za-z0-9][A-Za-z0-9_.-]*\$?$/.test(rawVal)) {
              compsSet[rawVal.toLowerCase()] = rawVal;
              var dParts = rawVal.split('.');
              if (!inferredDomain && dParts.length >= 3) inferredDomain = dParts.slice(1).join('.').toLowerCase();
            }
          } else if (rawVal.charAt(rawVal.length - 1) === '$' || (colName === 'cn' && treatCnAsComp) || (colName === 'samaccountname' && isCompQuery)) {
            if (/^[A-Za-z0-9][A-Za-z0-9_.-]*\$?$/.test(rawVal)) compsSet[rawVal.toLowerCase()] = rawVal;
          } else {
            if (!inferredDomain && rawVal.indexOf('@') > 0) {
              var atDom = rawVal.split('@').pop().trim().toLowerCase();
              if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(atDom)) inferredDomain = atDom;
            }
            var u = C._clean_username(rawVal);
            if (C._valid_username(u)) usersSet[u.toLowerCase()] = u;
          }
        }
      }
      i = r - 1;
    }
    return {
      users: C.uniqueSortedCI(Object.keys(usersSet).map(function (k) { return usersSet[k]; })),
      computers: C.uniqueSortedCI(Object.keys(compsSet).map(function (k) { return compsSet[k]; })),
      domain: inferredDomain
    };
  }

  function _parse_powerview(text, ws, command, source, facts, opts) {
    opts = opts || {};
    var cmd = command || '';
    var lc = cmd.toLowerCase();
    var h = 'host:' + ws.target;
    var domain = opts.domain_hint || C._domain_from_facts(ws);

    // 1. Get-Domain / Get-NetDomain and Get-DomainController / Get-NetDomainController
    var hasDomainKeys = /^\s*Forest\s*:\s*[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*$/im.test(text)
      && /^\s*(?:DomainControllers|PdcRoleOwner|RidRoleOwner|HighestCommittedUsn|IPAddress)\s*:/im.test(text);
    if (reSearch(_PV_DOMAIN_QUERY_RE, cmd) || hasDomainKeys) {
      var forestM = /^\s*Forest\s*:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*$/im.exec(text);
      var domFieldM = /^\s*Domain\s*:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*$/im.exec(text);
      var dcListM = /^\s*DomainControllers\s*:\s*\{?([^}\r\n]+)\}?\s*$/im.exec(text);
      var pdcM = /^\s*PdcRoleOwner\s*:\s*([A-Za-z0-9_.-]+)\s*$/im.exec(text);
      var ipM = /^\s*IPAddress\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/im.exec(text);
      var nameM = /^\s*Name\s*:\s*([A-Za-z0-9_.-]+)\s*$/im.exec(text);
      var pvDom = '';
      if (domFieldM) pvDom = domFieldM[1].trim().toLowerCase();
      else if (dcListM && nameM && /\.[A-Za-z]{2,}$/.test(nameM[1].trim())) pvDom = nameM[1].trim().toLowerCase();
      else if (forestM) pvDom = forestM[1].trim().toLowerCase();
      if (pvDom) {
        domain = pvDom;
        _add(facts, mkFact('ad.domain_known', 'domain:' + pvDom, { name: pvDom, method: 'powerview' }, S, source));
        _add(facts, mkFact('ad.base_dn', 'domain:' + pvDom, { base_dn: C._base_dn_from_domain(pvDom) }, S, source));
        _add(facts, mkFact('host.domain', h, { domain: pvDom }, S, source));
      }
      var rawDcFqdn = '';
      if (ipM && nameM && (!pvDom || nameM[1].trim().toLowerCase() !== pvDom)) rawDcFqdn = nameM[1].trim();
      else if (dcListM) rawDcFqdn = dcListM[1].split(',')[0].trim();
      else if (pdcM) rawDcFqdn = pdcM[1].trim();
      var dcShort = rawDcFqdn ? rawDcFqdn.split('.')[0] : '';
      if (ipM) {
        var dcIp = ipM[1].trim();
        var dcScope = 'host:' + dcIp;
        var dcVal = { host: dcIp, method: 'powerview' };
        if (dcShort) dcVal.name = dcShort;
        if (rawDcFqdn) dcVal.fqdn = rawDcFqdn;
        if (pvDom || domain) dcVal.domain = pvDom || domain;
        _add(facts, mkFact('ad.dc_candidate', dcScope, dcVal, S, source));
        if (dcShort) _add(facts, mkFact('host.hostname', dcScope, { name: dcShort }, S, source));
        if (pvDom || domain) _add(facts, mkFact('host.domain', dcScope, { domain: pvDom || domain }, S, source));
      } else if (rawDcFqdn) {
        var domDcVal = { method: 'powerview' };
        if (dcShort) domDcVal.name = dcShort;
        domDcVal.fqdn = rawDcFqdn;
        if (pvDom || domain) domDcVal.domain = pvDom || domain;
        _add(facts, mkFact('ad.dc_candidate', C._scope_for_domain(ws, pvDom || domain), domDcVal, S, source));
      }
    }

    // 2. Invoke-ShareFinder / Get-DomainShare UNC or Format-Table share rows
    var hasShareFinderTableHdr = /^\s*Name\s+Type\s+Remark\s+ComputerName\s*$/im.test(text);
    if (lc.indexOf('invoke-sharefinder') >= 0 || lc.indexOf('find-domainshare') >= 0 || lc.indexOf('get-domainshare') >= 0 || hasShareFinderTableHdr || reSearch(_PV_SHAREFINDER_RE, text)) {
      var sharesByScope = {}, allShares = [], uncShares = [];
      var checkAccess = /-(?:checkshareaccess|-check-share-access)\b/i.test(cmd);
      reAll(_PV_SHAREFINDER_RE, text).forEach(function (sm) {
        var shHost = (sm.groups.host || '').trim();
        var shName = (sm.groups.share || '').trim();
        if (!shHost || !shName) return;
        allShares.push(shName);
        uncShares.push('\\\\' + shHost + '\\' + shName);
        var shScope = C._IPV4_RE.test(shHost) ? ('host:' + observedHost(ws, shHost)) : h;
        (sharesByScope[shScope] = sharesByScope[shScope] || []).push(shName);
      });
      if (hasShareFinderTableHdr) {
        var sfLines = String(text || '').split(/\r?\n/);
        for (var sfi = 0; sfi < sfLines.length - 1; sfi++) {
          if (!/^\s*Name\s+Type\s+Remark\s+ComputerName\s*$/i.test(sfLines[sfi]) || !/^\s*-+(?:\s+-+){3,}\s*$/.test(sfLines[sfi + 1])) continue;
          var sfCompIdx = sfLines[sfi].toLowerCase().indexOf('computername');
          for (var sfr = sfi + 2; sfr < sfLines.length; sfr++) {
            var sfRow = sfLines[sfr];
            if (!sfRow.trim() || /^\s*(?:PS\s+[A-Za-z]:\\|\*Evil-WinRM\*\s+PS\b)/i.test(sfRow)) break;
            var sfNameM = /^\s*(\S+)\s+\d+\b/.exec(sfRow);
            if (!sfNameM) continue;
            var tblShare = sfNameM[1].trim();
            var tblHost = sfCompIdx >= 0 && sfCompIdx < sfRow.length ? sfRow.slice(sfCompIdx).trim().split(/\s+/)[0] : '';
            allShares.push(tblShare);
            if (tblHost) uncShares.push('\\\\' + tblHost + '\\' + tblShare);
            var tblScope = (tblHost && C._IPV4_RE.test(tblHost)) ? ('host:' + observedHost(ws, tblHost)) : h;
            (sharesByScope[tblScope] = sharesByScope[tblScope] || []).push(tblShare);
          }
          break;
        }
      }
      Object.keys(sharesByScope).forEach(function (sc) {
        var uniqSh = C.uniqueSortedCI(sharesByScope[sc]);
        var shVal = { shares: uniqSh, count: uniqSh.length, tool: 'powerview' };
        if (sc === h && uncShares.length) shVal.unc_shares = C.uniqueSortedCI(uncShares).slice(0, 40);
        _add(facts, mkFact('smb.shares', sc, shVal, S, source));
        if (checkAccess) {
          var readable = uniqSh.filter(function (s) { return !/^(?:IPC\$|PRINT\$)$/i.test(s); });
          if (readable.length) _add(facts, mkFact('smb.readable_share', sc, { shares: readable, tool: 'powerview' }, S, source));
        }
      });
    }

    // 3. PowerShell underlined Format-Table projections (cn, samaccountname, member, dnshostname)
    var isCompQuery = reSearch(/get-(?:net|domain|ad)computer/i, cmd);
    var tbl = _parse_ps_format_table(text, !!isCompQuery);
    if (tbl.domain && !domain) domain = tbl.domain;

    // 4. Format-List user / group-member stanzas
    var usersSet = {};
    tbl.users.forEach(function (u) { usersSet[u.toLowerCase()] = u; });
    var isUserOrCommandless = reSearch(_PV_USER_QUERY_RE, cmd) || (!cmd && /^\s*samaccountname\s*:\s*\S+/im.test(text));
    if (isUserOrCommandless) {
      reAll(_PV_SAM_RE, text).forEach(function (m) {
        var u = C._clean_username(m.groups.v);
        if (u && u.charAt(u.length - 1) !== '$' && C._valid_username(u)) usersSet[u.toLowerCase()] = u;
      });
      if (/get-(?:net|domain|ad)groupmember/i.test(cmd)) {
        reAll(_PV_MEMBER_RE, text).forEach(function (m) {
          var rawM = (m.groups.v || '').trim();
          if (/^cn=/i.test(rawM)) rawM = rawM.split(',')[0].split('=').slice(1).join('=').trim();
          var u = C._clean_username(rawM);
          if (u && u.charAt(u.length - 1) !== '$' && C._valid_username(u)) usersSet[u.toLowerCase()] = u;
        });
      }
      if (!Object.keys(usersSet).length && !reSearch(_PV_OTHER_QUERY_RE, cmd)) {
        reAll(_PV_CN_RE, text).forEach(function (m) {
          var u = C._clean_username(m.groups.v);
          if (u && u.charAt(u.length - 1) !== '$' && C._valid_username(u)) usersSet[u.toLowerCase()] = u;
        });
      }
    }
    var users = C.uniqueSortedCI(Object.keys(usersSet).map(function (k) { return usersSet[k]; }));
    if (users.length) {
      _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: users, count: users.length, method: 'powerview' }, S, source));
    }
    if (tbl.computers.length) {
      _add(facts, mkFact('ad.computer_list', C._scope_for_domain(ws, domain), { computers: tbl.computers, count: tbl.computers.length, method: 'powerview' }, S, source));
    }
  }
  C._parse_powerview = _parse_powerview;

  var _PV_GROUP_QUERY_RE = /get-(?:net|domain)group/i;
  var _PV_COMPUTER_QUERY_RE = /get-(?:net|domain)computer/i;
  var _PV_ACL_QUERY_RE = /get-(?:net|domain)?\w*objectacl|get-acl\b|get-domainobjectacl|find-interestingdomainacl/i;
  var _PV_SAM_FULL_RE = /^\s*samaccountname\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_NAME_FULL_RE = /^\s*name\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_CN_FULL_RE = /^\s*cn\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_DNSHOST_RE = /^\s*dnshostname\s*:\s*(?<v>[^\s,;]+)\s*$/im;
  var _PV_OS_RE = /^\s*operatingsystem\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_ADRIGHTS_RE = /^\s*activedirectoryrights\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_ACL_TARGET_RE = /^\s*(?:objectdn|objectidentity|objectname)\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_ACL_ID_RE = /^\s*(?:securityidentifier|identityreference(?:name)?|identitysid)\s*:\s*(?<v>.+?)\s*$/im;
  var _PV_ABUSABLE_RIGHT_RE = /^(?:GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|AllExtendedRights|ForceChangePassword|Self|WriteMembers|ExtendedRight)$/i;

  function _pv_values(text) {
    for (var i = 1; i < arguments.length; i++) {
      var rx = arguments[i], seen = {}, out = [];
      reAll(rx, text).forEach(function (m) {
        var v = (m.groups.v || '').trim();
        if (v && !seen[v.toLowerCase()] && v.charAt(0) !== '{') { seen[v.toLowerCase()] = true; out.push(v); }
      });
      if (out.length) return out;
    }
    return [];
  }

  function _parse_powerview_objects(text, ws, command, source, facts, opts) {
    opts = opts || {};
    var lc = (command || '').toLowerCase();
    var domain = opts.domain_hint || C._domain_from_facts(ws);
    var scope = C._scope_for_domain(ws, domain);
    if (reSearch(_PV_GROUP_QUERY_RE, lc)) {
      var groups = _pv_values(text, _PV_SAM_FULL_RE, _PV_NAME_FULL_RE, _PV_CN_FULL_RE);
      if (groups.length) _add(facts, mkFact('ad.group_list', scope, { groups: groups, count: groups.length, method: 'powerview' }, S, source));
    }
    if (reSearch(_PV_COMPUTER_QUERY_RE, lc)) {
      var comps = _pv_values(text, _PV_DNSHOST_RE, _PV_SAM_FULL_RE, _PV_NAME_FULL_RE);
      if (!comps.length) comps = _parse_ps_format_table(text, true).computers;
      if (comps.length) {
        var value = { computers: comps, count: comps.length, method: 'powerview' };
        var oses = _pv_values(text, _PV_OS_RE);
        if (oses.length) value.operating_systems = oses;
        _add(facts, mkFact('ad.computer_list', scope, value, S, source));
      }
    }
    if (reSearch(_PV_ACL_QUERY_RE, lc) || (!lc && reSearch(_PV_ADRIGHTS_RE, text) && reSearch(_PV_ACL_TARGET_RE, text))) {
      var rightsSet = {};
      text.split(/\r?\n/).forEach(function (line) {
        reAll(_PV_ADRIGHTS_RE, line).forEach(function (m) {
          m.groups.v.split(/[,\s]+/).forEach(function (r) {
            r = r.trim();
            if (r && _PV_ABUSABLE_RIGHT_RE.test(r)) rightsSet[r] = true;
          });
        });
      });
      var rights = C.uniqueSortedCI(Object.keys(rightsSet));
      if (rights.length) {
        _add(facts, mkFact('ad.acl_lead', scope, {
          rights: rights,
          targets: _pv_values(text, _PV_ACL_TARGET_RE).slice(0, 8),
          principals: _pv_values(text, _PV_ACL_ID_RE).slice(0, 8),
          method: 'powerview',
          note: 'enumerated control right (lead), cash it in with the ACL-abuse move; not a granted control path yet',
        }, S, source));
      }
    }
  }
  C._parse_powerview_objects = _parse_powerview_objects;

  var _KERBRUTE_USER_RE = /\[\+\]\s+VALID USERNAME:\s*(?<u>[A-Za-z0-9._-]+)(?:@(?<dom>[A-Za-z0-9.-]+))?/;
  var _KERBRUTE_LOGIN_RE = /\[\+\]\s+VALID LOGIN:\s*(?<u>[A-Za-z0-9._-]+)(?:@(?<dom>[A-Za-z0-9.-]+))?:(?<p>\S.*?)\s*$/m;

  function _add_valid_login_credential(ws, source, facts, user, password, domain, method) {
    user = C._clean_username(user);
    if (!C._valid_username(user, false) || !C._valid_password(password)) return;
    var value = { user: user, password: password, method: method };
    if (domain) value.domain = domain;
    _add(facts, mkFact('credential.available', C._scope_for_domain(ws, domain), value, S, source));
    // kerbrute VALID LOGIN already proved this credential against the KDC, so it is validated.
    var observed = _auth_observation(ws, { user: user, password: password, domain: domain || '', service: 'kerberos', via: method || 'valid-login', outcome: 'accepted' });
    delete observed.password;
    _add(facts, mkFact('credential.validated', 'host:' + ws.target, observed, S, source));
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

  var _LOOT_NAME_HINTS = ['password', 'passw', 'passwd', 'cred', 'secret', 'unattend', 'sysprep', 'web.config', 'connection', 'id_rsa', 'id_ed25519', '.ppk', '.kdbx', '.key', 'vnc', 'vpn', '.bak', 'backup', '.ntds', 'ntds.dit', 'sam', '.vmdk', '.ovpn', 'notes', 'todo', 'database', 'db-connection', '.pfx', '.ps1', 'groups.xml', 'scheduledtasks.xml', 'services.xml', 'datasources.xml', 'cpassword'];
  var _SMBMAP_FILE_RE = /^\s*fr[-rwxd]{8}\s+(?<size>\d+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s+(?<name>.+?)\s*$/m;
  var _SMBMAP_SECTION_RE = /^\s*\.\\(?<path>[^*\r\n]*)\*\s*$/m;
  // Interactive smbclient "smb: \>" ls/dir listing row:  name  ATTR  size  Day Mon DD HH:MM:SS YYYY
  var _SMB_LS_ROW_RE = /^[ \t]+(?<name>\S(?:[^\r\n]*?\S)?)[ \t]+(?<attr>[DAHSRNCETI]+)\s+(?<size>\d+)\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}\s*$/i;
  // smbclient ls footer, e.g. "64607 blocks of size 4096. 20590 blocks available"
  var _SMB_LS_FOOTER_RE = /\d+\s+blocks of size\s+\d+\.\s+\d+\s+blocks available/i;

  function _looks_sensitive(name) {
    var low = name.toLowerCase();
    return _LOOT_NAME_HINTS.some(function (hh) { return low.indexOf(hh) >= 0; });
  }

  // Shared loot.files minting for any file/directory enumeration (SMB share spider or on-host
  // shell listing). files[] = [{ share, path, size }]; `via` records the source shape so evidence
  // surfaces can tell an SMB-share spider from a native dir/Get-ChildItem listing.
  function _emit_file_loot(facts, h, files, tool, via, text, ws, source) {
    if (!files || !files.length) return;
    function nameOf(f) {
      var path = String(f.path).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
      var share = String(f.share || '').replace(/^\/+|\/+$/g, '');
      if (!share || path.indexOf(share + '/') === 0 || path === share) return path;
      return share + '/' + path;
    }
    var names = C.uniqueSortedCI(files.map(nameOf));
    var sensitive = C.uniqueSortedCI(names.filter(_looks_sensitive));
    _add(facts, mkFact('loot.files', h, { files: names, count: names.length, tool: tool, entries: files, sensitive: sensitive, via: via }, S, source));

    var gppFiles = names.filter(function (n) { return /groups\.xml|scheduledtasks\.xml|services\.xml|datasources\.xml/i.test(n); });
    if (gppFiles.length) {
      _add(facts, mkFact('config.review', h, { kind: 'gpp_xml', files: gppFiles }, S, source));
    }
    if (text.indexOf('cpassword=') >= 0 || text.indexOf('cpassword =') >= 0) {
      _parse_gpp_artifacts(text, ws, source, facts);
    }
  }
  C._emit_file_loot = _emit_file_loot;

  function _parse_share_inventory(text, ws, command, source, facts) {
    var h = 'host:' + ws.target, files = [];
    var cmd = String(command || '').toLowerCase();
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
    if (!files.length && cmd.indexOf('smbmap') >= 0) {
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
    if (!files.length && (text.indexOf('getting file ') >= 0 || cmd.indexOf('smbclient') >= 0)) {
      var mGetRe = /getting file\s+([^\r\n]+?)\s+of size\s+(\d+)/gi;
      var match;
      while ((match = mGetRe.exec(text)) !== null) {
        var cleanPath = match[1].replace(/\\/g, '/').replace(/^\/+/, '');
        files.push({ share: '', path: cleanPath, size: match[2] });
      }
    }
    if (!files.length) {
      // Interactive smbclient "smb: \>" ls/dir directory listing.
      var lsRows = [], sawDotEntries = false;
      text.split(/\r?\n/).forEach(function (line) {
        var rm = _SMB_LS_ROW_RE.exec(line);
        if (!rm) return;
        var nm = rm.groups.name.trim();
        if (nm === '.' || nm === '..') { sawDotEntries = true; return; }
        if (!nm) return;
        lsRows.push({ share: '', path: nm, size: rm.groups.size });
      });
      // Require a confident signal that this is a real listing: the blocks-of-size footer, the
      // "." / ".." self entries smbclient always prints, at least two file rows, or an explicit
      // interactive `smbclient ls/dir <file>` command.
      if (lsRows.length && (_SMB_LS_FOOTER_RE.test(text) || sawDotEntries || lsRows.length >= 2 || /^smbclient\s+(?:ls|dir)\b/i.test(command))) {
        files = lsRows;
      }
    }
    if (!files.length && /stream:\s*\[/i.test(text)) {
      var adsRe = /^\s*stream:\s*\[(:[^:\]\r\n]+:\$DATA)\],\s*(\d+)\s+bytes/gim, adsM;
      var altFile = (/altname:\s*([^\r\n]+)/i.exec(text) || [])[1] || 'stream';
      while ((adsM = adsRe.exec(text)) !== null) {
        files.push({ share: '', path: altFile.trim() + adsM[1], size: adsM[2] });
      }
    }
    if (!files.length) return;
    var tool = command.toLowerCase().indexOf('spider_plus') >= 0 ? 'spider_plus' : (command.toLowerCase().indexOf('smbmap') >= 0 ? 'smbmap' : 'smbclient');
    _emit_file_loot(facts, h, files, tool, 'smb-share', text, ws, source);
  }
  C._parse_share_inventory = _parse_share_inventory;

  // Native on-host directory listings. Two formats, often pasted with no tool token on the unit
  // command (just "dir" / "ls" / "gci"):
  //   cmd.exe  dir:   " Directory of C:\path"  then  "MM/DD/YYYY  HH:MM AM   <size|<DIR>>   name"
  //   PowerShell Get-ChildItem / ls / Invoke-Command { ls }:  "    Directory: C:\path"  then a
  //     "Mode  LastWriteTime  Length Name [PSComputerName]" table with "-a---  M/D/YYYY  H:MM  LEN name" rows.
  // Each file's path is anchored to the "Directory of/Directory:" header above it, so loot.files
  // records full host paths. Rows are only taken after the matching header is seen, so a stray date
  // line or a bare "-a---" fragment never mints on its own.
  var _WIN_DIR_HDR_LINE_RE = /^\s*Directory of\s+(?<path>.+?)\s*$/i;
  var _WIN_DIR_ROW_RE = /^\s*(?<date>\d{1,2}\/\d{1,2}\/\d{4})\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\s+(?<size><DIR>|[\d,]+)\s+(?<name>\S.*?)\s*$/i;
  var _PS_DIR_HDR_LINE_RE = /^\s*(?:Directory|[^\s:\\/0-9]{2,24})\s*:\s+(?<path>(?:[A-Za-z]:\\|\\\\[^\\\s]+\\)[^\r\n]+?)\s*$/i;
  var _PS_LS_HEADER_RE = /^\s*Mode\s+LastWriteTime\s+Length\s+Name(?<pscol>\s+PSComputerName)?\s*$/i;
  var _PS_LS_ROW_RE = /^\s*(?<mode>[-dalrhscetn]{4,7})\s+(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{4}|\d{4}[\/.-]\d{1,2}[\/.-]\d{1,2})\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?\s+(?<len>\d+)?\s+(?<rest>\S.*?)\s*$/i;

  function _fs_join(dir, name) {
    if (!dir) return name;
    return dir.replace(/[\\/]+$/, '') + '\\' + name;
  }

  function _parse_fs_listing(text, ws, command, source, facts) {
    var h = 'host:' + ws.target;
    var cmdFiles = [], psFiles = [], psHasCol = false;
    var curPath = '', mode = null;
    text.split(/\r?\n/).forEach(function (line) {
      var winHdr = _WIN_DIR_HDR_LINE_RE.exec(line);
      if (winHdr) { curPath = winHdr.groups.path.trim(); mode = 'cmd'; return; }
      var psHdr = _PS_DIR_HDR_LINE_RE.exec(line);
      if (psHdr) { curPath = psHdr.groups.path.trim(); mode = 'ps'; return; }
      var psColHdr = _PS_LS_HEADER_RE.exec(line);
      if (psColHdr) { mode = 'ps'; psHasCol = psHasCol || !!psColHdr.groups.pscol; return; }
      if (mode === 'cmd') {
        var wr = _WIN_DIR_ROW_RE.exec(line);
        if (wr) {
          var wn = wr.groups.name.trim();
          if (wn && wn !== '.' && wn !== '..') {
            cmdFiles.push({ share: '', path: _fs_join(curPath, wn), size: wr.groups.size === '<DIR>' ? '' : wr.groups.size.replace(/,/g, '') });
          }
          return;
        }
      }
      if (mode === 'ps') {
        var pr = _PS_LS_ROW_RE.exec(line);
        if (pr) {
          var rest = pr.groups.rest;
          var pn = (psHasCol ? rest.split(/\s{2,}/)[0] : rest).trim();
          if (pn && pn !== '.' && pn !== '..') {
            psFiles.push({ share: '', path: _fs_join(curPath, pn), size: pr.groups.len || '' });
          }
        }
      }
    });
    if (cmdFiles.length) _emit_file_loot(facts, h, cmdFiles, 'dir', 'shell-listing', text, ws, source);
    if (psFiles.length) _emit_file_loot(facts, h, psFiles, psHasCol ? 'invoke-command' : 'powershell', 'shell-listing', text, ws, source);
  }
  C._parse_fs_listing = _parse_fs_listing;

  // ── Confirmed file transfer / tool staged onto the host (outcome axis) ─────────────
  // A download or copy that OBOL can PROVE landed: certutil URLCache, wget "... saved [n/n]",
  // scp "name  100% ...", bitsadmin "Transfer complete", or a Windows "N file(s) copied". Mints a
  // terminal host.tool_staged receipt (the host. prefix makes it a report fact, not a move gate) so a
  // staged linpeas/nc/chisel is acknowledged instead of minting nothing. Each branch needs a tool-
  // appropriate SUCCESS token, so a failed or in-progress transfer mints nothing, and certutil arg
  // errors stay with blocker.certutil_usage. curl -O / Invoke-WebRequest -OutFile are intentionally
  // left out: their success is silent (no positive token), and a bare "100" meter row collides with
  // web-enum output, so recognizing them would cost a false positive.
  var _TRANSFER_WGET_OK_RE = /(?:^|\s)['"]?(?<f>[^\s'"]+)['"]?\s+saved\s+\[\d/im;
  var _TRANSFER_SAVING_RE = /^\s*Saving to:\s*['"]?(?<f>[^'"\r\n]+?)['"]?\s*$/im;
  var _TRANSFER_SCP_RE = /^[ \t]*(?<f>\S[^\r\n]{0,200}?)[ \t]+100%[ \t]+[\d.]+[ \t]*[KMGT]?B?\b/im;
  var _TRANSFER_CERTUTIL_OK_RE = /CertUtil:\s*-\w[\w-]*\s*command completed successfully/i;
  var _TRANSFER_BITS_OK_RE = /\bTransfer\s+complete\b/i;
  var _TRANSFER_COPY_OK_RE = /^\s*\d+\s+file\(s\)\s+copied\b/im;

  function _staged_basename(s) { return (s || '').trim().replace(/[`'"]/g, '').replace(/^.*[\\/]/, ''); }
  function _staged_name(command, text, tool) {
    var m;
    if (tool === 'wget' && (m = _TRANSFER_WGET_OK_RE.exec(text)) && m.groups.f) return _staged_basename(m.groups.f);
    if ((m = _TRANSFER_SAVING_RE.exec(text)) && m.groups.f) return _staged_basename(m.groups.f);
    if (tool === 'scp' && (m = _TRANSFER_SCP_RE.exec(text)) && m.groups.f) return _staged_basename(m.groups.f);
    if ((m = /\s-(?:O|o|OutFile)\s+['"]?([^\s'"]+)/i.exec(command || ''))) return _staged_basename(m[1]);
    if ((m = /https?:\/\/[^\s'"]+\/([^\/\s'"?#]+)/i.exec(command || ''))) return _staged_basename(m[1]);
    var toks = (command || '').trim().split(/\s+/).filter(function (t) { return t && t.charAt(0) !== '-' && !/^https?:/i.test(t) && !/[@:]/.test(t); });
    if (!toks.length) return '';
    var rawLast = toks[toks.length - 1] || '';
    var isTrailingDir = /[\\/]$/.test(rawLast) || rawLast === '.' || rawLast === '..';
    var last = isTrailingDir ? '' : _staged_basename(rawLast);
    if (last && last !== '.' && last !== '..') return last;
    return toks.length >= 2 ? _staged_basename(toks[toks.length - 2]) : '';
  }

  function _parse_transfer_success(text, ws, command, source, facts) {
    var lc = (command || '').toLowerCase();
    var tool = '', ok = false, via = 'download';
    if ((/\bcertutil\b/.test(lc) && /\burlcache\b/.test(lc)) || (!lc && _TRANSFER_CERTUTIL_OK_RE.test(text))) { tool = 'certutil'; ok = _TRANSFER_CERTUTIL_OK_RE.test(text); }
    else if (/\bwget\b/.test(lc) || (!lc && _TRANSFER_WGET_OK_RE.test(text))) { tool = 'wget'; ok = _TRANSFER_WGET_OK_RE.test(text); }
    else if (/\bscp\b/.test(lc)) { tool = 'scp'; via = 'scp'; ok = _TRANSFER_SCP_RE.test(text); }
    else if (/\bbitsadmin\b/.test(lc)) { tool = 'bitsadmin'; ok = _TRANSFER_BITS_OK_RE.test(text); }
    else if (/\b(?:copy|xcopy)\b/.test(lc) || (!lc && _TRANSFER_COPY_OK_RE.test(text))) { tool = 'copy'; via = 'copy'; ok = _TRANSFER_COPY_OK_RE.test(text); }
    else if (/\bsmbclient\b/.test(lc) || /putting file\s+\S+\s+as\s+\\/i.test(text)) { tool = 'smbclient'; via = 'smb-put'; ok = /putting file\s+\S+\s+as\s+\S+/i.test(text); }
    else if (/\b(?:mssqlclient|upload)\b/.test(lc) && /\[\+\]\s*Upload completed\b/i.test(text)) { tool = 'mssqlclient'; via = 'mssql-upload'; ok = true; }
    if (!tool || !ok) return;
    var h = 'host:' + ws.target;
    _add(facts, mkFact('host.tool_staged', h, { file: _staged_name(command, text, tool), tool: tool, via: via }, S, source));
  }
  C._parse_transfer_success = _parse_transfer_success;

  // Raw rpcclient SID/name resolution and single-object detail dumps that enum4linux-ng/nxc never
  // relabel to the (SidTypeUser)/user:[x] rid:[y] shapes _rid_usernames already catches. These are
  // the interactive residue of an rpcclient $> session (or a RID-cycling loop): lookupsids prints
  // "<SID> <DOMAIN>\<name> (<type>)", lookupnames prints "<name> <SID> (<Label>: <type>)", queryuser
  // prints "User Name : <name>", querygroup prints "Group Name : <name>". The SID_NAME_USE type tells
  // user (1) from group (2 group / 4 alias / 5 well-known), so resolved accounts feed ad.user_list
  // (the sprayable/roastable pivot) and resolved groups feed ad.group_list. *unknown* resolutions and
  // NT_STATUS_NONE_MAPPED failures carry no name and mint nothing.
  function _rpc_resolution(text) {
    var usersMap = {}, groupsMap = {};
    function addUser(n) { n = C._clean_username(String(n || '').trim()); if (C._valid_username(n, false)) usersMap[n] = true; }
    function addGroup(n) {
      n = String(n || '').trim();
      if (n && n !== '(null)' && !/\*unknown\*/i.test(n) && !/^\$[A-Z0-9]{6}-[A-Z0-9]{12}$/i.test(n)) groupsMap[n] = true;
    }
    // lookupsids: "S-1-5-21-...-RID DOMAIN\name (type)". type 1 = user, 2/4/5 = group.
    reAll(/^[ \t]*S-1-5-[0-9-]+\s+(?<dom>[^\\\s()]+)\\(?<name>[^()\r\n]+?)\s+\((?<type>\d{1,2})\)[ \t]*$/gim, text).forEach(function (m) {
      var dom = m.groups.dom || '', name = (m.groups.name || '').trim(), t = parseInt(m.groups.type, 10);
      if (/\*unknown\*/i.test(dom) || /\*unknown\*/i.test(name)) return;
      if (t === 1) addUser(name);
      else if (t === 2 || t === 4 || t === 5) addGroup(name);
    });
    // lookupnames: "name S-1-...-RID (Label: type)". Label names the SID_NAME_USE class.
    reAll(/^[ \t]*(?<name>\S[^\r\n]{0,120}?)[ \t]+S-1-[0-9-]+[ \t]+\((?<label>[A-Za-z ]+):\s*\d{1,2}\)[ \t]*$/gim, text).forEach(function (m) {
      var name = (m.groups.name || '').trim(), label = (m.groups.label || '').trim().toLowerCase();
      if (/\*unknown\*/i.test(name)) return;
      if (label === 'user') addUser(name);
      else if (/group|alias/.test(label)) addGroup(name);
    });
    // queryuser / querygroup single-object detail dumps.
    reAll(/^[ \t]*User Name\s*:\s*(?<name>[A-Za-z0-9._$-]+)[ \t]*$/gim, text).forEach(function (qu) {
      if (qu.groups && qu.groups.name) addUser(qu.groups.name);
    });
    reAll(/^[ \t]*Group Name\s*:\s*(?<name>[^\r\n]+?)[ \t]*$/gim, text).forEach(function (qg) {
      if (qg.groups && qg.groups.name) addGroup(qg.groups.name);
    });
    return { users: Object.keys(usersMap), groups: Object.keys(groupsMap) };
  }
  C._rpc_resolution = _rpc_resolution;

  function _parse_rid_user_list(text, ws, source, facts, opts) {
    opts = opts || {};
    var h = 'host:' + ws.target;
    if (!facts.some(function (f) { return f.kind === 'host.os_family'; })) C._add_os_from_text(text, ws, source, facts, 'smb', 'medium', true);
    var domain = opts.domain_hint || C._domain_from_facts(ws);
    var domMatch = reSearch(/^\s*(?:\[\+\]\s*Long domain name is|DNS domain|Domain Name)\s*:\s*([A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im, text);
    if (domMatch && domMatch[1]) {
      domain = domMatch[1].trim();
      var baseDn = C._base_dn_from_domain(domain);
      _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
      if (baseDn) _add(facts, mkFact('ad.base_dn', 'domain:' + domain, { base_dn: baseDn, domain: domain }, S, source));
      _add(facts, mkFact('host.domain', h, { domain: domain }, S, source));
    }
    var domScope = C._scope_for_domain(ws, domain);
    var fqdnMatch = reSearch(/^\s*FQDN\s*:\s*([A-Za-z0-9][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)\s*$/im, text);
    if (fqdnMatch && fqdnMatch[1]) {
      _add(facts, mkFact('host.fqdn', h, { fqdn: fqdnMatch[1].trim() }, S, source));
    }
    var nbMatch = reSearch(/^\s*NetBIOS computer name\s*:\s*([A-Za-z0-9_.-]+)\s*$/im, text);
    if (nbMatch && nbMatch[1]) {
      _add(facts, mkFact('host.hostname', h, { name: nbMatch[1].trim() }, S, source));
    }
    if (/\[\+\]\s*Appears to be (?:root\/parent|child) DC/i.test(text)) {
      _add(facts, mkFact('ad.dc_candidate', h, { name: (nbMatch && nbMatch[1]) ? nbMatch[1].trim() : ws.target }, S, source));
    }
    if (/\bWk\s+Sv\s+PDC\b|\bNT\s+Domain\s+Controller\b/i.test(text)) {
      _add(facts, mkFact('ad.dc_candidate', h, { host: ws.target, via: 'rpcclient-srvinfo' }, S, source));
      _add(facts, mkFact('smb.reachable', h, { port: 445, tool: 'rpcclient' }, S, source));
      var srvCmd = String((opts && opts.command) || source || '');
      if (/(?:^|\s)-U\s*(?:''|""|%)(?:\s|$)|\s-N\b/i.test(srvCmd)) {
        _add(facts, mkFact('smb.null_session', h, { tool: 'rpcclient' }, S, source));
      }
    }
    var rpcOsVerM = /platform_id\s*:\s*500[\s\S]{1,80}?os version\s*:\s*(\d+\.\d+)/i.exec(text);
    if (rpcOsVerM && C._add_os_observation) {
      C._add_os_observation(facts, ws, source, 'windows', 'Windows NT ' + rpcOsVerM[1] + ' (rpcclient srvinfo)', 'high', 'rpcclient', true);
    }
    if (/\[\+\]\s*LDAP is accessible on 389\/tcp/i.test(text)) {
      _add(facts, mkFact('ldap.reachable', h, { port: 389, tool: 'enum4linux-ng' }, S, source));
    }
    if (/\[\+\]\s*SMB is accessible on 445\/tcp/i.test(text)) {
      _add(facts, mkFact('smb.reachable', h, { port: 445, tool: 'enum4linux-ng' }, S, source));
    }
    if (/^\s*SMB 1\.0\s*:\s*true\b/im.test(text)) {
      _add(facts, mkFact('smb.smbv1', h, { enabled: true, tool: 'enum4linux-ng' }, S, source));
    }
    var signMatch = reSearch(/^\s*SMB signing required\s*:\s*(true|false)\b/im, text);
    if (signMatch && signMatch[1]) {
      _add(facts, mkFact('smb.signing', h, { required: signMatch[1].toLowerCase() === 'true' }, S, source));
    }
    if (/\[\+\]\s*Server allows authentication via username '' and password ''/i.test(text)) {
      _add(facts, mkFact('smb.null_session', h, { tool: 'enum4linux-ng' }, S, source));
    }
    var buildMatch = reSearch(/^\s*OS build\s*:\s*['"]?(\d+)['"]?\s*$/im, text);
    if (buildMatch && buildMatch[1]) {
      _add(facts, mkFact('host.kernel', h, { kernel: buildMatch[1], tool: 'enum4linux-ng' }, S, source));
    }
    var sidMatch = reSearch(C._DOMAIN_SID_RE, text);
    if (sidMatch && sidMatch.groups && sidMatch.groups.sid) {
      _add(facts, mkFact('ad.domain_sid', domScope, { sid: sidMatch.groups.sid, domain_sid: sidMatch.groups.sid }, S, source));
    }
    var asrepUsers = [];
    var yamlUserBlocks = reAll(/^\s+username:\s*['"]?([A-Za-z0-9._$-]{2,})['"]?[ \t]*$(?:\r?\n^\s+(?:name|acb|description):.*$){1,4}/gim, text);
    yamlUserBlocks.forEach(function (bm) {
      var block = bm[0], uName = C._clean_username(bm[1]);
      if (!C._valid_username(uName, false)) return;
      var acbM = /^\s+acb:\s*['"]?(0x[0-9a-fA-F]+)['"]?\s*$/im.exec(block);
      if (acbM && acbM[1]) {
        var acbVal = parseInt(acbM[1], 16);
        // 0x00010000 = ACB_DONT_REQUIRE_PREAUTH; 0x00000001 = ACB_DISABLED
        if (!isNaN(acbVal) && (acbVal & 0x00010000) !== 0 && (acbVal & 0x00000001) === 0) {
          if (asrepUsers.indexOf(uName) < 0) asrepUsers.push(uName);
          _add(facts, mkFact('credential.candidate', domScope, {
            kind: 'asrep_roastable', user: uName, domain: domain || '',
            acb: acbM[1], note: 'ACB_DONT_REQUIRE_PREAUTH (0x00010000) set on account via RPC'
          }, S, source));
        }
      }
      var descM = /^\s+description:\s*(.+?)\s*$/im.exec(block);
      if (descM && descM[1] && !/^\(?null\)?$/i.test(descM[1].trim())) {
        var dVal = descM[1].trim().replace(/^['"]|['"]$/g, '');
        if (dVal && !/^(?:Built-in account|Key Distribution Center|A user account managed by the system)/i.test(dVal)) {
          _parse_ldap_descriptions('sAMAccountName: ' + uName + '\ndescription: ' + dVal, ws, source, facts, { domain_hint: domain });
        }
      }
    });
    var res = _rpc_resolution(text);
    var groupsMap = {};
    reAll(/^\s+groupname:\s*['"]?([^'"\r\n]+?)['"]?\s*$|\bgroup:\[(?<grp>[^\]]+)\]\s+rid:\[/gim, text).forEach(function (gm) {
      var gName = String((gm.groups && gm.groups.grp) || gm[1] || '').trim();
      if (gName && gName !== '(null)' && !/^\$[A-Z0-9]{6}-[A-Z0-9]{12}$/i.test(gName)) groupsMap[gName] = true;
    });
    res.groups.forEach(function (g) { groupsMap[g] = true; });
    var groups = C.uniqueSortedCI(Object.keys(groupsMap));
    if (groups.length) {
      _add(facts, mkFact('ad.group_list', domScope, { groups: groups, count: groups.length, method: 'smb-rid' }, S, source));
    }
    var minLenM = reSearch(/^\s*Minimum password length\s*:\s*(\d+|none)\b/im, text);
    var lockThreshM = reSearch(/^\s*Lockout threshold\s*:\s*([^\r\n]+?)\s*$/im, text);
    if (minLenM || lockThreshM) {
      var cplxM = reSearch(/DOMAIN_PASSWORD_COMPLEX\s*:\s*(true|false)/i, text);
      var lockDurM = reSearch(/^\s*Lockout duration\s*:\s*([^\r\n]+?)\s*$/im, text);
      var histM = reSearch(/^\s*Password history length\s*:\s*(\d+|none)\b/im, text);
      _add(facts, mkFact('config.review', domScope, {
        kind: 'password_policy',
        min_length: minLenM ? (isNaN(parseInt(minLenM[1], 10)) ? minLenM[1] : parseInt(minLenM[1], 10)) : null,
        lockout_threshold: lockThreshM ? lockThreshM[1].trim() : null,
        lockout_duration: lockDurM ? lockDurM[1].trim() : null,
        history_length: histM ? (isNaN(parseInt(histM[1], 10)) ? histM[1] : parseInt(histM[1], 10)) : null,
        complexity: cplxM ? (cplxM[1].toLowerCase() === 'true') : null
      }, S, source));
    }
    var pwResetM = /Password changed for user\s+([A-Za-z0-9_.-]+)[\s\S]{1,120}?password reset to\s+(\S+?)\.?\s*$/im.exec(text);
    if (pwResetM && C._valid_username(pwResetM[1], false) && C._valid_password(pwResetM[2]) && C._add_plaintext_credential) {
      C._add_plaintext_credential(facts, ws, source, pwResetM[1], pwResetM[2], C._domain_from_facts(ws), 'rpcclient', '');
    }
    var users = C.uniqueSortedCI(C._rid_usernames(text).concat(res.users));
    if (!users.length && /\bquerygroupmem\b/i.test((opts && opts.command) || source || '') && /rid:\[0x1f4\]/i.test(text)) {
      users = ['Administrator'];
    }
    if (!users.length && /\b(?:nxc|netexec|crackmapexec|cme)\b[\s\S]*?(?:--rid-brute|--users)\b[\s\S]*?\|/i.test((opts && opts.command) || source || '')) {
      var pipeLines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
      if (pipeLines.length >= 2 && pipeLines.every(function (l) { return !/\s/.test(l) && C._valid_username(l, true); })) {
        users = C.uniqueSortedCI(pipeLines);
      }
    }
    if (!users.length) {
      var ridCmd = String((opts && opts.command) || source || '') + '\n' + String(text || '');
      var isAnonSamr = /(?:^|\s)-(?:u|U)\s*(?:''|""|%)(?:\s|$)/i.test(ridCmd) || /Server allows authentication via username ''/i.test(text);
      if (isAnonSamr && /NT_STATUS_ACCESS_DENIED|STATUS_ACCESS_DENIED|\bCould not get users via\b/i.test(text)) {
        _add(facts, mkFact('blocker.samr_null_denied', h, { tool: 'samr-anon', stage: 'authorization' }, S, source));
      }
      return;
    }
    var ulVal = { users: users, count: users.length, method: 'smb-rid' };
    if (asrepUsers.length) ulVal.asrep_users = asrepUsers;
    _add(facts, mkFact('ad.user_list', domScope, ulVal, S, source));
  }
  C._parse_rid_user_list = _parse_rid_user_list;

  function _parse_ldapsearch(text, ws, source, facts) {
    if (!facts.some(function (f) { return f.kind === 'host.os_family'; })) C._add_os_from_text(text, ws, source, facts, 'smb', 'medium', true);
    var dns = C.uniqueSortedCI(reAll(C._BASE_DN_RE, text).map(function (m) { return m[1]; }));
    if (!dns.length) {
      var dnMatches = reAll(/^\s*(?:distinguishedName|dn)\s*:\s*.*?\b(DC=[A-Za-z0-9_-]+(?:\s*,\s*DC=[A-Za-z0-9_-]+)+)\s*$/im, text);
      dns = C.uniqueSortedCI(dnMatches.map(function (m) { return m[1].replace(/\s+/g, ''); }));
    }
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
    if (!facts.some(function (f) { return f.kind === 'host.os_family'; })) C._add_os_from_text(text, ws, source, facts, 'smb', 'medium', true);
    var shares = [], byName = {};
    function addShare(name, permission, shareType, readable) {
      name = name.trim();
      if (!name || C._SHARE_HEADER_WORDS.has(name.toLowerCase()) || name[0] === '[') return;
      if (!/^[A-Za-z0-9_$.-]{2,}$/.test(name)) return;
      var uName = name.toUpperCase();
      var existing = byName[uName];
      if (existing) {
        if (permission && (!existing.permission || existing.permission === 'NO ACCESS')) existing.permission = permission;
        if (shareType && !existing.type) existing.type = shareType;
        if (readable !== undefined && readable !== null && (existing.readable === undefined || readable === true)) existing.readable = readable;
        return;
      }
      var row = { name: name };
      if (permission) row.permission = permission;
      if (shareType) row.type = shareType;
      if (readable !== undefined && readable !== null) row.readable = readable;
      byName[uName] = row;
      shares.push(row);
    }
    var e4lTestingShare = '', e4lYamlShare = '';
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      var e4lTestM = /^\[\*\]\s*Testing share\s+([A-Za-z0-9_$.-]+)\s*$/i.exec(line);
      if (e4lTestM) { e4lTestingShare = e4lTestM[1]; return; }
      if (e4lTestingShare) {
        var mapM = /^\[\+\]\s*Mapping:\s*(OK|DENIED)(?:,\s*Listing:\s*(OK|DENIED|N\/A))?/i.exec(line);
        if (mapM) {
          var mapOk = mapM[1].toUpperCase() === 'OK';
          var listSt = (mapM[2] || '').toUpperCase();
          var isRead = mapOk && (listSt === 'OK' || (listSt === 'N/A' && /^IPC\$$/i.test(e4lTestingShare)));
          addShare(e4lTestingShare, isRead ? 'READ' : (mapOk ? 'READ' : 'NO ACCESS'), '', listSt === 'OK');
          e4lTestingShare = '';
          return;
        }
        if (/^\[-\]\s*Could not connect:/i.test(line)) {
          addShare(e4lTestingShare, 'NO ACCESS', '', false);
          e4lTestingShare = '';
          return;
        }
      }
      var yamlShM = /^ {2}([A-Za-z0-9_$.-]{2,}):\s*$/.exec(raw);
      if (yamlShM) { e4lYamlShare = yamlShM[1]; return; }
      if (e4lYamlShare && /^ {4}type:\s*(Disk|IPC|Printer)\b/i.test(raw)) {
        var ytM = /^ {4}type:\s*(Disk|IPC|Printer)\b/i.exec(raw);
        addShare(e4lYamlShare, '', ytM[1]);
        e4lYamlShare = '';
        return;
      }
      if (/^SMB\s+/i.test(line)) {
        var parts = line.split(/\s+/);
        if (parts.length < 6) return;
        var share = parts[4], perm = parts[5].toUpperCase();
        if (perm === 'NO' && parts.length > 6 && parts[6].toUpperCase() === 'ACCESS') perm = 'NO ACCESS';
        if (!C._SHARE_PERMISSION_WORDS.has(perm)) return;
        addShare(share, perm, '', perm.indexOf('READ') >= 0);
        return;
      }
      var sm = /^([A-Za-z0-9_$.-]{2,})\s+(READ\s*ONLY|WRITE\s*ONLY|READ\s*,\s*WRITE|WRITE\s*,\s*READ|NO\s+ACCESS)(?:\s+(.*))?$/i.exec(line);
      if (sm) {
        var sp = sm[2].toUpperCase().replace(/\s+/g, ' ');
        var normP = sp === 'READ ONLY' ? 'READ' : (sp === 'WRITE ONLY' ? 'WRITE' : (sp.indexOf(',') >= 0 ? sp.replace(/[ \t]*,[ \t]*/, ',') : sp));
        addShare(sm[1], normP, '', normP.indexOf('READ') >= 0);
        return;
      }
      var p2 = line.split(/\s+/);
      if (p2.length >= 2 && ['Disk', 'IPC', 'Printer'].indexOf(p2[1]) >= 0) addShare(p2[0], '', p2[1]);
    });
    if (!shares.length) {
      var rawShareLines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
        return l && !/^(?:#\s*shares|shares|impacket[^\r\n]*|Type help for list of commands)$/i.test(l);
      });
      var anchorCount = rawShareLines.filter(function (l) { return /^(?:ADMIN\$|C\$|IPC\$|SYSVOL|NETLOGON|PRINT\$)$/i.test(l); }).length;
      var isBareSharesCmd = /-L\b|^\s*#?\s*shares\s*$/im.test(String(source || '') + '\n' + text);
      if ((isBareSharesCmd && anchorCount >= 1) || (anchorCount >= 2 && rawShareLines.length >= 2 && rawShareLines.length <= 32 && rawShareLines.every(function (l) { return /^[A-Za-z0-9_$. -]{1,32}$/.test(l) && !/[:\\/]/.test(l); }))) {
        rawShareLines.forEach(function (s) {
          if (/^[A-Za-z0-9_$.-]{2,32}$/.test(s)) {
            var stype = /^IPC\$$/i.test(s) ? 'IPC' : (/^PRINT\$$/i.test(s) ? 'Printer' : 'Disk');
            addShare(s, '', stype);
          }
        });
      }
    }
    if (/Anonymous login successful/i.test(text)) {
      _add(facts, mkFact('smb.reachable', 'host:' + ws.target, { port: 445, tool: 'smbclient' }, S, source));
      _add(facts, mkFact('smb.null_session', 'host:' + ws.target, { tool: 'smbclient' }, S, source));
    } else if (/\[\+\]\s*(?:(?:User\s+)?SMB session establish|IP:\s*\d+\.\d+\.\d+\.\d+:445\b)/i.test(text)) {
      _add(facts, mkFact('smb.reachable', 'host:' + ws.target, { port: 445, tool: 'smbmap' }, S, source));
    }
    if (shares.length) {
      _add(facts, mkFact('smb.shares', 'host:' + ws.target, { shares: shares, count: shares.length }, S, source));

      var BOILERPLATE_SHARES = { 'IPC$': 1, 'PRINT$': 1 };
      var POLICY_SHARES = { 'SYSVOL': 1, 'NETLOGON': 1 };
      var ADMIN_SHARES = { 'ADMIN$': 1, 'C$': 1 };

      var readableShares = shares.filter(function (sh) {
        var n = (sh.name || '').toUpperCase();
        return sh.readable === true && !BOILERPLATE_SHARES[n];
      });

      var customReadable = readableShares.filter(function (sh) {
        var n = (sh.name || '').toUpperCase();
        return !POLICY_SHARES[n] && !ADMIN_SHARES[n];
      });

      var policyReadable = readableShares.filter(function (sh) {
        var n = (sh.name || '').toUpperCase();
        return !!POLICY_SHARES[n];
      });

      var adminReadable = readableShares.filter(function (sh) {
        var n = (sh.name || '').toUpperCase();
        return !!ADMIN_SHARES[n];
      });

      readableShares.forEach(function (sh) {
        var n = (sh.name || '').toUpperCase();
        var cat = POLICY_SHARES[n] ? 'policy' : (ADMIN_SHARES[n] ? 'admin' : 'custom');
        _add(facts, mkFact('smb.readable_share', 'host:' + ws.target, {
          name: sh.name,
          permission: sh.permission,
          category: cat,
          is_custom: cat === 'custom',
          is_policy: cat === 'policy'
        }, S, source));
      });

      if (readableShares.length) {
        _add(facts, mkFact('smb.content_accessible', 'host:' + ws.target, {
          shares: readableShares.map(function (s) { return s.name; }),
          count: readableShares.length,
          has_custom: customReadable.length > 0
        }, S, source));
      }

      if (customReadable.length) {
        _add(facts, mkFact('config.review', 'host:' + ws.target, {
          kind: 'readable_custom_shares',
          shares: customReadable.map(function (s) { return s.name; })
        }, S, source));
      }

      if (policyReadable.length) {
        _add(facts, mkFact('config.review', 'host:' + ws.target, {
          kind: 'readable_domain_shares',
          shares: policyReadable.map(function (s) { return s.name; })
        }, S, source));
      }

      if (adminReadable.length) {
        _add(facts, mkFact('access.admin_share', 'host:' + ws.target, {
          shares: adminReadable.map(function (s) { return s.name; })
        }, S, source));
      }

      var usersShare = shares.find(function (sh) {
        return (sh.name || '').toUpperCase() === 'USERS' && sh.readable === true;
      });
      if (usersShare) {
        _add(facts, mkFact('share.users_readable', 'host:' + ws.target, {
          name: 'Users',
          permission: usersShare.permission
        }, S, source));
      }

      var writableShares = shares.filter(function (sh) {
        var n = (sh.name || '').toUpperCase();
        var p = (sh.permission || '').toUpperCase();
        return !BOILERPLATE_SHARES[n] && (p.indexOf('WRITE') >= 0);
      });
      if (writableShares.length) {
        var wVal = {
          shares: writableShares.map(function (s) { return s.name; }),
          count: writableShares.length
        };
        _add(facts, mkFact('smb.writable_share', 'host:' + ws.target, wVal, S, source));
      }
    }
  }
  C._parse_smb_shares = _parse_smb_shares;

  function _parse_gpp_artifacts(text, ws, source, facts) {
    var files = C.uniqueSortedCI(reAll(C._GPP_FILE_RE, text).map(function (m) { return m[0]; }));
    if (files.length) _add(facts, mkFact('config.review', 'host:' + ws.target, { kind: 'gpp_xml', files: files }, S, source));
    var cps = {};
    reAll(C._CPASSWORD_RE, text).forEach(function (m) { cps[m[1]] = true; });
    var cpasswords = Object.keys(cps).sort();

    var users = [], domain = C._domain_from_facts(ws);
    var uRe = /(?:userName|name)\s*=\s*["'](?:(?<dom>[^"'\\]+)\\)?(?<u>[^"'\s<>]+)["']/gi;
    var um;
    while ((um = uRe.exec(text)) !== null) {
      if (um.groups && um.groups.u) {
        var cleanU = C._clean_username(um.groups.u);
        if (cleanU && C._valid_username(cleanU, false) && users.indexOf(cleanU) < 0) users.push(cleanU);
        if (um.groups.dom) domain = domain || um.groups.dom.toLowerCase();
      }
    }
    if (users.length) {
      _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: users, count: users.length, method: 'gpp' }, S, source));
      if (domain) {
        _add(facts, mkFact('ad.domain_known', 'domain:' + domain, { name: domain }, S, source));
        _add(facts, mkFact('host.domain', 'host:' + ws.target, { domain: domain }, S, source));
      }
    }

    if (cpasswords.length) {
      var candVal = { kind: 'gpp_cpassword', count: cpasswords.length, values: cpasswords };
      if (users.length) candVal.user = users[0];
      if (domain) candVal.domain = domain;
      _add(facts, mkFact('credential.candidate', 'host:' + ws.target, candVal, S, source));
    }
  }
  C._parse_gpp_artifacts = _parse_gpp_artifacts;

  function _parse_gpp_decrypted(text, ws, source, facts) {
    if (!text) return;
    text = text.replace(C._ANSI_RE, '');
    var allowBare = /gpp-decrypt/i.test(String(source || '')) || /gpp-decrypt/i.test(text);
    var lines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
      if (!l) return false;
      if (/^(?:gpp-decrypt|┌|└|\$|\#|\[|\>|SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI|HTTP\/)/i.test(l)) return false;
      if (/^(?:Usage:|Error:|Traceback|Exception|Impacket\s+v)/i.test(l)) return false;
      if (l.indexOf('└─$') >= 0 || l.indexOf('┌──') >= 0) return false;
      return true;
    });
    if (!lines.length) return;

    var plain = '';
    for (var li = 0; li < lines.length; li++) {
      var cand = lines[li].trim();
      var pwMatch = cand.match(/(?:to\s+password[:\s]+|password(?:\s+is)?[:\s]+)(.+)$/i);
      if (pwMatch) {
        cand = pwMatch[1].trim();
      } else if (!allowBare) {
        continue;
      }
      cand = cand.replace(/^["']+|["']+$/g, '').trim();
      if (C._valid_password(cand) && cand.length >= 3 && cand.length < 128) {
        plain = cand;
        break;
      }
    }
    if (!plain) return;

    var domain = C._domain_from_facts(ws) || '';
    var user = '';
    var allF = (ws && (ws.facts || ws.seedFacts)) || facts || [];
    var associated = [];
    for (var i = 0; i < allF.length; i++) {
      var f = allF[i];
      if (f.kind === 'credential.candidate' && f.state === S && (f.value || {}).kind === 'gpp_cpassword' && (f.value || {}).user && (f.value.count || 1) === 1) {
        associated.push(f.value);
      }
    }
    if (associated.length === 1) {
      user = associated[0].user;
      domain = associated[0].domain || domain;
    }
    var val = { kind: 'gpp_plaintext', password: plain, secret: plain, secretType: 'password', method: 'gpp-decrypt' };
    if (user) { val.user = user; val.association = 'single-gpp-source'; }
    else val.association = 'unresolved';
    if (domain) val.domain = domain;
    var scope = C._scope_for_domain(ws, domain);
    if (user) _add(facts, mkFact('credential.available', scope, val, S, source));
    _add(facts, mkFact('credential.candidate', scope, val, S, source));
    _add(facts, mkFact('credential.plaintext', scope, val, S, source));
  }
  C._parse_gpp_decrypted = _parse_gpp_decrypted;

  function _unwrap_rubeus_roast(text) {
    var s = C._unwrap_kerberos_hashes ? C._unwrap_kerberos_hashes(text) : String(text || '');
    return s.replace(/(\$(?:krb5tgs|krb5asrep)\$[^\r\n]+)(?:\r?\n[ \t]*([0-9a-fA-F*$]+))+/g, function (m) {
      return m.replace(/\r?\n[ \t]*/g, '');
    });
  }

  function _parse_impacket_roast_table(text, ws, source, facts) {
    if (!/^(?:ServicePrincipalName\s+Name|Name\s+MemberOf\s+PasswordLastSet)/im.test(text)) return;
    var spnFirst = /^ServicePrincipalName\s+Name/im.test(text);
    var inTable = false, users = [], seen = {}, domain = '';
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      if (/^-{4,}/.test(line)) { inTable = true; return; }
      if (!inTable) return;
      if (/^\[\*\]|\[\-\]|\[\+\]/.test(line)) return;
      if (!domain) {
        var dcs = reAll(/DC=([A-Za-z0-9-]+)/gi, line).map(function (m) { return m[1].toLowerCase(); });
        if (dcs.length >= 2) domain = dcs.join('.');
      }
      var toks = line.split(/\s+/);
      var cand = spnFirst ? (toks[1] || '') : (toks[0] || '');
      cand = C._clean_username(cand.trim());
      if (cand && C._valid_username(cand, false) && !seen[cand.toLowerCase()]) {
        seen[cand.toLowerCase()] = 1;
        users.push(cand);
      }
    });
    if (users.length) {
      _add(facts, mkFact('ad.user_list', C._scope_for_domain(ws, domain), { users: users, count: users.length, method: spnFirst ? 'getuserspns' : 'getnpusers' }, S, source));
    }
  }
  C._parse_impacket_roast_table = _parse_impacket_roast_table;

  function _parse_asrep_hashes(text, ws, source, facts) {
    text = _unwrap_rubeus_roast(text);
    var rawMatches = reAll(C._ASREP_RE, text).map(function (m) { return m[1]; });
    var hashes = C.uniqueSortedCI(rawMatches.filter(function (h) {
      if (!/[:$][0-9a-fA-F]{6,}(?:\$[0-9a-fA-F]{6,})?$/.test(h)) return false;
      if (/\$[0-9a-fA-F]{16,}:[^\s:$]+$/.test(h)) return false;
      return true;
    }));
    if (!hashes.length) {
      if (!rawMatches.length) _parse_impacket_roast_table(text, ws, source, facts);
      return;
    }
    var users = [], domain = '';
    hashes.forEach(function (h) {
      var um = reSearch(C._ASREP_USER_RE, h);
      if (um && um.groups) {
        var u = C._clean_username(um.groups.user || '');
        if (u && users.indexOf(u) < 0) users.push(u);
        if (!domain && um.groups.domain) domain = um.groups.domain.toLowerCase();
      }
    });
    var scope = C._scope_for_domain(ws, domain);
    var hVal = { hashes: hashes, count: hashes.length };
    var cVal = { kind: 'asrep_hash', count: hashes.length };
    if (users.length) { hVal.user = users[0]; hVal.users = users; cVal.user = users[0]; cVal.users = users; }
    if (domain) { hVal.domain = domain; cVal.domain = domain; }
    _add(facts, mkFact('hash.asrep', scope, hVal, S, source));
    _add(facts, mkFact('credential.candidate', scope, cVal, S, source));
  }
  C._parse_asrep_hashes = _parse_asrep_hashes;

  function _parse_tgs_hashes(text, ws, source, facts) {
    text = _unwrap_rubeus_roast(text);
    var rawMatches = reAll(C._TGS_RE, text).map(function (m) { return m[1]; });
    var hashes = C.uniqueSortedCI(rawMatches.filter(function (h) {
      if (!/[:$][0-9a-fA-F]{6,}(?:\$[0-9a-fA-F]{6,})?$/.test(h)) return false;
      if (/\$[0-9a-fA-F]{16,}:[^\s:$]+$/.test(h)) return false;
      return true;
    }));
    if (!hashes.length) {
      if (!rawMatches.length) _parse_impacket_roast_table(text, ws, source, facts);
      return;
    }
    var users = [], domain = '';
    hashes.forEach(function (h) {
      var um = reSearch(C._TGS_USER_RE, h);
      if (um && um.groups) {
        var u = C._clean_username(um.groups.user || '');
        if (u && users.indexOf(u) < 0) users.push(u);
        if (!domain && um.groups.domain && um.groups.domain.indexOf('/') < 0) domain = um.groups.domain.toLowerCase();
      }
    });
    var scope = C._scope_for_domain(ws, domain);
    var hVal = { hashes: hashes, count: hashes.length };
    var cVal = { kind: 'tgs_hash', count: hashes.length };
    if (users.length) { hVal.user = users[0]; hVal.users = users; cVal.user = users[0]; cVal.users = users; }
    if (domain) { hVal.domain = domain; cVal.domain = domain; }
    _add(facts, mkFact('hash.tgs', scope, hVal, S, source));
    _add(facts, mkFact('credential.candidate', scope, cVal, S, source));
  }
  C._parse_tgs_hashes = _parse_tgs_hashes;

  function _parse_auth_material(auth) {
    auth = auth.replace(/(?:[ \t]+\([^)\r\n]*\))+[ \t]*$/, '').trim();
    var m = /^(?:(?<domain>[^\\\s:/]+)\\)?(?<user>[A-Za-z0-9._$@-]+):(?<secret>[^\r\n]*)$/.exec(auth);
    if (!m) return ['', '', ''];
    var user = m.groups.user, domain = (m.groups.domain || '').trim();
    if (user.indexOf('@') >= 0) { domain = domain || user.split('@')[1]; user = user.split('@')[0]; }
    return [domain, C._clean_username(user), m.groups.secret.trim()];
  }
  C._parse_auth_material = _parse_auth_material;

  function _add_authenticated_service(facts, ws, source, proto, user, secret, domain, admin) {
    user = C._clean_username(user);
    if (!C._valid_username(user, false)) return;
    var nthash = C._nt_hash(secret);
    var hasSecret = !!nthash || (C._valid_password(secret) && !/^(?:\*{3,}|<redacted>|\[redacted\])$/i.test(secret));
    var ctx = (ws && ws.context) || {};
    var domainName = domain || ctx.authRealm || '';
    var selectedCredential = ctx.credential && (ctx.credential.value || ctx.credential);
    var localAccount = !!(selectedCredential && selectedCredential.accountType === 'local' && (!domain || String(domain).toLowerCase() === String(ctx.authRealm || selectedCredential.realm || '').toLowerCase())) ||
      !!(domainName && (String(domainName).toLowerCase() === String(ws.target).toLowerCase() || String(domainName).toLowerCase() === String(ws.hostname || '').toLowerCase()));
    var value = { user: user, service: proto, method: nthash ? 'pth' : 'nxc' };
    if (nthash) value.nthash = nthash; else if (hasSecret) value.password = secret;
    if (domainName) value.realm = domainName;
    if (domainName && !localAccount) value.domain = domainName;
    if (localAccount) { value.accountType = 'local'; value.targetBinding = ws.target; }
    value = _auth_observation(ws, value);
    if (hasSecret) _add(facts, mkFact('credential.available', domainName && !localAccount ? ('domain:' + domainName) : ('host:' + ws.target), value, S, source));
    if (['smb', 'ldap', 'winrm', 'rdp', 'ftp', 'ssh'].indexOf(proto) >= 0) {
      _add(facts, mkFact(proto + '.authenticated', 'host:' + ws.target, value, S, source));
    }
    var observed = Object.assign({}, value, { outcome: 'accepted' });
    delete observed.password; delete observed.nthash;
    _add(facts, mkFact('credential.validated', 'host:' + ws.target, observed, S, source));
    if (proto === 'winrm') {
      _add(facts, mkFact('winrm.reachable', 'host:' + ws.target, { tool: 'nxc' }, S, source));
    } else if (proto === 'ssh') {
      _add(facts, mkFact('ssh.reachable', 'host:' + ws.target, { tool: 'nxc' }, S, source));
    } else if (proto === 'mssql') {
      _add(facts, mkFact('db.session', 'host:' + ws.target, { engine: 'mssql', user: user, tool: 'nxc' }, S, source));
    }
    if (admin && proto === 'mssql') _add(facts, mkFact('db.admin', 'host:' + ws.target, Object.assign({}, observed, { engine: 'mssql', role: 'sysadmin', authorizationProof: 'nxc-pwn3d' }), S, source));
    else if (admin) _add(facts, mkFact('access.admin', 'host:' + ws.target, Object.assign({}, observed, { authorizationProof: 'nxc-pwn3d' }), S, source));
  }
  C._add_authenticated_service = _add_authenticated_service;

  function _parse_nxc_auth_validation(text, ws, source, facts) {
    var hostSet = {};
    reAll(C._NXC_PROTO_REACHABLE_RE, text).forEach(function (m) {
      if (m.groups && m.groups.host && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(m.groups.host)) hostSet[m.groups.host] = 1;
    });
    var multiHost = Object.keys(hostSet).length > 1;
    reAll(C._NXC_AUTH_RE, text).forEach(function (m) {
      var proto = m.groups.proto.toLowerCase();
      if (proto === 'smb' && /^\s*SMB\s+\S+\s+(?:5985|5986)\b/i.test(m[0])) proto = 'winrm';
      var auth = m.groups.auth.trim();
      if (/\((?:Guest|Null Auth:True)\)/i.test(auth)) return;
      var parsed = _parse_auth_material(auth);
      var domain = parsed[0], user = parsed[1], secret = parsed[2];
      if (!user) return;
      if (/^(?:guest|anonymous)$/i.test(user)) return;
      var lineHost = observedHost(ws, m.groups && m.groups.host);
      var hostname = /^\s*\S+\s+\S+\s+\d+\s+(\S+)/.exec(m[0]);
      var lineWs = Object.assign({}, ws, { target: lineHost, observedTarget: m.groups && m.groups.host, hostname: hostname ? hostname[1] : '' });
      var linePwned = /\(pwn3d!\)/i.test(auth);
      var admin = linePwned && (proto === 'smb' || proto === 'wmi' || proto === 'mssql');
      _add_authenticated_service(facts, lineWs, source, proto, user, secret, domain, admin);
    });
  }
  C._parse_nxc_auth_validation = _parse_nxc_auth_validation;

  function _parse_auth_failures(text, ws, source, facts) {
    if (/\\\$krb5(?:asrep|tgs)\$|Testing credentials \(\$krb5/i.test(text)) return;
    var isAnonOnly = /\[\+\]\s*[^\\\r\n]*\\:\s*$/im.test(text) && !/\[\+\]\s*[^\\\r\n]*\\[A-Za-z0-9._$-]+:/im.test(text);
    var cleaned = String(text || '').replace(/^[^\r\n]*\bguest:\s*STATUS_ACCOUNT_DISABLED[^\r\n]*$/gim, '');
    if (isAnonOnly) {
      cleaned = cleaned.replace(/^[^\r\n]*(?:Error enumerating shares|LSAD SessionError):[^\r\n]*STATUS_ACCESS_DENIED[^\r\n]*$/gim, '');
    }
    cleaned.split(/\r?\n/).forEach(function (line) {
      var row = /^\s*(SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+(\S+)\s+(\d+)\s+\S+\s+(?:\[[-*]\]\s*)?(.*)$/i.exec(line);
      var lineWs = row ? Object.assign({}, ws, { target: observedHost(ws, row[2]), observedTarget: row[2] }) : ws;
      var ctx = (ws && ws.context) || {};
      var service = row ? row[1].toLowerCase() : String(ctx.service || '');
      var auth = row ? row[4] : line;
      var parsed = _parse_auth_material(auth.replace(/[ \t]+STATUS_[A-Z_]+[^\r\n]*$/i, ''));
      var value = { reason: '', service: service };
      if (parsed[1]) value.user = parsed[1];
      if (parsed[0]) value.domain = parsed[0];
      if (parsed[2] && !/^(?:\*{3,}|<redacted>|\[redacted\])$/i.test(parsed[2])) value.password = parsed[2];
      if (row) value.port = +row[3];
      Object.keys(C._FAILURE_REASONS).forEach(function (marker) {
        if (line.toLowerCase().indexOf(marker) < 0) return;
        value.reason = C._FAILURE_REASONS[marker];
        var authorization = marker === 'status_access_denied';
        value.outcome = authorization ? 'denied' : 'rejected';
        value.stage = authorization ? 'authorization' : 'authentication';
        var observed = _auth_observation(lineWs, value);
        delete observed.password;
        _add(facts, mkFact(authorization ? 'credential.authorization' : 'credential.validation', 'host:' + lineWs.target, observed, authorization ? S : REF, source));
      });
    });
  }
  C._parse_auth_failures = _parse_auth_failures;

  // Auth blockers record the barrier for the attempted context, without asserting validity.
  // A forced password change (STATUS_PASSWORD_MUST_CHANGE) and
  // Kerberos clock skew (KRB_AP_ERR_SKEW) each mint a blocker.* fact so the matching fix move surfaces.
  function _parse_auth_blockers(text, ws, source, facts) {
    var t = String(text || '').replace(/^[^\r\n]*\bguest:\s*STATUS_ACCOUNT_DISABLED[^\r\n]*$/gim, '');
    function add(kind, re, tool, stage) {
      t.split(/\r?\n/).forEach(function (line) {
        if (!re.test(line)) return;
        var row = /^\s*(SMB|LDAP|WINRM|RDP|SSH|FTP|MSSQL|WMI)\s+(\S+)\s+\d+\s+\S+\s+(?:\[[-*]\]\s*)?(.*)$/i.exec(line);
        var lineWs = row ? Object.assign({}, ws, { target: observedHost(ws, row[2]), observedTarget: row[2] }) : ws;
        var parsed = _parse_auth_material(row ? row[3].replace(/[ \t]+STATUS_[A-Z_]+[^\r\n]*$/i, '') : '');
        var value = { tool: tool || 'auth', stage: stage || 'authentication', service: row ? row[1].toLowerCase() : (((ws || {}).context || {}).service || '') };
        if (parsed[1]) value.user = parsed[1];
        if (parsed[0]) value.domain = parsed[0];
        if (parsed[2] && !/^(?:\*{3,}|<redacted>|\[redacted\])$/i.test(parsed[2])) value.password = parsed[2];
        value = _auth_observation(lineWs, value);
        delete value.password;
        _add(facts, mkFact(kind, 'host:' + lineWs.target, value, S, source));
      });
    }
    if (/STATUS_PASSWORD_MUST_CHANGE|STATUS_PASSWORD_EXPIRED|KDC_ERR_KEY_EXPIRED|0xc0000224|0xc0000071|\bdata\s+(?:532|773)\b|password must (?:be )?change|must change (?:your )?password|password has expired/i.test(t))
      add('blocker.password_change', /STATUS_PASSWORD_MUST_CHANGE|STATUS_PASSWORD_EXPIRED|KDC_ERR_KEY_EXPIRED|0xc0000224|0xc0000071|\bdata\s+(?:532|773)\b|password must (?:be )?change|must change (?:your )?password|password has expired/i);
    if (/KRB_AP_ERR_SKEW|clock skew too great|kerberos[^\n]*\bskew\b|time difference too large/i.test(t))
      add('blocker.clock_skew', /KRB_AP_ERR_SKEW|clock skew too great|kerberos[^\n]*\bskew\b|time difference too large/i, 'auth', 'environment');
    // An NTLM refusal does not establish whether the credential is valid.
    if (/NT_STATUS_NOT_SUPPORTED|STATUS_NTLMPASSWORD_DISABLED|0xc00000bb|StrongerAuthRequired|NTLM[^\r\n]*disabled/i.test(t) || (/STATUS_NOT_SUPPORTED/i.test(t) && /\b(smb|ldap|nxc|SMBv|NTLM)\b/i.test(t)))
      add('blocker.ntlm_disabled', /(?:NT_)?STATUS_NOT_SUPPORTED|STATUS_NTLMPASSWORD_DISABLED|0xc00000bb|StrongerAuthRequired|NTLM[^\r\n]*disabled/i, 'auth', 'environment');
    if (/STATUS_ACCOUNT_LOCKED_OUT|KDC_ERR_CLIENT_REVOKED|0xc0000234|\bdata\s+775\b|account (?:is |has been )?locked out|lockoutThreshold reached/i.test(t))
      add('blocker.lockout', /STATUS_ACCOUNT_LOCKED_OUT|KDC_ERR_CLIENT_REVOKED|0xc0000234|\bdata\s+775\b|account (?:is |has been )?locked out|lockoutThreshold reached/i);
    if (/STATUS_ACCOUNT_DISABLED|STATUS_ACCOUNT_RESTRICTION|STATUS_LOGON_TYPE_NOT_GRANTED|STATUS_ACCOUNT_EXPIRED|STATUS_INVALID_LOGON_HOURS|STATUS_INVALID_WORKSTATION|0xc000006e|0xc000006f|0xc0000070|0xc0000072|0xc000015b|0xc0000193|\bdata\s+(?:530|531|533|701)\b/i.test(t))
      add('blocker.account_restricted', /STATUS_ACCOUNT_DISABLED|STATUS_ACCOUNT_RESTRICTION|STATUS_LOGON_TYPE_NOT_GRANTED|STATUS_ACCOUNT_EXPIRED|STATUS_INVALID_LOGON_HOURS|STATUS_INVALID_WORKSTATION|0xc000006e|0xc000006f|0xc0000070|0xc0000072|0xc000015b|0xc0000193|\bdata\s+(?:530|531|533|701)\b/i);
    // An LDAP WRITE denied (bloodyAD/dacledit `insufficientAccessRights` when granting DCSync, setting an
    // owner, or adding a group member) right after you GRANTED yourself that right is the classic AD wall:
    // the right exists but your CURRENT session's token predates it, so re-authenticate and retry. Keyed on
    // the LDAP-modify signature (insufficientAccessRights), not a bare ACCESS_DENIED, so it never fires on
    // the NTDS replication denial (rpc_s_access_denied), which has its own grant-first field note.
    if (/insufficientAccessRights|insufficient[ _]access[ _]rights|INSUFFICIENT_ACCESS_RIGHTS|INSUFF_ACCESS_RIGHTS|dsid-03152|ERROR_DS_DRA_ACCESS_DENIED/i.test(t))
      add('blocker.acl_reauth', /insufficientAccessRights|insufficient[ _]access[ _]rights|INSUFFICIENT_ACCESS_RIGHTS|INSUFF_ACCESS_RIGHTS|dsid-03152|ERROR_DS_DRA_ACCESS_DENIED/i, 'ldap', 'authorization');
  }
  C._parse_auth_blockers = _parse_auth_blockers;

  function _parse_evil_winrm(text, ws, command, source, facts) {
    var rawText = text || '';
    var low = rawText.toLowerCase();
    var isEvilWinrmCmd = /\bevil-winrm\b/i.test(command || '');
    var hasInlinePrompt = !!reSearch(C._EW_PROMPT_RE, rawText);
    var followPrompt = (ws && ws.context && ws.context.followPrompt) || '';
    var hasFollowPrompt = isEvilWinrmCmd && !!reSearch(C._EW_PROMPT_RE, followPrompt);
    var promptCtx = hasInlinePrompt ? rawText : (hasFollowPrompt ? (rawText + '\n' + followPrompt) : rawText);
    if (low.indexOf('winrmauthorizationerror') >= 0) {
      _add(facts, mkFact('blocker.logon_failure', 'host:' + ws.target, { tool: 'evil-winrm', service: 'winrm' }, S, source));
      return;
    }
    var hasTransportOrError = low.indexOf('winrmhttptransporterror') >= 0
      || /\b401\b/.test(rawText)
      || low.indexOf('unauthorized') >= 0
      || /^\s*Error:\s+/im.test(rawText)
      || /\bWinRM::[A-Za-z]+Error\b/i.test(rawText)
      || /\bExiting with code\s+[1-9]\d*\b/i.test(rawText);
    if (hasTransportOrError) return;
    if (!isEvilWinrmCmd && !hasInlinePrompt) return;
    var hasPrompt = hasInlinePrompt || hasFollowPrompt;
    var hasCleanBanner = isEvilWinrmCmd && /Evil-WinRM\s+shell\s+v\d/i.test(rawText) && /Info:\s*Establishing connection to remote endpoint/i.test(rawText);
    if (!hasPrompt && !hasCleanBanner) return;
    var h = 'host:' + ws.target;
    var user = C._command_arg(command, ['-u', '--user', '--username']);
    if (!user) {
      var pm = /(?:\*Evil-WinRM\*\s+PS\s+|^\s*PS\s+)[A-Za-z]:\\Users\\([A-Za-z0-9._-]+)(?:\\|>|\s*$)/im.exec(promptCtx);
      if (pm && pm[1] && !/^(Public|Default|All Users)$/i.test(pm[1])) user = pm[1];
    }
    var password = C._command_arg(command, ['-p', '--password']);
    var nthash = C._nt_hash(C._command_arg(command, ['-H', '--hash']));
    var domain = C._command_arg(command, ['-r', '--realm', '-d', '--domain']);
    var isAdminPrompt = /(?:\*Evil-WinRM\*\s+PS\s+|^\s*(?:PS\s+)?)[A-Za-z]:\\Users\\Administrator(?:\\|>|\s*$)/im.test(promptCtx);
    var value = { service: 'winrm', tool: 'evil-winrm', proof: hasPrompt ? 'interactive-prompt' : 'connection-banner' };
    if (user) value.user = C._clean_username(user);
    else if (isAdminPrompt) value.user = 'Administrator';
    var isAdmin = isAdminPrompt || /^administrator$/i.test(String(value.user || ''));
    if (isAdmin) value.admin = true;
    if (nthash) value.nthash = nthash; else if (password) value.password = password;
    if (domain) value.domain = domain;
    value = _auth_observation(ws, value);
    _add(facts, mkFact('winrm.authenticated', h, value, S, source));
    _add(facts, mkFact('foothold.windows', h, value, S, source));
    _add(facts, mkFact('access.shell', h, { service: 'winrm', tool: 'evil-winrm', user: value.user || '' }, S, source));
    _add(facts, mkFact('access.desktop', h, { session: 'evil-winrm', user: value.user || '', admin: isAdmin }, S, source));
    // An evil-winrm shell proves the credential works here, so it is validated.
    var observed = Object.assign({}, value, { outcome: 'accepted' });
    delete observed.password; delete observed.nthash;
    if (value.user) {
      _add(facts, mkFact('credential.validated', h, observed, S, source));
    }
    if (isAdmin) {
      _add(facts, mkFact('access.admin', h, Object.assign({}, observed, { authorizationProof: 'evil-winrm-admin' }), S, source));
    }
    C._add_os_observation(facts, ws, source, 'windows', 'evil-winrm authenticated shell', 'high', 'evil-winrm', true);
    if (hasInlinePrompt && user && (nthash || (password && C._valid_password(password)))) {
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
    var infoDone = /INFO:\s*Done in \d+M \d+S/i.test(text) || (/INFO:\s*Found AD domain:/i.test(text) && /INFO:\s*Found \d+ (?:users|computers|domains|trusts)/i.test(text) && !/Traceback \(most recent call last\)/i.test(text));
    var collected = ((zips.length || jsons.length) && ['bloodhound', 'sharphound', 'compressing', 'collection', 'saved'].some(function (mk) { return lowered.indexOf(mk) >= 0; })) || infoDone;
    if (!collected) return;
    var domM = /INFO:\s*Found AD domain:\s*([A-Za-z0-9._-]+)/i.exec(text);
    var dom = domM ? domM[1].toLowerCase().replace(/\.$/, '') : '';
    if (dom) _add(facts, mkFact('ad.domain_known', 'domain:' + dom, { name: dom, tool: 'bloodhound' }, S, source));
    var value = { tool: 'bloodhound' };
    if (zips.length) value.archives = zips;
    if (jsons.length) value.files = jsons;
    _add(facts, mkFact('ad.graph.collected', C._scope_for_domain(ws, dom), value, S, source));
  }
  C._parse_bloodhound_collection = _parse_bloodhound_collection;

  var _AD_PATH_ARROW_RE = /-+\[?\s*([A-Za-z]+)\s*\]?-+>/;
  var _ABUSABLE_EDGES = new Set(['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'AddMember', 'AddSelf', 'ForceChangePassword', 'AllExtendedRights', 'AddKeyCredentialLink', 'WriteSPN', 'AddAllowedToAct', 'AllowedToAct', 'CanPSRemote', 'WriteAccountRestrictions', 'Contains', 'SyncLAPSPassword', 'ReadLAPSPassword', 'ReadGMSAPassword', 'GetChanges', 'GetChangesAll']);
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
    var scope = C._scope_for_domain(ws);
    var value = { tool: 'bloodhound', evidence: 'analysis_output' };
    if (hops.length) {
      value.path = hops;
      value.goal = hops[hops.length - 1].to;
      if (first) value.first_action = first;
    }
    _add(facts, mkFact('ad.attack_paths', scope, value, S, source));
    var nonMemberHops = hops.filter(function (h) { return h && !/^memberof$/i.test(String(h.edge || '')); });
    if (first && (first.edge === 'GetChanges' || first.edge === 'GetChangesAll') && nonMemberHops.length <= 1) {
      _add(facts, mkFact('ad.control_paths', scope, value, S, source));
      _add(facts, mkFact('ad.domain_control', scope, { tool: 'bloodhound', right: 'DCSync', principal: hops[0] ? hops[0].from : '' }, S, source));
    }
    if (first || hops.length) {
      var tgt = first ? first.target : (hops[0] ? hops[0].to.split('@')[0].trim() : '');
      var fedge = first ? first.edge : (hops[0] ? hops[0].edge : '');
      _add(facts, mkFact('ad.acl_lead', scope, { tool: 'bloodhound', target: tgt, targets: tgt ? [tgt] : [], edge: fedge, first_action: first }, S, source));
      var memberGroups = [], seenMg = {};
      hops.forEach(function (hp) {
        if (!hp || !/^memberof$/i.test(String(hp.edge || ''))) return;
        var gName = String(hp.to || '').split('@')[0].trim();
        var pName = String(hp.from || '').split('@')[0].trim();
        if (!gName) return;
        var gk = gName.toLowerCase();
        if (!seenMg[gk]) { seenMg[gk] = true; memberGroups.push(gName); }
        if (/^(?:Backup Operators|Account Operators|Server Operators|Print Operators|DnsAdmins|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Remote Management Users|Exchange Windows Permissions)$/i.test(gName)) {
          _add(facts, mkFact('ad.acl_lead', scope, { tool: 'bloodhound', principal: pName, group: gName, target: gName, targets: [gName], edge: 'MemberOf' }, S, source));
          if (/^(?:Backup Operators|Account Operators|Server Operators|Print Operators|DnsAdmins)$/i.test(gName)) {
            _add(facts, mkFact('privesc.privileged_group', 'host:' + ws.target, { principal: pName, user: pName, group: gName, via: 'bloodhound-memberof' }, S, source));
          }
        }
      });
      if (memberGroups.length) {
        _add(facts, mkFact('ad.group_list', scope, { groups: memberGroups, count: memberGroups.length, method: 'bloodhound-edge' }, S, source));
      }
      if ((first && first.edge === 'ReadGMSAPassword') || hops.some(function (h) { return h.edge === 'ReadGMSAPassword'; })) {
        _add(facts, mkFact('ad.gmsa', scope, { tool: 'bloodhound', edge: 'ReadGMSAPassword', target: tgt }, S, source));
      }
      if ((first && (first.edge === 'ReadLAPSPassword' || first.edge === 'SyncLAPSPassword')) || hops.some(function (h) { return h.edge === 'ReadLAPSPassword' || h.edge === 'SyncLAPSPassword'; })) {
        _add(facts, mkFact('ad.laps', scope, { tool: 'bloodhound', edge: first ? first.edge : 'ReadLAPSPassword', target: tgt }, S, source));
      }
      if ((first && (first.edge === 'AllowedToAct' || first.edge === 'AddAllowedToAct')) || hops.some(function (h) { return h.edge === 'AllowedToAct' || h.edge === 'AddAllowedToAct'; })) {
        _add(facts, mkFact('ad.rbcd', scope, { tool: 'bloodhound', edge: first ? first.edge : 'AllowedToAct', target: tgt }, S, source));
        _add(facts, mkFact('ad.delegation', scope, { tool: 'bloodhound', edge: first ? first.edge : 'AllowedToAct', target: tgt }, S, source));
      }
    }
  }
  C._parse_bloodhound_analysis = _parse_bloodhound_analysis;

  function _is_ad_abuse_command(command) {
    var l = (command || '').toLowerCase();
    if (l.indexOf('net localgroup') >= 0 && l.indexOf('/domain') >= 0) return true;
    if (/\bnet(?:\.exe)?\s+user\s+\S+\s+(?!\/)\S+\s+\/domain\b/i.test(command || '') && !/\/add\b/i.test(command || '')) return true;
    return ['bloodyad', 'dacledit', 'owneredit', 'ticketer', 'addcomputer', 'impacket-rbcd', 'rbcd.py', 'impacket-getst', 'getst.py', 'impacket-gettgt', 'gettgt.py', 'gmsadumper', 'msds-managedpassword', ' ms-mcs-admpwd', ' laps', ' -m laps', 'get-adcomputer', 'get-adserviceaccount', 'get-gppermission', 'rubeus', 'klist', 'kinit', 'net group', 'net rpc'].some(function (t) { return l.indexOf(t) >= 0; });
  }
  C._is_ad_abuse_command = _is_ad_abuse_command;

  function _canonical_right(right) {
    var map = { writedacl: 'WriteDACL', genericall: 'GenericAll', genericwrite: 'GenericWrite', writeowner: 'WriteOwner', fullcontrol: 'FullControl', allextendedrights: 'AllExtendedRights', forcechangepassword: 'ForceChangePassword', addmember: 'WriteMembers', writemembers: 'WriteMembers', dcsync: 'DCSync', getchanges: 'DCSync', getchangesall: 'DCSync', readgmsapassword: 'ReadGMSAPassword', 'msds-allowedtoactonbehalfofotheridentity': 'RBCD', allowedtoact: 'RBCD', rbcd: 'RBCD' };
    var key = right.trim().toLowerCase();
    return map[key] || right.trim();
  }
  C._canonical_right = _canonical_right;

  function _ad_abuse_tool(command) {
    var l = (command || '').toLowerCase();
    var tools = ['bloodyad', 'dacledit', 'owneredit', 'ticketer', 'addcomputer', 'rbcd', 'getst', 'gettgt', 'gmsadumper', 'rubeus', 'net'];
    for (var i = 0; i < tools.length; i++) if (l.indexOf(tools[i]) >= 0) return tools[i];
    if (l.indexOf('laps') >= 0) return 'laps';
    return 'ad-abuse';
  }
  C._ad_abuse_tool = _ad_abuse_tool;

  function _parse_ad_control_paths(text, ws, command, source, facts) {
    var lc = (command || '').toLowerCase();
    var textLow = (text || '').toLowerCase();
    if (/\bdacledit(?:\.py)?\b/i.test(lc) && /-action\s+read\b/i.test(lc)) {
      var rSet = {};
      reAll(C._AD_CONTROL_RIGHT_RE, text).forEach(function (m) { rSet[_canonical_right(m[1])] = true; });
      var rList = C.uniqueSortedCI(Object.keys(rSet));
      if (rList.length) {
        var rTarget = C._command_arg(command, ['--target', '-target', '-target-dn', '--target-dn']) || '';
        var rPrincipal = C._command_arg(command, ['-principal', '--principal']) || '';
        _add(facts, mkFact('ad.acl_lead', C._scope_for_domain(ws), {
          rights: rList,
          targets: rTarget ? [C.stripChars(rTarget, "'\"")] : [],
          principals: rPrincipal ? [C.stripChars(rPrincipal, "'\"")] : [],
          method: 'dacledit',
          note: 'enumerated DACL ACE (read-only)',
        }, S, source));
      }
      return;
    }
    if (/\bnet\s+localgroup\b/i.test(lc) && !/\/domain\b/i.test(lc)) return;
    var netUserResetM = /(?:^|\n|[>;]\s*)net(?:\.exe)?\s+user\s+(?:'([^']+)'|"([^"]+)"|([^\s/"']+))\s+(?:'([^']+)'|"([^"]+)"|([^\s/"']+))\s+\/domain\b(?![^\r\n]*\/add\b)/i.exec((command || '') + '\n' + (text || ''));
    var netRpcPassM = /(?:^|\n|[>;$#]\s*)net\s+rpc\s+password\s+(?:'([^']+)'|"([^"]+)"|([^\s"'-][^\s"']*))\s+(?:'([^']+)'|"([^"]+)"|([^\s"'-][^\s"']*))/i.exec((command || '') + '\n' + (text || ''));
    var nonCommentText = String(text || '').replace(/^\s*#[^\r\n]*$/gm, '').trim();
    var abuseVerb = ['groupmember', 'set owner', 'writeowner', 'owneredit', 'genericall', 'dacledit', '-action write',
      'add dcsync', ' dcsync', '-rights dcsync', 'rights:dcsync', 'add rbcd', 'add uac', 'set password', 'add computer', 'net group', 'net rpc'
    ].some(function (k) { return lc.indexOf(k) >= 0; }) || (lc.indexOf('net localgroup') >= 0 && lc.indexOf('/domain') >= 0) || !!netUserResetM;
    if (lc.indexOf('get writable') >= 0 && !abuseVerb) return;
    if (/\b(?:get-adcomputer|get-adserviceaccount|get-aduser|get-adgroup|get-domaincomputer|get-netcomputer)\b/i.test(lc) && !abuseVerb) return;
    var rightsSet = {};
    var operation = '';
    if (lc.indexOf('add dcsync') >= 0 || lc.indexOf(' dcsync') >= 0 || lc.indexOf('-rights dcsync') >= 0 || lc.indexOf('rights:dcsync') >= 0 || /is now able to dcsync/i.test(text)) { operation = 'dcsync_grant'; rightsSet.DCSync = true; }
    else if (lc.indexOf('groupmember') >= 0 || lc.indexOf('add groupmember') >= 0 || /\bnet\s+(?:group|localgroup\b[^\r\n]*\/domain|rpc\s+group\s+addmem)\b.*\/add\b/i.test(lc) || /\badded to (?:group\s+)?["']?[A-Za-z0-9 _-]+["']?\s*$/im.test(text)) { operation = 'group_member_write'; rightsSet.WriteMembers = true; }
    else if (lc.indexOf('set owner') >= 0 || lc.indexOf('writeowner') >= 0 || lc.indexOf('owneredit') >= 0 || /ownersid modified successfully|current owner information below/i.test(text)) { operation = 'owner_write'; rightsSet.WriteOwner = true; }
    else if (lc.indexOf('set password') >= 0 || /password changed successfully/i.test(text) || (netUserResetM && /The command completed successfully/i.test(text)) || (netRpcPassM && nonCommentText.length > 0)) { operation = 'password_reset'; rightsSet.ForceChangePassword = true; }
    else if (lc.indexOf('genericall') >= 0 || lc.indexOf('dacledit') >= 0 || /dacl modified successfully/i.test(text)) { operation = 'dacl_write'; rightsSet.GenericAll = true; }
    else if (lc.indexOf('rbcd') >= 0 || textLow.indexOf('msds-allowedtoact') >= 0) { operation = 'rbcd_write'; rightsSet.RBCD = true; }

    var evidence = [];
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      if (/^\s*\[-\]|\b(?:insufficientAccessRights|insufficient_access_rights|INSUFF_ACCESS_RIGHTS|access[_ ]denied|error|failed)\b/i.test(line)) continue;
      reAll(C._AD_CONTROL_RIGHT_RE, line).forEach(function (m) { rightsSet[_canonical_right(m[1])] = true; });
      if (reSearch(C._AD_CONTROL_RIGHT_RE, line) || reSearch(C._AD_CONTROL_SUCCESS_RE, line)) evidence.push(line.slice(0, 220));
      if (evidence.length >= 5) break;
    }
    var explicitAbuseSuccess = /dacl modified successfully|ownersid modified successfully|password changed successfully|successfully (?:updated|changed|reset) password|is now able to dcsync|delegation rights modified successfully|msds-allowedtoactonbehalfofotheridentity modified/i.test(text);
    var opError = reSearch(/^\s*\[-\]|\b(error|failed|denied|unauthorized|insufficient|insufficientAccessRights|insufficient_access_rights|INSUFF_ACCESS_RIGHTS|dsid-|traceback|not recognized|access is denied|constraint|cannot|invalid)\b/im, text);
    var alreadyMemberRe = /already a member|entryalreadyexists|member_in_alias/i;
    var hasJoinLine = operation === 'group_member_write' && (/(?:\badded to\b|^\s*\[\+\]\s*joined:|The command completed successfully)/im.test(text) || alreadyMemberRe.test(text));
    var success = explicitAbuseSuccess || hasJoinLine || evidence.length > 0 || !!reSearch(C._AD_CONTROL_SUCCESS_RE, text) || (!!operation && !!nonCommentText && !opError);
    if (netUserResetM && !/The command completed successfully/i.test(text)) success = false;
    if (netRpcPassM && (!nonCommentText || /\b(?:NT_STATUS_|Usage:|System error)\b/i.test(text))) success = false;
    if (opError && !explicitAbuseSuccess && !hasJoinLine && !reSearch(C._AD_CONTROL_SUCCESS_RE, text) && !alreadyMemberRe.test(text)) success = false;
    if (!success) return;

    var successMatch = reSearch(C._AD_CONTROL_SUCCESS_RE, text);
    var defaultEvidence = successMatch ? [C._line_for_match(text, successMatch)] : [((text.trim().split(/\r?\n/)[0]) || 'control path granted').slice(0, 220)];
    var domScope = C._scope_for_domain(ws);
    if (operation === 'group_member_write') {
      var joins = [], seenJ = {};
      text.split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim(); if (!line) return;
        var body = line.replace(/^\[\d[\d:]*\]\s*(?:INFO|WARN(?:ING)?|DEBUG|ERROR)?\s*/i, '').replace(/^\[[-*+!]\]\s*/, '');
        var g = '', principal = '', mj = /^joined:\s*(.+)$/i.exec(body);
        if (mj) { g = mj[1].trim(); }
        else {
          var ma = /^([^\r\n]{1,120}?)[ \t]+added to (?:group[ \t]+)?([^\r\n]{1,120}?)\.?$/i.exec(body);
          if (ma) { principal = ma[1].trim(); g = ma[2].trim(); }
          else { var me = /entryalreadyexists for cn=([^,\n]+)/i.exec(body); if (me) g = me[1].trim(); }
        }
        if (!g || g.indexOf('$') >= 0) return;
        var key = g.toLowerCase(); if (seenJ[key]) return; seenJ[key] = true;
        joins.push({ group: C.stripChars(g, "'\""), principal: C.stripChars(principal, "'\""), line: line.slice(0, 220) });
      });
      if (!joins.length) {
        var gmMatches = reAll(/groupmember\s+(?:'([^']+)'|"([^"]+)"|(\S+))/gi, command || '');
        var netMatches = reAll(/\bnet\s+(?:group|localgroup(?=[^\r\n]*\/domain))\s+(?:'([^']+)'|"([^"]+)"|(\S+))\s+(?:'([^']+)'|"([^"]+)"|(\S+))\s+\/add/gi, (command || '') + '\n' + (text || ''));
        if (gmMatches.length) {
          var toks = (command || '').split(/\s+/);
          var gmPrinc = toks.length ? toks[toks.length - 1] : '';
          gmMatches.forEach(function (m) {
            var cg = m[1] || m[2] || m[3] || '';
            if (cg && cg.indexOf('$') < 0 && (!opError || explicitAbuseSuccess || hasJoinLine || alreadyMemberRe.test(text))) {
              var key = cg.toLowerCase(); if (seenJ[key]) return; seenJ[key] = true;
              joins.push({ group: C.stripChars(cg, "'\""), principal: C.stripChars(gmPrinc, "'\""), line: (evidence[0] || defaultEvidence[0] || '') });
            }
          });
        }
        if (netMatches.length) {
          netMatches.forEach(function (m) {
            var cg = m[1] || m[2] || m[3] || '';
            var princ = m[4] || m[5] || m[6] || '';
            if (cg && cg.indexOf('$') < 0 && (!opError || explicitAbuseSuccess || hasJoinLine || alreadyMemberRe.test(text))) {
              var key = cg.toLowerCase(); if (seenJ[key]) return; seenJ[key] = true;
              joins.push({ group: C.stripChars(cg, "'\""), principal: C.stripChars(princ, "'\""), line: (evidence[0] || defaultEvidence[0] || '') });
            }
          });
        }
      }
      joins.forEach(function (j) {
        _add(facts, mkFact('ad.group_joined', domScope,
          { group: j.group, principal: j.principal, method: _ad_abuse_tool(command), evidence: [j.line] }, S, source));
        if (/^(domain admins|enterprise admins|administrators|schema admins)$/i.test(String(j.group || '').trim())) {
          _add(facts, mkFact('ad.control_paths', domScope,
            { right: 'AddMember', rights: ['WriteMembers'], operation: 'group_member_write', group: j.group, principal: j.principal, method: _ad_abuse_tool(command), evidence: [j.line] }, S, source));
        }
      });
      return;
    }
    var rights = Object.keys(rightsSet);
    var value = { rights: rights.length ? C.uniqueSortedCI(rights) : ['control_path'], method: _ad_abuse_tool(command), evidence: evidence.length ? evidence : defaultEvidence };
    if (operation) value.operation = operation;
    var target = C._command_arg(command, ['--target', '-target', '-target-dn', '--target-dn', '-delegate-to']) || C._command_arg(command, ['-target-sam']);
    if (!target && operation === 'password_reset') {
      var rstM = netUserResetM || netRpcPassM;
      if (rstM) target = rstM[1] || rstM[2] || rstM[3] || '';
    }
    if (target) value.target = C.stripChars(target, "'\"");
    var principal = C._command_arg(command, ['-principal', '--principal', '-new-owner', '--new-owner', '-delegate-from']);
    if (!principal && operation === 'dcsync_grant') {
      var dm = /(?:add\s+dcsync|dcsync\s+-v)\s+(?:'([^']+)'|"([^"]+)"|(\S+))/i.exec(command || '') || /^\s*\[\+\]\s*([^\s]+)\s+is now able to dcsync/im.exec(text || '');
      if (dm) principal = dm[1] || dm[2] || dm[3] || '';
    }
    if (principal) value.principal = C.stripChars(principal, "'\"");
    if (operation === 'password_reset') value.action = 'password-reset';
    _add(facts, mkFact('ad.control_paths', domScope, value, S, source));
    if (operation === 'dcsync_grant') {
      _add(facts, mkFact('ad.domain_control', domScope, { principal: value.principal || '', right: 'DCSync', method: value.method, evidence: value.evidence }, S, source));
    }
    if (operation === 'password_reset') {
      _add(facts, mkFact('ad.acl_paths', domScope, value, S, source));
      var spm = /set\s+password\s+(?:'([^']+)'|"([^"]+)"|(\S+))\s+(?:'([^']+)'|"([^"]+)"|(\S+))/i.exec(command || '');
      if (spm && /password changed successfully|successfully (?:updated|changed|reset) password/i.test(text) && C._add_plaintext_credential) {
        var spUser = spm[1] || spm[2] || spm[3] || '';
        var spPass = spm[4] || spm[5] || spm[6] || '';
        C._add_plaintext_credential(facts, ws, source, spUser, spPass, C._domain_from_facts(ws), 'bloodyad-set-password', '');
      } else if ((netUserResetM || netRpcPassM) && C._add_plaintext_credential) {
        var nrM = netUserResetM || netRpcPassM;
        var nrUser = nrM[1] || nrM[2] || nrM[3] || '';
        var nrPass = nrM[4] || nrM[5] || nrM[6] || '';
        C._add_plaintext_credential(facts, ws, source, nrUser, nrPass, C._domain_from_facts(ws), 'acl-password-reset', '');
      }
    }
  }
  C._parse_ad_control_paths = _parse_ad_control_paths;

  function _parse_added_computer(text, ws, command, source, facts) {
    var lowered = (text + '\n' + command).toLowerCase();
    if (lowered.indexOf('addcomputer') < 0 && lowered.indexOf('machine account') < 0 && lowered.indexOf('computer account') < 0) return;
    var explicitAddSuccess = !!reSearch(C._ADD_COMPUTER_SUCCESS_RE, text) || /\bsuccessfully\s+(?:added|created)\b/i.test(text);
    if (!explicitAddSuccess && /\b(error|failed|denied|constraint|already exists)\b/i.test(text)) return;
    var success = explicitAddSuccess || /\b(success|created|added)\b/i.test(text);
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
    var rubeusSuccess = /\[\+\]\s*TGT request successful!|\[\+\]\s*Ticket successfully imported!|\[\+\]\s*S4U2self success!|\[\+\]\s*S4U2proxy success!|Base64\(ticket\.kirbi\):|\bdoIF[A-Za-z0-9+\/=\r\n]{40,}/i.test(text);
    var ticketSignal = files.length > 0 || lowered.indexOf('got tgt') >= 0 || (lowered.indexOf('ticket') >= 0 && lowered.indexOf('saved') >= 0) || klistSuccess || rubeusSuccess;
    if (!ticketSignal) return;
    var principal = C._command_arg(command, ['-impersonate', '--impersonate']);
    var rImp = /\/(?:impersonateuser|user):([^\s"']+)/i.exec(command || '') || /^\s*UserName\s*:\s*(\S+)/im.exec(text);
    if (!principal && rImp) principal = rImp[1];
    var m = reSearch(C._IMPERSONATE_RE, text);
    if (!principal && m) principal = m.groups.user;
    if (!principal) principal = C._command_arg(command, ['-u', '--user', '--username']) || C._command_arg(command, ['user']);
    if (!principal && files.length) {
      var fBase = files[0].split('/').pop().replace(/\.(?:ccache|kirbi)$/i, '');
      if (fBase && C._valid_username(fBase.split('@')[0], false)) principal = fBase.split('@')[0];
    }
    var value = { method: rubeusSuccess ? 'rubeus' : _ad_abuse_tool(command) };
    if (files.length) value.files = files;
    if (principal) value.principal = C._clean_username(principal);
    var spn = C._command_arg(command, ['-spn', '--spn']);
    var rSpn = /\/(?:msdsspn|altservice|service):([^\s"']+)/i.exec(command || '') || /^\s*ServiceName\s*:\s*(\S+)/im.exec(text);
    if (!spn && rSpn) spn = rSpn[1];
    if (spn) value.spn = C.stripChars(spn, "'\"");
    _add(facts, mkFact('kerberos.tickets', C._scope_for_domain(ws), value, S, source));
  }
  C._parse_kerberos_ticket_material = _parse_kerberos_ticket_material;
  C._parse_rubeus_asktgt = _parse_kerberos_ticket_material;

  function _parse_gmsa_material(text, ws, command, source, facts) {
    var lowered = (text + '\n' + command).toLowerCase();
    if (lowered.indexOf('gmsa') < 0 && lowered.indexOf('msds-managedpassword') < 0) return;
    var entries = [], seen = {};
    reAll(C._GMSA_HASH_RE, text).forEach(function (m) {
      var user = C._clean_username(m.groups.user);
      var nt = m.groups.nt.toLowerCase();
      if (!C._valid_username(user) || seen[user.toLowerCase() + '|' + nt]) return;
      seen[user.toLowerCase() + '|' + nt] = true;
      var item = { user: user, nthash: nt, method: 'gmsa', accountType: 'domain' };
      var domain = m.groups.domain || C._domain_from_facts(ws);
      if (domain) { item.domain = domain; item.realm = domain; }
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
      var nxcMatch = reSearch(/(?:SMB|LDAP)\s+\S+\s+\d+\s+(?<computer>[A-Za-z0-9_.-]+)\s+\[[-+]\]\s+(?:[A-Za-z0-9_.-]+\\)?administrator:(?<pw>\S+)/i, line);
      if (nxcMatch) {
        pwMatch = { groups: { pw: nxcMatch.groups.pw } };
        computer = nxcMatch.groups.computer;
        currentUser = 'Administrator';
      }
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
      creds.push({ kind: 'laps_password', computer: computer, targetBinding: computer.replace(/\$$/, ''), accountType: 'local', realm: computer.replace(/\$$/, ''), user: currentUser, password: password, method: 'laps' });
    });
    creds.forEach(function (cred) {
      _add(facts, mkFact('credential.candidate', C._scope_for_domain(ws), cred, S, source));
      _add(facts, mkFact('ad.laps', 'host:' + cred.targetBinding, { computer: cred.computer, user: cred.user || 'Administrator', password: cred.password, via: 'laps' }, S, source));
      _add(facts, mkFact('credential.available', 'host:' + cred.targetBinding, {
        user: cred.user || 'Administrator',
        password: cred.password,
        method: 'laps',
        computer: cred.computer,
        targetBinding: cred.targetBinding,
        accountType: 'local',
        realm: cred.realm,
        domain: '',
        sourceDomain: C._domain_from_facts(ws) || ''
      }, S, source));
    });
  }
  C._parse_laps_material = _parse_laps_material;

  function _parse_ldap_descriptions(text, ws, source, facts, opts) {
    opts = opts || {};
    var domain = opts.domain_hint || (ws && ws.domain) || '';
    var scope = C._scope_for_domain(ws, domain);
    // Unfold RFC 2849 LDIF line continuations (CRLF/LF followed by a single space or tab)
    var unfolded = String(text || '').replace(/\r?\n[ \t]+(?=[A-Za-z0-9_!@#$%^&*()+=.,;:'"\/\\?-])/g, '');
    var lines = unfolded.split(/\r?\n/);
    var pwRegex = /(?:password(?:\s+for\s+[^\r\n]{1,40}?)?\s+(?:is|set\s+to)|pwd[:=\s]+|pass[:=\s]+|password\s*[:=])\s*['"]?([^\s'"]{4,})['"]?/i;
    var ldifUser = '', pendingDesc = '', pendingLine = '';
    function emitDesc(user, desc, evLine) {
      if (!desc) return;
      var pwm = desc.match(pwRegex);
      if (pwm) {
        var pwd = pwm[1].trim();
        var cred = { user: user || 'user', password: pwd, method: 'description', domain: domain };
        _add(facts, mkFact('credential.candidate', scope, cred, S, source));
        if (user && user !== 'user') {
          _add(facts, mkFact('credential.available', scope, cred, S, source));
        }
        _add(facts, mkFact('config.review', scope, { file: 'description', evidence: [evLine], note: 'Password recovered from account description' }, S, source));
      }
    }
    lines.forEach(function (raw) {
      var line = raw.trim();
      if (!line || /^dn\s*:/i.test(line)) {
        if (pendingDesc) emitDesc(ldifUser, pendingDesc, pendingLine);
        ldifUser = ''; pendingDesc = ''; pendingLine = '';
        if (/^dn\s*:/i.test(line)) {
          var cnM = /\b(?:CN|uid)=([^,\r\n]+)/i.exec(line);
          if (cnM && cnM[1] && !/\s/.test(cnM[1].trim())) ldifUser = cnM[1].trim();
        }
        return;
      }
      var samM = /^sAMAccountName\s*:\s*(\S+)/i.exec(line);
      if (samM) {
        ldifUser = samM[1].trim();
        if (pendingDesc) { emitDesc(ldifUser, pendingDesc, pendingLine); pendingDesc = ''; pendingLine = ''; }
        return;
      }
      var m = line.match(/^(?:(?:LDAP|SMB)\s+\S+\s+\d+\s+\S+\s+)?([A-Za-z0-9_.-]+)[ \t]+(?:\d{4}-\d{2}-\d{2}(?:[ \t]+\d{2}:\d{2}:\d{2})?|<never>|never|none)[ \t]+\d*[ \t]*(.*)/i);
      if (m) {
        emitDesc(m[1].trim(), m[2].trim(), line);
        return;
      }
      var dm = line.match(/^description\s*:\s*\[?(.*?)\]?\s*$/i);
      if (dm) {
        var dText = dm[1].replace(/\)\s*$/, '').trim();
        if (ldifUser) emitDesc(ldifUser, dText, line);
        else { pendingDesc = dText; pendingLine = line; }
      }
    });
    if (pendingDesc) emitDesc(ldifUser, pendingDesc, pendingLine);
  }
  C._parse_ldap_descriptions = _parse_ldap_descriptions;

  var _UNCONSTRAINED_RE = /\b(TRUSTED_FOR_DELEGATION|unconstrained(?:\s+delegation)?)\b/i;
  var _CONSTRAINED_RE = /\b(msDS-AllowedToDelegateTo|TRUSTED_TO_AUTH_FOR_DELEGATION|Constrained(?:\s+w\/\s+Protocol\s+Transition|\s+Delegation)?)\b/i;
  var _RBCD_DELEG_RE = /\b(msDS-AllowedToActOnBehalfOfOtherIdentity|Resource-Based\s+Constrained)\b/i;
  var _GMSA_DISCOVER_RE = /(msDS-GroupMSAMembership|GroupManagedServiceAccount|msDS-ManagedPasswordId|\bgMSA\b)/i;

  // Domain Controllers always carry TRUSTED_FOR_DELEGATION (SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION = 532480,
  // primaryGroupID 516, OU=Domain Controllers) by Active Directory design. Only mint ad.unconstrained when a
  // non-DC computer or user principal exhibits unconstrained delegation.
  function _isDcOnlyUnconstrained(text, ws) {
    var knownDc = String((ws && (ws.dc_hostname || ws.dcHost || ws.hostname)) || '').split('.')[0].toLowerCase();
    function stanzaIsDc(block) {
      if (/\b(?:SERVER_TRUST_ACCOUNT|OU=Domain Controllers)\b/i.test(block)) return true;
      if (/\bprimaryGroupID:\s*516\b/i.test(block)) return true;
      if (/\buserAccountControl:\s*(?:532480|532512)\b/i.test(block)) return true;
      var acctM = /\b(?:sAMAccountName|cn|name):\s*([^\r\n$]+)\$?/i.exec(block);
      if (acctM) {
        var acct = acctM[1].trim().toLowerCase();
        if ((knownDc && acct === knownDc) || /^dc\d*$/.test(acct)) return true;
      }
      return false;
    }
    function stanzaHasUnconstrainedUac(block) {
      var uacM = /\buserAccountControl:\s*(\d+)\b/i.exec(block);
      if (!uacM) return null;
      var uac = parseInt(uacM[1], 10);
      if (!isFinite(uac)) return null;
      // 0x80000 = TRUSTED_FOR_DELEGATION, 0x2000 = SERVER_TRUST_ACCOUNT (Domain Controller)
      if ((uac & 0x80000) !== 0 && (uac & 0x2000) === 0) return uacM[0].trim();
      return null;
    }
    if (/^\s*dn:\s+/im.test(text)) {
      var stanzas = String(text).split(/\r?\n\s*\r?\n/);
      var nonDcEv = [];
      for (var s = 0; s < stanzas.length; s++) {
        var st = stanzas[s];
        if (stanzaIsDc(st)) continue;
        var m = reSearch(_UNCONSTRAINED_RE, st);
        if (m) nonDcEv.push(C._line_for_match(st, m));
        else {
          var uacEv = stanzaHasUnconstrainedUac(st);
          if (uacEv) nonDcEv.push(uacEv);
        }
      }
      return nonDcEv.length ? nonDcEv : null;
    }
    var lines = String(text || '').split(/\r?\n/);
    var hits = [];
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (!_UNCONSTRAINED_RE.test(ln)) continue;
      if (/\b(?:SERVER_TRUST_ACCOUNT|OU=Domain Controllers|Domain Controller)\b/i.test(ln)) continue;
      // Check principal token on tabular/nxc/findDelegation lines (e.g. "DC$  Server Trust Account  Unconstrained" or "DC$ (unconstrained)").
      // Note: '$' is non-word in JS regex so do not place \b after '$'.
      var dcTok = /\b([A-Za-z0-9._-]+)\$(?=\s|$|[),;:])/.exec(ln);
      if (dcTok) {
        var hostBase = dcTok[1].split('.')[0].toLowerCase();
        if ((knownDc && hostBase === knownDc) || /^dc\d*$/.test(hostBase)) continue;
      }
      hits.push(ln.trim());
    }
    return hits.length ? hits : null;
  }

  function _parse_ad_delegation_surface(text, ws, command, source, facts) {
    if (/\bget\s+writable\b/i.test(command || '') || (C._looks_like_bloodyad_writable && C._looks_like_bloodyad_writable(text))) return;
    var scope = C._scope_for_domain(ws);
    var hasUacAttr = text.indexOf('userAccountControl:') >= 0 || text.indexOf('useraccountcontrol:') >= 0;
    var um = reSearch(_UNCONSTRAINED_RE, text) || hasUacAttr;
    if (um) {
      var nonDc = _isDcOnlyUnconstrained(text, ws);
      if (nonDc && nonDc.length) {
        _add(facts, mkFact('ad.unconstrained', scope, { evidence: nonDc.slice(0, 4) }, S, source));
      }
    }
    var rm = reSearch(_RBCD_DELEG_RE, text);
    if (rm) {
      _add(facts, mkFact('ad.rbcd', scope, { evidence: [C._line_for_match(text, rm)] }, S, source));
      _add(facts, mkFact('ad.delegation', scope, { kind: 'rbcd', evidence: [C._line_for_match(text, rm)] }, S, source));
    }
    var cm = reSearch(_CONSTRAINED_RE, text);
    if (cm || /^AccountName\s+AccountType\s+DelegationType/im.test(text)) {
      var ev = cm ? [C._line_for_match(text, cm)] : [];
      _add(facts, mkFact('ad.delegation', scope, { kind: 'constrained', evidence: ev }, S, source));
      _add(facts, mkFact('ad.attack_paths', scope, { kind: 'delegation', evidence: ev }, S, source));
    }
    var gm = reSearch(_GMSA_DISCOVER_RE, text);
    if (gm && !reSearch(C._GMSA_READ_ERROR_RE, text)) _add(facts, mkFact('ad.gmsa', scope, { evidence: [C._line_for_match(text, gm)] }, S, source));
  }
  C._parse_ad_delegation_surface = _parse_ad_delegation_surface;

  var _BLOODY_WRITABLE_ATTR_RIGHT = {
    all: 'GenericAll',
    member: 'WriteMembers',
    permission: 'WriteMembers',
    ntsecuritydescriptor: 'WriteDACL',
    owner: 'WriteOwner',
    unicodepwd: 'ForceChangePassword',
    userpassword: 'ForceChangePassword',
    'msds-keycredentiallink': 'AddKeyCredentialLink',
    serviceprincipalname: 'WriteSPN',
    'msds-allowedtoactonbehalfofotheridentity': 'RBCD',
  };
  var _ABUSABLE_GROUP_CN = {
    'exchange windows permissions': 1, 'organization management': 1,
    'account operators': 1, 'backup operators': 1, 'server operators': 1, 'print operators': 1,
    'dnsadmins': 1, 'administrators': 1, 'domain admins': 1, 'enterprise admins': 1, 'schema admins': 1,
    'group policy creator owners': 1, 'key admins': 1, 'enterprise key admins': 1,
    'remote management users': 1, 'distributed com users': 1,
  };
  var _BUILTIN_NOISE_GROUP_CN = {
    'domain users': 1, 'domain guests': 1, 'guests': 1, 'users': 1, 'domain computers': 1,
    'domain controllers': 1, 'read-only domain controllers': 1, 'enterprise read-only domain controllers': 1,
    'pre-windows 2000 compatible access': 1, 'incoming forest trust builders': 1,
    'windows authorization access group': 1, 'terminal server license servers': 1,
    'allowed rodc password replication group': 1, 'denied rodc password replication group': 1,
    'cert publishers': 1, 'ras and ias servers': 1, 'iis_iusrs': 1, 'performance monitor users': 1,
    'performance log users': 1, 'event log readers': 1, 'cryptographic operators': 1,
    'network configuration operators': 1, 'certificate service dcom access': 1,
    'rds remote access servers': 1, 'rds endpoint servers': 1, 'rds management servers': 1,
    'access control assistance operators': 1, 'cloneable domain controllers': 1, 'protected users': 1,
  };
  var _ACL_LEAD_NOTES = {
    'exchange windows permissions':
      'you can add yourself to Exchange Windows Permissions, which holds WriteDacl over the domain '
      + '-> grant yourself DCSync (getchanges/getchangesall) -> secretsdump the Administrator hash',
  };
  function _cn_from_dn(dn) {
    var head = (dn || '').split(',')[0];
    return head.indexOf('=') >= 0 ? head.split('=').slice(1).join('=').trim() : head.trim();
  }

  var _BLOODY_WRITABLE_PERM_RE = /^[A-Za-z][\w-]*:[ \t]*(?:WRITE|CREATE_CHILD)[ \t]*$/;
  function _looks_like_bloodyad_writable(text) {
    if (!text || text.toLowerCase().indexOf('distinguishedname:') < 0) return false;
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      if (_BLOODY_WRITABLE_PERM_RE.test(lines[i].trim())) return true;
    }
    return false;
  }
  C._looks_like_bloodyad_writable = _looks_like_bloodyad_writable;

  function _parse_bloodyad_writable(text, ws, command, source, facts) {
    if (command.toLowerCase().indexOf('get writable') < 0 && !_looks_like_bloodyad_writable(text)) return;
    var memberT = [], customMemberT = [], daclT = [], ownerT = [], gpoT = [], rights = {}, notes = [];
    text.split(/(?:^|\r?\n)(?=[ \t]*distinguishedName[ \t]*:)/i).forEach(function (block) {
      var lines = block.split(/\r?\n/).map(function (l) { return l.replace(/\s+$/, ''); }).filter(function (l) { return l.trim(); });
      if (!lines.length || !/^\s*distinguishedname\s*:/i.test(lines[0])) return;
      var dn = lines[0].split(':').slice(1).join(':').trim();
      var cn = _cn_from_dn(dn), cnl = cn.toLowerCase(), attrs = {};
      for (var i = 1; i < lines.length; i++) {
        var ln = lines[i];
        if (ln.indexOf(':') >= 0) attrs[ln.split(':')[0].trim().toLowerCase()] = ln.split(':').slice(1).join(':').trim().toUpperCase();
      }
      var isDomainRoot = !!dn && dn.split(',').every(function (p) { return p.trim().toLowerCase().indexOf('dc=') === 0; });
      var isComputer = cn.charAt(cn.length - 1) === '$' || dn.indexOf(',CN=Computers,') >= 0;
      var isUserOrObject = dn.toLowerCase().indexOf('cn=users') >= 0 || dn.toLowerCase().indexOf('ou=') >= 0 || dn.toLowerCase().indexOf('cn=managed service accounts') >= 0;
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
          } else if (!isDomainRoot && !isComputer && isUserOrObject && !_BUILTIN_NOISE_GROUP_CN[cnl]) {
            rights[right] = 1; customMemberT.push(cn);
          }
        } else if (right === 'RBCD') {
          if (isComputer || isUserOrObject) { rights[right] = 1; ownerT.push(cn); }
        } else if (right === 'ForceChangePassword' || right === 'AddKeyCredentialLink' || right === 'WriteSPN' || right === 'GenericAll') {
          if (isDomainRoot || isComputer || _ABUSABLE_GROUP_CN[cnl] || isUserOrObject) {
            rights[right] = 1;
            ownerT.push(isDomainRoot ? 'the domain object' : cn);
          }
        } else if (isDomainRoot || isComputer || _ABUSABLE_GROUP_CN[cnl]) {
          rights[right] = 1;
          (right === 'WriteDACL' ? daclT : ownerT).push(isDomainRoot ? 'the domain object' : cn);
        }
      });
    });
    var seenG = {};
    gpoT.forEach(function (g) { if (!seenG[g]) { seenG[g] = 1; _add(facts, mkFact('ad.gpo_writable', C._scope_for_domain(ws), { gpo: g, method: 'bloodyad' }, S, source)); } });
    var seenT = {}, targets = [];
    memberT.concat(customMemberT, daclT, ownerT).forEach(function (t) { if (!seenT[t]) { seenT[t] = 1; targets.push(t); } });
    var rightList = Object.keys(rights);
    if (!(rightList.length && targets.length)) return;
    if (!notes.length) notes.push('enumerated control right (lead), cash it in with the ACL-abuse move; not a granted control path yet');
    _add(facts, mkFact('ad.acl_lead', C._scope_for_domain(ws), {
      rights: rightList.sort(function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; }),
      targets: targets.slice(0, 10), method: 'bloodyad', note: notes.join(' - '),
    }, S, source));
  }
  C._parse_bloodyad_writable = _parse_bloodyad_writable;

  var _SCCM_NAA_USER_RE = /Network\s*Access\s*(?:Username|Account)\s*[:=]\s*([^\r\n]+)/i;
  var _SCCM_NAA_PASS_RE = /Network\s*Access\s*Password\s*[:=]\s*(\S+)/i;
  var _SCCM_NAA_COLON_RE = /Network\s*Access\s*Account\s*[:=]\s*(?:(?<dom>[A-Za-z0-9._-]+)\\)?(?<user>[A-Za-z0-9._$-]+)\s*:\s*(?<pw>\S+)/i;
  var _SCCM_NAA_GENERIC_RE = /\bNAA\b.*(?:cred|password|username)/i;
  var _SCCM_BANNER_RE = /SCCMHunter\s+v[\d.]+|SharpSCCM/i;
  var _SCCM_ABSENT_RE = /System Management Container not found|No results found|\bno sccm\b|not vulnerable to sccm/i;
  var _SCCM_PRESENT_RE = /\[\+\]|System Management Container found|\bFound\b[^\r\n]{0,60}(?:management point|distribution point|site (?:server|system|code)|SMS Provider)|\bprimary site code\b|Site Server\s*:\s*\S+/i;

  function _parse_sccm(text, ws, source, facts) {
    var domScope = C._scope_for_domain(ws), h = 'host:' + ws.target;
    var colonM = reSearch(_SCCM_NAA_COLON_RE, text);
    var users = reAll(_SCCM_NAA_USER_RE, text);
    var passM = reSearch(_SCCM_NAA_PASS_RE, text);
    var hasPass = !!passM || !!colonM;
    var generic = !!reSearch(_SCCM_NAA_GENERIC_RE, text);
    var present = !!reSearch(_SCCM_PRESENT_RE, text);
    var absent = !!reSearch(_SCCM_ABSENT_RE, text);
    var siteSrv = reSearch(/Site Server\s*:\s*([A-Za-z0-9._-]+)/i, text);
    if (colonM && colonM.groups) {
      var naaUser = C._clean_username(colonM.groups.user);
      var naaPw = colonM.groups.pw.trim();
      var naaDom = (colonM.groups.dom || '').trim() || C._domain_from_facts(ws);
      _add(facts, mkFact('credential.candidate', domScope, { kind: 'sccm_naa', user: naaUser, password: naaPw, count: 1 }, S, source));
      if (C._valid_username(naaUser, false) && C._valid_password(naaPw) && C._add_plaintext_credential) {
        C._add_plaintext_credential(facts, ws, source, naaUser, naaPw, naaDom, 'sccmhunter', '');
      }
      _add(facts, mkFact('ad.sccm_candidates', domScope, { present: true, naa_user: naaUser, site_server: siteSrv ? siteSrv[1] : undefined, method: 'sccmhunter' }, S, source));
      _add(facts, mkFact('sccm.enumerated', h, { present: true, method: 'sccmhunter' }, S, source));
      return;
    }
    if ((users.length && hasPass) || (generic && hasPass)) {
      _add(facts, mkFact('credential.candidate', domScope,
        { kind: 'sccm_naa', count: Math.max(users.length, 1) }, S, source));
      _add(facts, mkFact('ad.sccm_candidates', domScope, { present: true, method: 'sccmhunter' }, S, source));
      _add(facts, mkFact('sccm.enumerated', h, { present: true, method: 'sccmhunter' }, S, source));
      return;
    }
    var hasSccmStruct = reSearch(_SCCM_BANNER_RE, text) || (/Site Server\s*:/i.test(text) && /(?:Site Code|Management Point|SMS Provider)\s*:/i.test(text));
    if (!(hasSccmStruct && (present || absent))) return;
    _add(facts, mkFact('sccm.enumerated', h,
      { present: present, method: 'sccmhunter' }, S, source));
    if (present) {
      _add(facts, mkFact('ad.sccm_candidates', domScope, { present: true, site_server: siteSrv ? siteSrv[1] : undefined, method: 'sccmhunter' }, S, source));
    }
  }
  C._parse_sccm = _parse_sccm;

  var _DC_RIGHT_RE = /(WriteDacl|WRITE_DACL|GenericAll|GENERIC_ALL|WriteOwner|WRITE_OWNER|\bOwns\b|GetChangesAll|Get-Changes-All|AllExtendedRights)/i;
  var _TRUSTEE_LABEL_RE = /(?:trustee|principal|identity|account)\s*[:=]\s*(.+?)\s*$/i;
  var _DC_ROOT_DN_RE = /get object\s+['"]?(?:dc=[^,'" ]+)(?:\s*,\s*dc=[^,'" ]+)+/i;
  var _INLINE_TRUSTEE_RE = /(?<![A-Za-z0-9.\-])([A-Za-z0-9.\-]{1,64}\\[A-Za-z0-9.\-_$ ]{1,64}?)[ \t]*$/;

  function _normalize_trustee(raw) {
    var s = C.stripChars((raw || '').trim(), "'\"");
    if (s.indexOf('\\') >= 0) s = s.split('\\').pop();
    if (s.indexOf('@') >= 0) s = s.split('@')[0];
    return s.trim();
  }
  C._normalize_trustee = _normalize_trustee;

  function _parse_bloodyad_domain_control(text, ws, command, source, facts) {
    var low = (command || '').toLowerCase();
    if (low.indexOf('get object') < 0 || low.replace(/_/g, '-').indexOf('resolve-sd') < 0) return;
    if (!reSearch(_DC_ROOT_DN_RE, low)) return;
    var current = '';
    text.split(/\r?\n/).forEach(function (raw) {
      var line = raw.trim();
      if (!line) return;
      var lab = reSearch(_TRUSTEE_LABEL_RE, line);
      if (lab && !reSearch(_DC_RIGHT_RE, lab[1])) current = _normalize_trustee(lab[1]);
      var rt = reSearch(_DC_RIGHT_RE, line);
      if (!rt) return;
      var principal = current;
      var inline = line.slice(0, rt.index);
      var bs = reSearch(_INLINE_TRUSTEE_RE, inline);
      if (bs) principal = _normalize_trustee(bs[1]);
      if (!principal) return;
      _add(facts, mkFact('ad.domain_control', C._scope_for_domain(ws),
        { principal: principal, right: rt[1], object: 'domain' }, S, source));
    });
  }
  C._parse_bloodyad_domain_control = _parse_bloodyad_domain_control;

  var _GP_BUILTIN_PRIV_TRUSTEE_RE = /^(?:Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Group Policy Creator Owners|Enterprise Domain Controllers|Domain Controllers|Read-only Domain Controllers|Enterprise Read-only Domain Controllers|SYSTEM|NT AUTHORITY\\SYSTEM|CREATOR OWNER|S-1-5-(?:9|18|32-544|32-548)|S-1-5-21-[0-9-]+-(?:512|516|518|519|520|521|544))$/i;
  var _GP_WRITABLE_PERM_RE = /^(?:GpoEditDeleteModifySecurity|GpoCustom)$/i;

  function _is_builtin_gp_trustee(raw) {
    var s = C.stripChars(String(raw || '').trim(), "'\"");
    if (!s) return true;
    if (_GP_BUILTIN_PRIV_TRUSTEE_RE.test(s)) return true;
    var norm = _normalize_trustee(s);
    return !norm || _GP_BUILTIN_PRIV_TRUSTEE_RE.test(norm);
  }

  function _looks_like_gp_permission(text) {
    if (!text) return false;
    return /^\s*Trustee\s*:\s*[^\r\n]+[\s\S]{1,180}?^\s*Permission\s*:\s*Gpo\w+/im.test(text)
      || (/^\s*Trustee\s+TrusteeType\s+Permission\b/im.test(text) && /\bGpo(?:EditDeleteModifySecurity|Custom|Apply|Read)\b/i.test(text));
  }
  C._looks_like_gp_permission = _looks_like_gp_permission;

  function _parse_gp_permission(text, ws, command, source, facts) {
    if (Array.isArray(source) && facts === undefined) {
      facts = source;
      source = command;
      command = '';
    }
    var cmd = String(command || '');
    if (cmd.toLowerCase().indexOf('get-gppermission') < 0 && !_looks_like_gp_permission(text)) return;
    var gpoNameM = /-Name\s+(?:"([^"]+)"|'([^']+)'|([^\s'"]+))/i.exec(cmd);
    var gpoGuidM = /-Guid\s+(?:"([^"]+)"|'([^']+)'|([^\s'"]+))/i.exec(cmd);
    var gpoName = gpoNameM ? (gpoNameM[1] || gpoNameM[2] || gpoNameM[3] || '').trim() : '';
    var gpoGuid = gpoGuidM ? (gpoGuidM[1] || gpoGuidM[2] || gpoGuidM[3] || '').trim().replace(/^[{}]|[{}]$/g, '') : '';
    if (!gpoName) {
      var gmText = /^\s*(?:GpoName|DisplayName)\s*:\s*(.+?)\s*$/im.exec(text || '');
      if (gmText) gpoName = gmText[1].trim();
    }
    if (!gpoName && gpoGuid) gpoName = gpoGuid;
    var scope = C._scope_for_domain(ws);
    var entries = [];
    String(text || '').split(/(?:^|\r?\n)(?=\s*Trustee\s*:)/i).forEach(function (blk) {
      var tm = /^\s*Trustee\s*:\s*(.+?)\s*$/im.exec(blk);
      var pm = /^\s*Permission\s*:\s*(.+?)\s*$/im.exec(blk);
      if (!tm || !pm) return;
      var ttm = /^\s*TrusteeType\s*:\s*(.+?)\s*$/im.exec(blk);
      entries.push({ trustee: tm[1].trim(), trusteeType: ttm ? ttm[1].trim() : '', permission: pm[1].trim() });
    });
    if (!entries.length) {
      var lines = String(text || '').split(/\r?\n/);
      for (var i = 0; i < lines.length - 1; i++) {
        if (!/^\s*Trustee\s+TrusteeType\s+Permission\b/i.test(lines[i]) || !/^\s*-+(?:\s+-+)+\s*$/.test(lines[i + 1])) continue;
        var spans = [], dm, dRe = /-+/g;
        while ((dm = dRe.exec(lines[i + 1])) !== null) spans.push(dm.index);
        if (spans.length < 3) continue;
        for (var r = i + 2; r < lines.length; r++) {
          var rl = lines[r];
          if (!rl.trim() || /^\s*(?:PS\s+[A-Za-z]:\\|\*Evil-WinRM\*)/i.test(rl)) break;
          var trCell = rl.slice(spans[0], spans[1]).trim();
          var ttCell = rl.slice(spans[1], spans[2]).trim();
          var prCell = rl.slice(spans[2], spans.length > 3 ? spans[3] : rl.length).trim();
          if (!/^Gpo/i.test(prCell)) {
            var fbM = /^\s*(.+?)\s+(User|Group|WellKnownGroup|Computer|Unknown)\s+(Gpo[A-Za-z]+)(?:\s+(?:True|False))?\s*$/i.exec(rl);
            if (fbM) { trCell = fbM[1].trim(); ttCell = fbM[2].trim(); prCell = fbM[3].trim(); }
          }
          if (trCell && prCell) entries.push({ trustee: trCell, trusteeType: ttCell, permission: prCell });
        }
        break;
      }
    }
    entries.forEach(function (e) {
      if (!_GP_WRITABLE_PERM_RE.test(e.permission)) return;
      if (_is_builtin_gp_trustee(e.trustee)) return;
      var cleanTr = _normalize_trustee(e.trustee);
      var val = { trustee: cleanTr, principals: [cleanTr], permission: e.permission, method: 'get-gppermission' };
      if (e.trusteeType) val.trustee_type = e.trusteeType;
      if (gpoName) val.gpo = gpoName;
      if (gpoGuid) val.gpo_id = gpoGuid;
      _add(facts, mkFact('ad.gpo_writable', scope, val, S, source));
    });
  }
  C._parse_gp_permission = _parse_gp_permission;

  var _AD_ABUSE_CONTENT_RE = /DACL modified successfully|OwnerSid modified successfully|Password changed successfully!|\[\+\]\s+\S+\s+added to\s+\S+|\[\*\]\s+Action:\s*Ask\s+TGT|TGT request successful!|Service ticket successfully requested|Saving ticket in\s+\S+\.ccache|DeviceKey\s*:|KeyCredential\s+added|Trustee\s*:\s*[^\r\n]+[\s\S]{1,180}?Permission\s*:\s*Gpo(?:EditDeleteModifySecurity|Custom)\b/i;
  function _parse_ad_abuse_output(actionId, text, ws, command, source, facts) {
    if (!(_is_ad_abuse_command(command) || C._AD_ABUSE_ACTION_IDS.has(actionId) || _AD_ABUSE_CONTENT_RE.test(text || ''))) return;
    _parse_ad_control_paths(text, ws, command, source, facts);
    _parse_bloodyad_writable(text, ws, command, source, facts);
    _parse_bloodyad_domain_control(text, ws, command, source, facts);
    _parse_gp_permission(text, ws, command, source, facts);
    _parse_added_computer(text, ws, command, source, facts);
    _parse_kerberos_ticket_material(text, ws, command, source, facts);
    _parse_gmsa_material(text, ws, command, source, facts);
    _parse_laps_material(text, ws, command, source, facts);
  }
  C._parse_ad_abuse_output = _parse_ad_abuse_output;

  var _KLIST_CACHED_RE = /Cached Tickets:\s*\((?<n>\d+)\)/i;
  var _KLIST_CLIENT_RE = /^\s*(?:#\d+>\s*)?Client:\s*(?<user>\S+)\s*@\s*(?<realm>\S+)/im;
  var _KLIST_SERVER_RE = /^\s*Server:\s*(?<spn>\S+)\s*@\s*(?<realm>\S+)/im;
  var _KLIST_DEFAULT_PRINCIPAL_RE = /Default principal:\s*(?<user>[^@\s]+)(?:@(?<realm>\S+))?/i;

  function _looks_like_klist(text) {
    var t = text || '';
    if (reSearch(_KLIST_CACHED_RE, t)) return true;
    if (/^\s*Server:\s*krbtgt\//im.test(t)) return true;
    if (reSearch(_KLIST_DEFAULT_PRINCIPAL_RE, t) && /krbtgt\//i.test(t)) return true;
    return false;
  }
  C._looks_like_klist = _looks_like_klist;

  function _parse_klist(text, ws, command, source, facts) {
    if (!text || !text.trim()) return;
    text = text.replace(C._ANSI_RE, '');
    if (!_looks_like_klist(text)) return;
    var value = { tool: 'klist' }, realm = '';
    var cm = reSearch(_KLIST_CLIENT_RE, text) || reSearch(_KLIST_DEFAULT_PRINCIPAL_RE, text);
    if (cm) {
      var u = C._clean_username(cm.groups.user || '');
      if (u) value.principal = u;
      if (cm.groups.realm) realm = cm.groups.realm.toLowerCase().replace(/\.$/, '');
    }
    var cnt = reSearch(_KLIST_CACHED_RE, text);
    if (cnt) value.count = parseInt(cnt.groups.n, 10);
    var servers = C.uniqueSortedCI(reAll(_KLIST_SERVER_RE, text).map(function (m) { return m.groups.spn; }));
    if (servers.length) value.services = servers.slice(0, 20);
    if (/krbtgt\//i.test(text)) value.tgt = true;
    _add(facts, mkFact('kerberos.tickets', C._scope_for_domain(ws, realm), value, S, source));
  }
  C._parse_klist = _parse_klist;

  function _parse_domain_trusts(text, ws, source, facts) {
    if (!text) return;
    var low = text.toLowerCase();
    var trustWord = /domain_trusts|list of domain trusts|trustdirection|trustattributes|forest tree root|trusted domain|get-domaintrust|get-adtrust/.test(low) ||
      (/\btrust\b/.test(low) && /\b(bidirectional|inbound|outbound|one-way|two-way|forest_transitive|within_forest)\b/.test(low));
    var names = {}, order = [];
    function add(d) { if (!d) return; d = d.toLowerCase().replace(/[.,]$/, ''); if (!names[d] && /\.[a-z]{2,}$/.test(d)) { names[d] = 1; order.push(d); } }
    reAll(/^\s*\d+:\s+\S+\s+([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/gm, text).forEach(function (m) { add(m[1]); });
    reAll(/\b(?:TargetName|Target|SourceName)\s*:\s*([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/gi, text).forEach(function (m) { add(m[1]); });
    reAll(/->\s*([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})/g, text).forEach(function (m) { add(m[1]); });
    if (!trustWord && !order.length) return;
    _add(facts, mkFact('ad.trusts', C._scope_for_domain(ws), { count: order.length, domains: order.slice(0, 20) }, S, source));
  }
  C._parse_domain_trusts = _parse_domain_trusts;

  function _parse_zerologon_scan(text, ws, source, facts) {
    if (!text) return;
    var low = text.toLowerCase();
    if (!/zerologon|cve-2020-1472|netlogon/.test(low)) return;
    var hasExplicitSuccess = /success!|is vulnerable|target vulnerable|can be fully compromised|exploitable|performing attack[^\r\n]*success/i.test(low);
    if (!hasExplicitSuccess && /not vulnerable|target is patched|is not vulnerable|attack failed|exploit failed|patched!|STATUS_ACCESS_DENIED/i.test(text)) return;
    if (hasExplicitSuccess && !/\bis not vulnerable\b|\bnot vulnerable\b/i.test(text)) {
      _add(facts, mkFact('ad.zerologon', C._scope_for_domain(ws), { cve: 'CVE-2020-1472', vulnerable: true }, S, source));
    }
  }
  C._parse_zerologon_scan = _parse_zerologon_scan;

  var _ESC_RE = /\bESC(?:1[0-6]|[1-9])\b/g;
  function _parse_adcs(text, ws, command, source, facts) {
    if (!text) return;
    var escs = {}, order = [], m;
    _ESC_RE.lastIndex = 0;
    while ((m = _ESC_RE.exec(text)) !== null) { var e = m[0].toUpperCase(); if (!escs[e]) { escs[e] = 1; order.push(e); } }
    var hasEnrolleeSubject = /Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|msPKI-Certificate-Name-Flag\s*:\s*[^\r\n]*ENROLLEE_SUPPLIES_SUBJECT/i.test(text);
    var hasEditfSan = /EDITF_ATTRIBUTESUBJECTALTNAME2/i.test(text);
    var hasCra = /Certificate Request Agent/i.test(text) && /(?:Template Name|Enrollment Rights)/i.test(text);
    var hasAnyPurpose = /\bAny Purpose\b/i.test(text) && /(?:Template Name|Enrollment Rights)/i.test(text);
    var mcaM = /^\s*(?:ManageCertificates|ManageCA)\s*:\s*([^\r\n]+)/im.exec(text);
    var hasEsc7Perm = !!(mcaM && !/^(?:BUILTIN\\Administrators|[^\\\r\n]+\\(?:Domain Admins|Enterprise Admins|Administrators))\s*$/i.test(mcaM[1].trim()));
    if (hasEnrolleeSubject && !escs.ESC1) { escs.ESC1 = 1; order.push('ESC1'); }
    if (hasAnyPurpose && !escs.ESC2) { escs.ESC2 = 1; order.push('ESC2'); }
    if (hasCra && !escs.ESC3) { escs.ESC3 = 1; order.push('ESC3'); }
    if (hasEditfSan && !escs.ESC6) { escs.ESC6 = 1; order.push('ESC6'); }
    if (hasEsc7Perm && !escs.ESC7) { escs.ESC7 = 1; order.push('ESC7'); }
    var noVulnTemplates = /\b(?:no|0)\s+vulnerable\s+(?:certificates?\s+)?templates?\b|\bnot\s+vulnerable\b/i.test(text);
    var vulnWord = ((/\[!\]\s*vulnerabilit|is vulnerable to|vulnerable (?:certificates? )?templates|ESC\d/i.test(text) && !noVulnTemplates) || hasEnrolleeSubject || hasEditfSan || hasEsc7Perm);
    if (order.length || vulnWord) {
      var cas = C.uniqueSortedCI(reAll(/\b(?:CA Name|Enterprise CA Name)["']?\s*:\s*["']?([^\n\r"',]{1,64})/gi, text).map(function (x) { return (x[1] || '').trim(); }).filter(Boolean));
      var sections = text.split(/(?=\bTemplate Name["']?\s*:)/i);
      var vulnTmpls = [];
      if (sections.length > 2) {
        sections.forEach(function (sec) {
          if (/ESC(?:1[0-6]|[1-9])\b|\[!\]\s*vulnerabilit|is vulnerable to|Enrollee\s*Supplies\s*Subject["']?\s*:\s*(?:True|true)|ENROLLEE_SUPPLIES_SUBJECT|Certificate Request Agent|Any Purpose/i.test(sec)) {
            reAll(/\b(?:Template Name|Template)["']?\s*:\s*["']?([^\n\r"',]{1,64})/gi, sec).forEach(function (x) {
              var tn = (x[1] || '').trim();
              if (tn) vulnTmpls.push(tn);
            });
          }
        });
      }
      var tmpls = vulnTmpls.length
        ? C.uniqueSortedCI(vulnTmpls)
        : C.uniqueSortedCI(reAll(/\b(?:Template Name|Template)["']?\s*:\s*["']?([^\n\r"',]{1,64})/gi, text).map(function (x) { return (x[1] || '').trim(); }).filter(Boolean));
      var adcsVal = { esc: order.slice(0, 16), templates: tmpls.slice(0, 200) };
      if (cas.length) { adcsVal.ca = cas[0]; adcsVal.cas = cas.slice(0, 100); }
      _add(facts, mkFact('adcs.vulnerable', C._scope_for_domain(ws), adcsVal, S, source));
    }
    var pfx = reSearch(/Saved (?:certificate and private key|PFX)[^\n]*?(?:to|at)\s*'?([^\s'"]+\.pfx)'?/i, text) ||
      reSearch(/(?:^|[\s'"])([A-Za-z0-9_.-]{1,120}\.pfx)'?[ \t]*(?:saved|written)/i, text) ||
      reSearch(/\[\*\]\s*Writing (?:private key|certificate[^\r\n]*)\s+to\s+'([^']+)'/i, text);
    if (pfx) {
      _add(facts, mkFact('credential.certificate', C._scope_for_domain(ws), { pfx: pfx[1], files: [pfx[1]], via: /pywhisker/i.test(command) ? 'shadow-credentials' : 'adcs' }, S, source));
    } else if (/\[\*\]\s*Successfully requested certificate\b/i.test(text)) {
      var upnM = /Got certificate with UPN\s+'([^']+)'/i.exec(text) || /(?:^|\s)-upn\s+['"]?([^\s'"]+)/i.exec(command || '');
      var certFile = upnM ? (upnM[1].split('@')[0].toLowerCase() + '.pfx') : 'requested.pfx';
      _add(facts, mkFact('credential.certificate', C._scope_for_domain(ws), { pfx: certFile, files: [certFile], via: 'adcs' }, S, source));
    }
    var modM = /\[\*\]\s*Successfully (?:updated|added officer|enabled|issued certificate)(?:\s+for|\s+template)?\s*(?:'([^']+)')?/i.exec(text);
    if (!modM && /\[\*\]\s*Updating certificate template\s*(?:'([^']+)')?/i.test(text) && !/\b(?:error|denied|insufficient|failed)\b/i.test(text)) {
      modM = /\[\*\]\s*Updating certificate template\s*(?:'([^']+)')?/i.exec(text);
    }
    if (modM) {
      _add(facts, mkFact('ad.control_paths', C._scope_for_domain(ws), { right: 'ADCSModify', target: modM[1] || 'adcs', method: 'certipy' }, S, source));
    }
  }
  C._parse_adcs = _parse_adcs;

  // --- certipy auth: a PKINIT/cert auth that returns the account's NT hash (and a usable credential). ---
  var _CERT_HASH_RE = /(?:Got|NT)\s+hash\s+for\s+'?([^:'"\n]+)'?\s*:\s*(?:[a-f0-9]{32}:)?([a-f0-9]{32})/i;
  function _parse_certipy_auth(text, ws, command, source, facts) {
    if (!text) return;
    var hm = reSearch(_CERT_HASH_RE, text);
    if (hm) {
      var rawUser = (hm[1] || '').trim();
      var cleanUser = rawUser.replace(/@.*$/, '').replace(/^[^\\]+\\/, '');
      var nthash = (hm[2] || '').toLowerCase();
      var domain = rawUser.indexOf('@') >= 0 ? rawUser.split('@')[1] : (rawUser.indexOf('\\') >= 0 ? rawUser.split('\\')[0] : ((ws && ws.domainSeed) || ''));
      _add(facts, mkFact('hash.ntlm', C._scope_for_domain(ws, domain), { nthash: nthash, user: cleanUser, via: 'certipy-auth' }, S, source));
      _add(facts, mkFact('credential.available', C._scope_for_domain(ws, domain), { user: cleanUser, nthash: nthash, domain: domain, kind: 'cert_auth_nt_hash', via: 'certipy-auth' }, S, source));
      if (/^administrator$/i.test(cleanUser) && (/-pfx\b/i.test(command || '') || /Got TGT|Saved credential cache|Trying to get TGT|Using principal/i.test(text))) {
        _add(facts, mkFact('access.admin', 'host:' + ws.target, { user: cleanUser, domain: domain, via: 'certipy-auth' }, S, source));
      }
      // A recovered account hash does not establish administrative authorization.
    } else if (/Got TGT|Saved credential cache|\.ccache/i.test(text)) {
      _add(facts, mkFact('credential.available', C._scope_for_domain(ws), { kind: 'cert_auth_tgt', via: 'certipy-auth' }, S, source));
      if (/\badministrator\b/i.test(text + ' ' + (command || ''))) {
        _add(facts, mkFact('access.admin', 'host:' + ws.target, { user: 'Administrator', via: 'certipy-auth' }, S, source));
      }
    }
  }

  C._parse_certipy_auth = _parse_certipy_auth;

  // --- late-game AD recording facts (the move already lands the access; these record the specific
  //     primitive for the report and the map's parser lens). All content-gated on a success marker. ---
  function _parse_lateral_movement(text, ws, source, facts) {
    if (/nt authority\\system|Microsoft Windows \[Version|^[A-Z]:\\[^\n]*>|\bpwned\b|Access granted/i.test(text)) {
      _add(facts, mkFact('lateral.movement', C._scope_for_domain(ws), { via: /rubeus|ptt|ticket/i.test(text) ? 'ticket-reuse' : 'lateral-exec' }, S, source));
    }
  }
  C._parse_lateral_movement = _parse_lateral_movement;

  function _parse_coerced_auth(text, ws, source, facts) {
    if (/received connection|smb.*ntlmv2|attack worked|triggered|rpc.*success|\[\+\].*(?:coerc|petitpotam|printerbug|dfscoerce)/i.test(text)) {
      _add(facts, mkFact('ad.coerced_auth', C._scope_for_domain(ws), { note: 'authentication coerced from the target' }, S, source));
    }
  }
  C._parse_coerced_auth = _parse_coerced_auth;

  function _parse_gpo_control(text, ws, source, facts) {
    if (/version(?:Number)? (?:updated|incremented)|scheduled task created|immediate task|gPCMachineExtensionNames|GPO .* modified|\[\+\].*gpo/i.test(text)) {
      _add(facts, mkFact('ad.gpo_control', C._scope_for_domain(ws), { note: 'a writable GPO was modified' }, S, source));
    }
  }
  C._parse_gpo_control = _parse_gpo_control;

  function _parse_sid_history(text, ws, source, facts) {
    if (/ExtraSids|sid-?history|SID History (?:added|injected)|-extra-sid/i.test(text)) {
      _add(facts, mkFact('ad.sid_history', C._scope_for_domain(ws), { note: 'SID history abused for cross-domain privilege' }, S, source));
    }
  }
  C._parse_sid_history = _parse_sid_history;

  // LAPS read: a recovered local-admin password from ms-MCS-AdmPwd (legacy LAPS)
  // or msLAPS-Password (Windows LAPS). Grounded in the NetExec source and real
  // domain controller output. SUCCESS shapes:
  //   - nxc -M laps highlight: "Computer:<name> User:<user> Password:<cleartext>"
  //     (NetExec nxc/modules/laps.py: f"Computer:{sAMAccountName} User:{user:<15} Password:{password}")
  //   - ldapsearch / Get-ADComputer: "ms-MCS-AdmPwd: <cleartext>" (single or ::base64)
  //   - Windows LAPS v2 cleartext JSON blob: {"n":..., "p":"<cleartext>"}
  // MUST NOT mint on the real failures (verified against live DC output):
  //   "No result found with attribute ms-MCS-AdmPwd or msLAPS-Password !"  (no colon+value)
  //   "Module LAPS is not supported for protocol smb"
  //   "LDAP connection failed with account ..."
  //   Get-ADComputer usage error: "Cannot find an object with identity: 'ms-Mcs-AdmPwd'"
  // Each guard works because the attribute name here is NOT immediately followed
  // by a colon-and-value, so the value-bearing regexes below never fire on them.
  var _LAPS_NXC_RE = /^.*?Computer:\s*(?<comp>\S+)\s+User:\s*(?<user>\S*)\s+Password:\s*(?<pw>\S.*?)\s*$/im;
  var _LAPS_ATTR_RE = /\bms-?MCS-AdmPwd\b\s*:{1,2}\s*(?<pw>\S[^\r\n]*)/i;
  var _LAPS_V2_RE = /msLAPS-Password\b[\s\S]{0,240}?"p"\s*:\s*"(?<pw>[^"]+)"/i;

  function _parse_laps(text, ws, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target, hit = null;
    var m = reSearch(_LAPS_NXC_RE, text);
    if (m && m.groups.pw) hit = { computer: (m.groups.comp || '').replace(/\$$/, ''), user: m.groups.user || '', password: m.groups.pw.trim(), via: 'nxc-laps' };
    if (!hit) { m = reSearch(_LAPS_V2_RE, text); if (m && m.groups.pw) hit = { password: m.groups.pw.trim(), via: 'mslaps-v2' }; }
    if (!hit) { m = reSearch(_LAPS_ATTR_RE, text); if (m && m.groups.pw && !/^\s*or\b/i.test(m.groups.pw)) hit = { password: m.groups.pw.trim(), via: 'ms-mcs-admpwd' }; }
    if (!hit) return;
    _add(facts, mkFact('ad.laps_lead', h, hit, S, source));
    _add(facts, mkFact('ad.laps', h, hit, S, source));
    // A found cleartext is a candidate, not auto-validated (same rule as any dumped plaintext).
    _add(facts, mkFact('credential.candidate', h, { kind: 'laps_local_admin', user: hit.user || 'Administrator', password: hit.password, computer: hit.computer, via: 'laps' }, S, source));
  }
  C._parse_laps = _parse_laps;

  function _parse_rpcdump(text, ws, command, source, facts) {
    if (!text) return;
    var h = 'host:' + ws.target;
    var protocols = [], pipes = [], seenP = {}, seenPipe = {};
    reAll(/^\s*Protocol:\s*(\[MS-[A-Z0-9-]+\]):\s*([^\r\n]+)/gim, text).forEach(function (m) {
      var p = m[1].toUpperCase();
      if (!seenP[p]) { seenP[p] = 1; protocols.push(p); }
    });
    reAll(/ncacn_np:[^\s\[\r\n]+\[\\pipe\\([A-Za-z0-9_.-]+)\]/gi, text).forEach(function (m) {
      var pp = m[1];
      if (!seenPipe[pp.toLowerCase()]) { seenPipe[pp.toLowerCase()] = 1; pipes.push(pp); }
    });
    var epCountM = /\[\*\]\s*Received\s+(\d+)\s+endpoints/i.exec(text);
    if (!protocols.length && !pipes.length && !epCountM) return;
    var count = epCountM ? parseInt(epCountM[1], 10) : (protocols.length || pipes.length);
    if (C._add_os_observation) {
      C._add_os_observation(facts, ws, source, 'windows', 'MS-RPC endpoint mapper (' + count + ' endpoints)', 'high', 'rpcdump', true);
    }
    _add(facts, mkFact('rpc.endpoints', h, { count: count, protocols: protocols.slice(0, 30), pipes: pipes.slice(0, 20), tool: 'rpcdump' }, S, source));
    if (seenP['[MS-DRSR]'] || seenP['[MS-ADTS]'] || /ntdsapi/i.test(text)) {
      _add(facts, mkFact('ad.dc_candidate', h, { host: ws.target, via: 'rpcdump' }, S, source));
    }
  }
  C._parse_rpcdump = _parse_rpcdump;

})(typeof globalThis !== 'undefined' ? globalThis : this);
