/*!
 * OBOL resolved context. Selection is a material reference, never proof of access.
 * Target identity, authentication identity, and service remain separate.
 */
(function (root) {
  'use strict';
  var O = root.OBOL = root.OBOL || {}, pins = Object.create(null);
  function clean(v) { return String(v == null ? '' : v).trim(); }
  function lower(v) { return clean(v).toLowerCase().replace(/\.$/, ''); }
  function owns(o, k) { return Object.prototype.hasOwnProperty.call(o || {}, k); }
  function list(fs) { return Array.isArray(fs) ? fs : (fs && fs.facts) || []; }
  function digest(text) {
    if (O.facts && O.facts.fingerprint) return O.facts.fingerprint(text);
    var a = 2166136261, b = 5381;
    for (var i = 0; i < text.length; i++) { a = Math.imul(a ^ text.charCodeAt(i), 16777619); b = Math.imul(b, 33) ^ text.charCodeAt(i); }
    return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
  }
  function material(raw, scope) {
    raw = raw || {};
    var user = clean(raw.user || raw.username), domain = clean(raw.domain || raw.realm);
    if (user.indexOf('\\') >= 0) { var up = user.split('\\'); domain = domain || up.shift(); user = up.join('\\'); }
    if (user.indexOf('@') > 0 && !domain) { domain = user.slice(user.indexOf('@') + 1); user = user.slice(0, user.indexOf('@')); }
    var password = raw.password != null ? String(raw.password) : raw.secret != null ? String(raw.secret) : '';
    var nthash = clean(raw.nthash || raw.hash), type = clean(raw.secretType || raw.secret_type || raw.type).toUpperCase();
    if (/^(NT|NTHASH|NTLM)$/.test(type) && !nthash) { nthash = password; password = ''; }
    var accountType = raw.accountType || (raw.local ? 'local' : domain ? 'domain' : 'unknown');
    var rawScope = clean(scope || raw.scope || '');
    var originHost = clean(raw.originHost || raw.reuseFrom || (/^host:/i.test(rawScope) && lower(rawScope) !== 'host:target' ? rawScope.slice(5) : ''));
    var binding = clean(raw.targetBinding || raw.computer || (accountType === 'local' ? raw.host || raw.target : ''));
    if (accountType === 'local' && !binding) binding = originHost || (/^host:/.test(scope || '') ? scope.slice(5) : '');
    var key = JSON.stringify([lower(user), lower(domain), password, lower(nthash), accountType, lower(binding)]);
    var fingerprint = O.facts && O.facts.fingerprint ? O.facts.fingerprint(JSON.stringify([lower(domain),lower(user),nthash ? 'nthash' : 'password',String(nthash || password)])) : digest(key);
    return { id: 'cred-' + digest(key), credentialFingerprint:fingerprint, user: user, principal: domain ? domain + '\\' + user : user,
      domain: domain, realm: domain, password: password, secret: password, nthash: nthash,
      type: nthash && !password ? 'NT' : password ? 'PW' : type || '?', secretType: nthash && !password ? 'NT' : password ? 'PW' : type || 'USER',
      scope: scope || raw.scope || '', originHost: originHost, reuseFrom: clean(raw.reuseFrom || ''),
      unvalidatedOnTarget: !!raw.unvalidatedOnTarget, targetBinding: binding, computer: raw.computer || '', accountType: accountType,
      source: raw.source || 'recovered', sourceId: raw.id || '', method: raw.method || raw.via || '' };
  }
  function credentials(eng) {
    eng = eng || {}; var found = [], seen = Object.create(null);
    function add(raw, scope) {
      var c = material(raw, scope); if (raw.unresolved || !c.user || (!c.password && !c.nthash && c.secretType !== 'USER')) return;
      if (seen[c.id]) {
        if (!seen[c.id].scope && c.scope && !(raw && raw.unvalidatedOnTarget)) seen[c.id].scope = c.scope;
        if (!seen[c.id].originHost && c.originHost) seen[c.id].originHost = c.originHost;
        if (!seen[c.id].method && c.method) seen[c.id].method = c.method;
        if (!seen[c.id].targetBinding && c.targetBinding) seen[c.id].targetBinding = c.targetBinding;
        return;
      }
      seen[c.id] = c; found.push(c);
    }
    (eng.credentials || []).forEach(function (c) { add(c, c.scope); });
    list(eng.facts).forEach(function (f) {
      if (f && f.state === 'supported' && /^credential\.(available|plaintext|ntlm_hash)$/.test(f.kind)) {
        var v = Object.assign({}, f.value || {});
        if (!v.domain && /^domain:/.test(f.scope || '') && f.scope !== 'domain:domain' && v.accountType !== 'local') v.domain = f.scope.slice(7);
        add(v, f.scope);
      }
    });
    return found;
  }
  function shape(eng) {
    if (!eng) return { version: 1, byTarget: {}, targetDomains: {}, anonymousByTarget: {} };
    if (!eng.contextSelections || eng.contextSelections.version !== 1) eng.contextSelections = { version: 1, byTarget: {}, targetDomains: {} };
    var s = eng.contextSelections; s.byTarget = s.byTarget || {}; s.targetDomains = s.targetDomains || {};
    return s;
  }
  function identityParams(p) { return JSON.stringify([p && p.username || p && p.user || '', p && p.password || '', p && p.nthash || '', p && p.authRealm || '']); }
  function rememberMaterial(eng, p, target) {
    if (!p || !(p.username || p.user)) return null;
    var candidates = credentials(eng), known = candidates.find(function (x) { return x.id === p.credentialId; });
    if (known && lower(known.user) === lower(p.username || p.user) && known.password === (p.password || '') && lower(known.nthash) === lower(p.nthash || '') && lower(known.domain) === lower(owns(p,'authRealm') ? p.authRealm : known.domain)) return known.id;
    var ambiguous = (eng.credentials || []).filter(function(x){return x.unresolved;}).concat(list(eng.facts).filter(function(f){return f.kind === 'credential.candidate' && (f.value || {}).association === 'unresolved';}).map(function(f){return f.value;}));
    if (ambiguous.some(function(x) {
      var v = material(x, x.scope), username = lower(p.username || p.user);
      return (!v.user || lower(v.user) === username) && ((v.password && v.password === p.password) || (v.nthash && lower(v.nthash) === lower(p.nthash)));
    })) return null;
    var c = material({ user: p.username || p.user, domain: owns(p,'authRealm') ? p.authRealm : p.domain || '', password: p.password || '', nthash: p.nthash || '',
      accountType:known && known.accountType, targetBinding:known && known.targetBinding, computer:known && known.computer });
    var exact = candidates.find(function (x) { return x.id === c.id; });
    if (exact) return exact.id;
    eng.credentials = eng.credentials || [];
    eng.credentials.push({ id: c.id, user: c.user, domain: c.domain, secret: c.password, nthash: c.nthash,
      secretType: c.secretType, source: 'configured', scope: target ? 'host:' + target : '', accountType:c.accountType,targetBinding:c.targetBinding,computer:c.computer });
    return c.id;
  }
  function normalize(eng) {
    if (!eng) return eng;
    var legacy = !eng.contextSelections || eng.contextSelections.version !== 1, s = shape(eng), p = eng.params || {}, target = clean(eng.activeTarget || p.target);
    if (legacy && target) {
      s.byTarget[target] = rememberMaterial(eng, p, target);
      if (p.domain) s.targetDomains[target] = p.domain;
      s.legacyAssociation = 'Only the saved active target was associated. Other legacy associations remain unresolved.';
      if (!s.byTarget[target] && (p.username || p.password || p.nthash)) s.unresolvedLegacyParams = Object.assign({}, p);
      applySelection(eng, target);
    }
    return eng;
  }
  function pin(eng) { return eng && owns(pins, eng.id) ? pins[eng.id] : undefined; }
  function selectedId(eng, target) {
    if (!eng) return undefined;
    normalize(eng);
    target = clean(target || eng.activeTarget || (eng.params || {}).target);
    var pinned = pin(eng);
    return pinned !== undefined ? pinned : shape(eng).byTarget[target];
  }
  function applySelection(eng, target) {
    if (!eng) return;
    target = clean(target || eng.activeTarget || (eng.params || {}).target);
    var p = eng.params = eng.params || {}, id = selectedId(eng, target), c = credentials(eng).find(function (x) { return x.id === id; });
    p.username = c ? c.user : ''; p.user = c ? c.user : ''; p.password = c ? c.password : ''; p.nthash = c ? c.nthash : ''; p.authRealm = c ? c.domain : '';
    var td = shape(eng).targetDomains[target];
    var tg = (eng.targets || []).find(function (t) { return (t.ip || t.id) === target; });
    p.domain = td || (tg && tg.domain) || '';
    p.credentialId = c ? c.id : '';
  }
  function select(eng, id, target) {
    normalize(eng); target = clean(target || eng.activeTarget || (eng.params || {}).target);
    if (id != null && !credentials(eng).some(function (c) { return c.id === id; })) throw new Error('Credential selection is no longer available');
    var active = clean((eng.params || {}).target || eng.activeTarget);
    var selections = shape(eng); selections.anonymousByTarget = selections.anonymousByTarget || {};
    if (id == null) selections.anonymousByTarget[target] = true; else delete selections.anonymousByTarget[target];
    if (pin(eng) !== undefined && target === active) pins[eng.id] = id; else shape(eng).byTarget[target] = id;
    if (target === active) applySelection(eng, target);
    return id;
  }
  function setPin(eng, enabled) {
    normalize(eng); var target = clean(eng.activeTarget || (eng.params || {}).target);
    if (enabled) pins[eng.id] = selectedId(eng, target) || null; else delete pins[eng.id];
    applySelection(eng, target);
  }
  function beforeUpdate(eng) { normalize(eng); return { target: clean((eng.params || {}).target), params: Object.assign({}, eng.params || {}) }; }
  function reconcile(eng, before) {
    if (!before) return normalize(eng);
    var p = eng.params || {}, target = clean(p.target), s = shape(eng), changed = identityParams(p) !== identityParams(before.params);
    if (target !== before.target) {
      if (p.domain && p.domain !== before.params.domain) s.targetDomains[target] = p.domain;
      if (changed) s.byTarget[target] = rememberMaterial(eng, p, target);
      if (!owns(s.byTarget, target)) s.byTarget[target] = null;
      applySelection(eng, target);
    } else if (changed) {
      if ((p.username || p.user) !== (before.params.username || before.params.user) && p.password === before.params.password && p.nthash === before.params.nthash && p.credentialId === before.params.credentialId) { p.password = ''; p.nthash = ''; }
      if (p.password !== before.params.password && p.nthash === before.params.nthash) p.nthash = '';
      else if (p.nthash !== before.params.nthash && p.password === before.params.password) p.password = '';
      var id = rememberMaterial(eng, p, target);
      if (pin(eng) !== undefined) pins[eng.id] = id; else s.byTarget[target] = id;
      p.credentialId = id || '';
    }
    if (p.domain !== before.params.domain && target === before.target) s.targetDomains[target] = p.domain || '';
  }
  function serviceOf(command, explicit) {
    if (explicit) return lower(explicit);
    var c = lower(command), nx = c.match(/\b(?:nxc|netexec|crackmapexec)\s+(smb|ldap|winrm|ssh|rdp|mssql|ftp)\b/);
    if (nx) return nx[1];
    if (/\b(?:ldapsearch|windapsearch|bloodyad)\b/.test(c)) return 'ldap';
    if (/\b(?:smbclient|smbmap|rpcclient)\b/.test(c)) return 'smb';
    if (/\bevil-winrm\b/.test(c)) return 'winrm';
    if (/\b(?:ssh|scp)\b/.test(c)) return 'ssh';
    if (/\b(?:curl|wget|ffuf|gobuster|feroxbuster)\b/.test(c)) return 'http';
    return '';
  }
  var DIR_METADATA_FACT_RE = /^ad\.(?:domain_known|base_dn|domain_sid|trusts)$/;
  function hasConflictingNonAdEvidence(hostFacts, targetObj) {
    if (targetObj) {
      if (targetObj.os && /\b(?:linux|unix|ubuntu|debian|centos|freebsd|openbsd|netbsd)\b/i.test(String(targetObj.os))) return true;
      var tDom = clean(targetObj.domain);
      if (tDom && (lower(tDom) === 'workgroup' || tDom.indexOf('.') < 0)) return true;
    }
    var hasWinOrAd = false, hasLin = false, hasWg = false;
    for (var i = 0; i < hostFacts.length; i++) {
      var f = hostFacts[i];
      if (!f || f.state !== 'supported') continue;
      var v = f.value || {};
      if (/^(?:foothold\.windows|os\.windows|ad\.dc_candidate|ad\.domain_known|(?:kerberos|ldap|winrm|rdp|mssql)\.reachable|port:(?:88|389|636|3268|3269|5985|5986))$/.test(f.kind)) hasWinOrAd = true;
      if ((f.kind === 'host.os_family' || f.kind === 'host.os_hint' || f.kind === 'host.os') && /windows/i.test(String(v.family || v.os || ''))) hasWinOrAd = true;
      if (/^(?:foothold\.linux|os\.linux)$/.test(f.kind)) hasLin = true;
      if ((f.kind === 'host.os_family' || f.kind === 'host.os_hint' || f.kind === 'host.os') && /\b(?:linux|unix|ubuntu|debian|centos|freebsd|openbsd|netbsd)\b/i.test(String(v.family || v.os || ''))) hasLin = true;
      if (f.kind === 'smb.signing' && v.workgroup === true) hasWg = true;
      if (f.kind === 'host.domain') {
        var hd = clean(v.domain || v.name);
        if (hd && (lower(hd) === 'workgroup' || hd.indexOf('.') < 0)) hasWg = true;
      }
    }
    return hasWg || (hasLin && !hasWinOrAd);
  }
  function cleanAdDom(v) {
    return lower(String(v == null ? '' : v).trim().replace(/0\.$/, ''));
  }
  function uniqueProvenAdDomains(allFacts) {
    var seen = Object.create(null), out = [];
    list(allFacts).forEach(function (f) {
      if (!f || f.state !== 'supported' || f.kind !== 'ad.domain_known') return;
      var sc = clean(f.scope);
      var raw = clean(((f.value || {}).name || (f.value || {}).domain || (/^domain:/i.test(sc) ? sc.slice(7) : ''))).replace(/0\.$/, '').replace(/\.$/, '');
      var key = lower(raw);
      if (!key || key === 'domain' || key === 'workgroup' || key.indexOf('.') < 0 || seen[key]) return;
      seen[key] = 1;
      out.push(raw);
    });
    return out;
  }
  function projectDirMetadataFacts(allFacts, domainName) {
    var domKey = cleanAdDom(domainName);
    if (!domKey || domKey === 'domain' || domKey === 'workgroup' || domKey.indexOf('.') < 0) return [];
    var all = list(allFacts), hostDom = Object.create(null);
    all.forEach(function (f) {
      if (!f || f.state !== 'supported' || f.kind !== 'ad.domain_known' || !/^host:/i.test(f.scope || '')) return;
      var d = cleanAdDom((f.value || {}).domain || (f.value || {}).name);
      if (d && d.indexOf('.') > 0) hostDom[lower(f.scope)] = d;
    });
    var out = [];
    all.forEach(function (f) {
      if (!f || f.state !== 'supported' || !DIR_METADATA_FACT_RE.test(f.kind || '')) return;
      var sc = clean(f.scope), v = f.value || {}, fDom = '';
      if (/^domain:/i.test(sc)) fDom = cleanAdDom(sc.slice(7));
      if (!fDom || fDom === 'domain') fDom = cleanAdDom(v.domain || v.name);
      if (!fDom && f.kind === 'ad.base_dn' && (v.basedn || v.dn)) {
        var dcs = [], m, re = /\bDC=([A-Za-z0-9-]+)/gi, bdn = String(v.basedn || v.dn);
        while ((m = re.exec(bdn))) dcs.push(m[1].toLowerCase());
        if (dcs.length >= 2) fDom = dcs.join('.');
      }
      if (!fDom && /^host:/i.test(sc)) fDom = hostDom[lower(sc)] || '';
      if (fDom !== domKey) return;
      if (/^domain:/i.test(sc)) {
        out.push(f);
      } else if (O.facts && O.facts.makeFact) {
        out.push(O.facts.makeFact({ kind: f.kind, scope: 'domain:' + domKey, state: 'supported', source: f.source || 'domain-metadata', value: v }));
      } else {
        out.push(Object.assign({}, f, { scope: 'domain:' + domKey }));
      }
    });
    return out;
  }
  function targetDomain(eng, target, facts, params) {
    var configured = eng && shape(eng).targetDomains[target], tg = ((eng && eng.targets) || []).find(function (t) { return (t.ip || t.id) === target; });
    if (configured) return clean(configured);
    if (tg && tg.domain) return clean(tg.domain);
    var host = list(facts).filter(function (f) { return f.state === 'supported' && f.scope === 'host:' + target; });
    for (var i = 0; i < host.length; i++) {
      var f = host[i], v = f.value || {};
      if (/^(host\.domain|ad\.domain_known|dns\.zone)$/.test(f.kind) && (v.domain || v.name || v.zone)) return clean(v.domain || v.name || v.zone).replace(/\.+$/, '');
      if (f.kind === 'host.fqdn' && String(v.fqdn || v.name || '').indexOf('.') > 0) return String(v.fqdn || v.name).split('.').slice(1).join('.');
    }
    if (!eng && params.domain) return clean(params.domain);
    var names = uniqueProvenAdDomains(facts);
    if (names.length === 1 && !hasConflictingNonAdEvidence(host, tg)) return names[0];
    return '';
  }
  function targetAliases(eng, target) {
    var out = [lower(target)], t = ((eng && eng.targets) || []).find(function (x) { return (x.ip || x.id) === target; });
    if (t) [t.hostname,t.fqdn].forEach(function (v) { if (v) { out.push(lower(v)); out.push(lower(v).split('.')[0]); } });
    return out;
  }
  var AUTH_SURFACE_RE = /^(?:port:(?:21|22|23|25|80|88|110|135|139|143|389|443|445|465|587|636|993|995|1433|1521|2222|3268|3269|3306|3389|5432|5900|5901|5985|5986|6379|8000|8080|8443|8888|27017)|(?:http|https|smb|ssh|winrm|rdp|ldap|kerberos|ftp|mssql|mysql|postgres|postgresql|redis|oracle|vnc|mail|imap|pop3|smtp)\.reachable|web\.login_form|http\.(?:login|basic_auth)|ad\.dc_candidate)$/;
  function hasScannedActivity(hostFacts) {
    for (var i = 0; i < hostFacts.length; i++) {
      var f = hostFacts[i];
      if (!f || f.state !== 'supported') continue;
      if (f.kind.indexOf('target.') === 0 || f.kind === 'host.hostname' || f.kind === 'host.domain' || f.kind === 'host.fqdn') continue;
      if ((f.kind === 'host.os' || f.kind === 'host.os_hint') && f.source === 'target-edit') continue;
      return true;
    }
    return false;
  }
  function isLapsBoundElsewhere(v, originHost, aliases) {
    v = v || {};
    var tag = clean(v.method || v.via || v.kind || v.source || '');
    if (!/\blaps\b/i.test(tag) && !v.machineBound) return false;
    var bound = lower(v.targetBinding || v.computer || originHost || '').replace(/\$$/, '');
    if (!bound) return true;
    return aliases.indexOf(bound) < 0 && aliases.indexOf(bound.split('.')[0]) < 0;
  }
  function isSshPassphraseOnly(v) {
    v = v || {};
    if (clean(v.user || v.username)) return false;
    return /ssh/i.test(clean(v.kind || v.via || v.method || v.format || '')) || /^id_(?:rsa|ed25519|ecdsa|dsa)/i.test(clean(v.file || v.path || ''));
  }
  function scopeFacts(eng, target, facts, domain) {
    var all = list(facts), multi = ((eng && eng.targets) || []).length > 1 || all.some(function (f) { return /^host:/.test(f.scope || '') && f.scope !== 'host:target' && f.scope !== 'host:' + target; });
    var aliases = targetAliases(eng, target);
    var ownHostFacts = [];
    for (var hi = 0; hi < all.length; hi++) {
      var hf = all[hi];
      if (!hf) continue;
      var hsc = clean(hf.scope);
      if (/^host:/.test(hsc) && (aliases.indexOf(lower(hsc.slice(5)).replace(/\$$/, '')) >= 0 || (!multi && hsc === 'host:target'))) {
        ownHostFacts.push(hf);
      }
    }
    if (multi && target && !hasScannedActivity(ownHostFacts)) {
      var isRegisteredTarget = ((eng && eng.targets) || []).some(function (t) { return (t.ip || t.id) === target; });
      if (domain && isRegisteredTarget) {
        var dirMeta = projectDirMetadataFacts(all, domain);
        if (dirMeta.length) return ownHostFacts.concat(dirMeta);
      }
      return ownHostFacts;
    }
    var baseScoped = all.filter(function (f) {
      if (!f) return false; var sc = clean(f.scope);
      if (/^host:/.test(sc)) return aliases.indexOf(lower(sc.slice(5)).replace(/\$$/, '')) >= 0 || (!multi && sc === 'host:target');
      if (/^domain:/.test(sc)) {
        if (/^(?:access\.|foothold\.|(?:smb|ldap|winrm|ssh|rdp|mssql)\.authenticated$|credential\.(?:validated|validation|admin)$)/.test(f.kind)) return false;
        return !!domain && (lower(sc.slice(7)) === lower(domain) || (!multi && sc === 'domain:domain'));
      }
      if (multi && !sc && /^(?:access\.|foothold\.|credential\.|blocker\.|loot\.)/.test(f.kind)) return false;
      return !multi || /^scope:/.test(sc) || !sc;
    });
    if (multi && domain) {
      var extraDirMeta = projectDirMetadataFacts(all, domain);
      for (var dmi = 0; dmi < extraDirMeta.length; dmi++) {
        var dmf = extraDirMeta[dmi];
        if (!baseScoped.some(function (ef) { return ef && ef.state === 'supported' && ef.kind === dmf.kind; })) {
          baseScoped.push(dmf);
        }
      }
    }
    if (multi && target && O.facts && O.facts.makeFact) {
      var hostScope = 'host:' + target;
      if (O.store && O.store.pivotRouteForTarget && (!eng || !O.store.active || O.store.active() === eng)
        && !baseScoped.some(function (f) { return f && f.state === 'supported' && f.kind === 'tunnel.reachable_via_pivot'; })) {
        var piv = O.store.pivotRouteForTarget(target);
        if (piv) {
          baseScoped.push(O.facts.makeFact({
            kind: 'tunnel.reachable_via_pivot',
            scope: hostScope,
            state: 'supported',
            source: 'pivot-projection',
            value: { pivotHost: piv.pivotHost, subnet: piv.subnet, via: piv.via, active: piv.active }
          }));
        }
      }
      var otherSources = [];
      for (var oi = 0; oi < all.length; oi++) {
        var of = all[oi];
        if (!of || of.state !== 'supported') continue;
        var osc = clean(of.scope);
        if (!/^host:/.test(osc) || osc === 'host:target') continue;
        var ohost = osc.slice(5);
        if (aliases.indexOf(lower(ohost).replace(/\$$/, '')) >= 0) continue;
        if (/^credential\.(?:available|plaintext|ntlm_hash|ssh_key|certificate)$|^loot\.ssh_key$|^ssh\.private_key$/.test(of.kind)) {
          otherSources.push({ fact: of, originHost: ohost });
        }
      }
      if (otherSources.length) {
        var hasAuthSurface = ownHostFacts.some(function (f) { return f && f.state === 'supported' && AUTH_SURFACE_RE.test(f.kind); });
        var hasSshSurface = ownHostFacts.some(function (f) { return f && f.state === 'supported' && /^(?:port:(?:22|2222)|ssh\.reachable)$/.test(f.kind); });
        var destHasAdSurface = !!(domain && domain.indexOf('.') > 0 && lower(domain) !== 'workgroup') || ownHostFacts.some(function (f) {
          if (!f || f.state !== 'supported') return false;
          if (/^(?:kerberos\.reachable|ldap\.reachable|ad\.dc_candidate|ad\.domain_controller|port:(?:88|389|636|3268|3269))$/.test(f.kind)) return true;
          if (f.kind === 'ad.domain_known' && f.value && String(f.value.name || '').indexOf('.') > 0) return true;
          if (f.kind === 'host.domain' && f.value && String(f.value.domain || f.value.name || '').indexOf('.') > 0 && lower(f.value.domain || f.value.name) !== 'workgroup') return true;
          return false;
        });
        var destIsLinux = ownHostFacts.some(function (f) {
          if (!f || f.state !== 'supported') return false;
          if (/^(?:foothold\.linux|os\.linux)$/.test(f.kind)) return true;
          if ((f.kind === 'host.os_family' || f.kind === 'host.os_hint') && f.value && /^(?:linux|unix|ubuntu|debian|centos|freebsd)$/i.test(String(f.value.family || f.value.os || ''))) return true;
          return false;
        }) && !ownHostFacts.some(function (f) {
          return f && f.state === 'supported' && /^(?:foothold\.windows|os\.windows|winrm\.reachable|port:5985)$/.test(f.kind);
        });
        var destIsWorkgroupWin = !destHasAdSurface && !destIsLinux && ownHostFacts.some(function (f) {
          if (!f || f.state !== 'supported') return false;
          if (f.kind === 'host.domain' && f.value) {
            var hd = clean(f.value.domain || f.value.name);
            if (hd && (lower(hd) === 'workgroup' || hd.indexOf('.') < 0)) return true;
          }
          if (f.kind === 'smb.signing' && f.value && f.value.workgroup === true) return true;
          return false;
        });
        var hasNativeCred = baseScoped.some(function (f) {
          if (!f || f.state !== 'supported' || !/^credential\.(?:available|plaintext|ntlm_hash)$/.test(f.kind)) return false;
          var fv = f.value || {};
          if (fv.unvalidatedOnTarget) return false;
          return !!(clean(fv.user || fv.username) && (fv.password || fv.secret || fv.nthash || fv.hash));
        });
        var isAnon = !!(eng && shape(eng).anonymousByTarget && shape(eng).anonymousByTarget[target]);
        var hasPinnedOrSelected = (eng && pin(eng) !== undefined) || !!(eng && selectedId(eng, target)) || isAnon || hasNativeCred;
        var seenReuse = Object.create(null), seenAvail = Object.create(null), seenKey = Object.create(null);
        baseScoped.forEach(function (bf) {
          if (!bf || bf.state !== 'supported') return;
          var bv = bf.value || {};
          if (bf.kind === 'credential.reuse_candidate') {
            seenReuse[[lower(bv.user), bv.password || bv.secret || '', lower(bv.nthash), clean(bv.keyPath)].join('|')] = 1;
          } else if (bf.kind === 'credential.available') {
            seenAvail[material(bv, bf.scope).id] = 1;
          } else if (bf.kind === 'loot.ssh_key') {
            seenKey[clean(bv.keyPath || bv.path || bv.file)] = 1;
          }
        });
        var hasCertKey = baseScoped.some(function (bf) { return bf && bf.state === 'supported' && bf.kind === 'credential.certificate'; });
        for (var si = 0; si < otherSources.length; si++) {
          var srcFact = otherSources[si].fact, srcHost = otherSources[si].originHost, sv = srcFact.value || {};
          if (/^credential\.(?:available|plaintext|ntlm_hash)$/.test(srcFact.kind)) {
            if (sv.unresolved || sv.association === 'unresolved') continue;
            if (isLapsBoundElsewhere(sv, srcHost, aliases) || isSshPassphraseOnly(sv)) continue;
            var mat = material(sv, srcFact.scope);
            if (!mat.password && !mat.nthash) continue;
            var srcHasAdFact = all.some(function (af) {
              return af && af.state === 'supported' && af.scope === ('host:' + srcHost) && /^(?:ad\.domain_known|ad\.dc_candidate|kerberos\.reachable|ldap\.reachable)$/.test(af.kind);
            });
            var srcIsAdDomainCred = (!!mat.domain && mat.domain.indexOf('.') > 0 && lower(mat.domain) !== 'workgroup')
              || /^domain:/i.test(srcFact.scope || '')
              || (srcHasAdFact && mat.accountType !== 'local');
            var specCrossDomain = !!(srcIsAdDomainCred && ((destIsLinux && !destHasAdSurface) || destIsWorkgroupWin));
            var rKey = [lower(mat.user), mat.password, lower(mat.nthash), ''].join('|');
            if (!seenReuse[rKey]) {
              seenReuse[rKey] = 1;
              baseScoped.push(O.facts.makeFact({
                kind: 'credential.reuse_candidate',
                scope: hostScope,
                state: 'supported',
                source: 'cross-host-reuse',
                value: {
                  user: mat.user,
                  password: mat.password,
                  secret: mat.password,
                  nthash: mat.nthash,
                  keyPath: '',
                  domain: mat.domain,
                  originHost: srcHost,
                  accountType: mat.accountType,
                  credentialId: mat.id,
                  reuseHypothesis: true,
                  speculativeCrossDomainReuse: specCrossDomain
                }
              }));
            }
            if (hasAuthSurface && !hasPinnedOrSelected && mat.user && !seenAvail[mat.id]) {
              seenAvail[mat.id] = 1;
              baseScoped.push(O.facts.makeFact({
                kind: 'credential.available',
                scope: hostScope,
                state: 'supported',
                source: 'cross-host-reuse',
                value: {
                  user: mat.user,
                  domain: mat.domain,
                  password: mat.password,
                  secret: mat.password,
                  nthash: mat.nthash,
                  accountType: mat.accountType,
                  targetBinding: mat.targetBinding,
                  credentialId: mat.id,
                  method: mat.method,
                  originHost: srcHost,
                  reuseFrom: srcHost,
                  unvalidatedOnTarget: true,
                  speculativeCrossDomainReuse: specCrossDomain
                }
              }));
            }
          } else {
            if (srcFact.kind === 'credential.certificate' && sv.kind !== 'private_key' && !sv.ssh_key_path && !sv.keyPath && !sv.key_path && !sv.keyfile) continue;
            var kp = clean(sv.ssh_key_path || sv.sshKeyPath || sv.keyPath || sv.key_path || sv.keyfile || sv.path || sv.file || 'id_rsa');
            var ku = clean(sv.user || sv.username || sv.owner || '');
            var rkKey = [lower(ku), '', '', kp].join('|');
            if (!seenReuse[rkKey]) {
              seenReuse[rkKey] = 1;
              baseScoped.push(O.facts.makeFact({
                kind: 'credential.reuse_candidate',
                scope: hostScope,
                state: 'supported',
                source: 'cross-host-reuse',
                value: {
                  user: ku,
                  password: '',
                  secret: '',
                  nthash: '',
                  keyPath: kp,
                  originHost: srcHost,
                  accountType: sv.accountType || 'local',
                  reuseHypothesis: true
                }
              }));
            }
            if (hasAuthSurface && !hasPinnedOrSelected) {
              if (!seenKey[kp]) {
                seenKey[kp] = 1;
                baseScoped.push(O.facts.makeFact({
                  kind: 'loot.ssh_key',
                  scope: hostScope,
                  state: 'supported',
                  source: 'cross-host-reuse',
                  value: {
                    path: kp,
                    file: kp,
                    keyPath: kp,
                    user: ku,
                    originHost: srcHost,
                    reuseFrom: srcHost,
                    unvalidatedOnTarget: true
                  }
                }));
              }
              if (hasSshSurface && !hasCertKey) {
                hasCertKey = true;
                baseScoped.push(O.facts.makeFact({
                  kind: 'credential.certificate',
                  scope: hostScope,
                  state: 'supported',
                  source: 'cross-host-reuse',
                  value: {
                    kind: 'private_key',
                    path: kp,
                    file: kp,
                    keyPath: kp,
                    user: ku,
                    encrypted: !!sv.encrypted,
                    originHost: srcHost,
                    reuseFrom: srcHost,
                    unvalidatedOnTarget: true
                  }
                }));
              }
            }
          }
        }
      }
    }
    return baseScoped;
  }
  function resolve(opts) {
    opts = opts || {}; var eng = opts.engagement || null;
    // Reuse work only within this resolution. A new paste or selection gets a fresh
    // frame, so cached projections never outlive the evidence/identity snapshot.
    var frame = opts._frame;
    if (eng && !frame) normalize(eng);
    var p = Object.assign({}, opts.params || (eng && eng.params) || {}), target = clean(opts.target || p.target || (eng && eng.activeTarget)), allFacts = opts.facts || (eng && eng.facts) || [];
    var domain = frame ? frame.domain : targetDomain(eng, target, allFacts, p), selected, source = 'none', registry = frame ? frame.registry : credentials(eng || { facts: list(allFacts) });
    if (owns(opts, 'credentialId')) { selected = opts.credentialId; source = 'explicit'; }
    else if (eng) { selected = selectedId(eng, target); source = pin(eng) !== undefined ? 'session-pin' : 'target-memory'; }
    var c = registry.find(function (x) { return x.id === selected; }) || null;
    if (!eng && selected === undefined && (p.username || p.user)) { c = material({ user:p.username || p.user, domain:p.authRealm || '', password:p.password || '', nthash:p.nthash || '' }); source = 'explicit-params'; }
    if (!frame) {
      var retirableActInfos = null;
      if (eng && Array.isArray(eng.activities)) {
        retirableActInfos = [];
        for (var rai = 0; rai < eng.activities.length; rai++) {
          var rAct = eng.activities[rai];
          if (!rAct || !rAct.outcome) continue;
          var rAo = rAct.outcome;
          if (!rAo.retireCommand && !(rAo.kind === 'success' && /(?:^|\s)--host\b/i.test(rAct.command || ''))) continue;
          retirableActInfos.push({
            actionId: rAct.action_id || rAct.actionId || '',
            hay: (String(rAct.command || '') + '\n' + String(rAct.dispatch || '') + '\n' + (Array.isArray(rAct.sequenceCommands) ? rAct.sequenceCommands.join('\n') : '')).toLowerCase()
          });
        }
      }
      frame = { domain:domain, registry:registry, scoped:scopeFacts(eng, target, allFacts, domain),
        materials:new Map(), projections:Object.create(null), contexts:Object.create(null), attempts:Object.create(null),
        retirableActInfos:retirableActInfos };
    }
    var scoped = frame.scoped, conflicts = [], unresolved = [];
    if (!eng && selected === undefined && !c) {
      var scopedRegistry = credentials({facts:scoped});
      if (scopedRegistry.length === 1) { c = scopedRegistry[0]; source = 'single-scoped-candidate'; }
    }
    if (!c && !owns(opts, 'credentialId') && pin(eng) === undefined && !selected && !(eng && shape(eng).anonymousByTarget && shape(eng).anonymousByTarget[target])) {
      var reuseFacts = scoped.filter(function (f) {
        return f && f.state === 'supported' && f.kind === 'credential.available' && f.value && f.value.unvalidatedOnTarget && f.value.reuseFrom;
      });
      if (reuseFacts.length) {
        var svcHint = serviceOf(opts.command, opts.service);
        var blockers = scoped.filter(function (f) {
          return f && ((f.state === 'supported' && /^blocker\.(?:logon_failure|account_disabled|account_locked|password_expired)$/.test(f.kind))
            || (f.state === 'refuted' && f.kind === 'credential.validation'));
        });
        var reuseAliases = targetAliases(eng, target);
        var targetActs = (eng && Array.isArray(eng.activities)) ? eng.activities.filter(function (act) {
          if (!act || !act.outcome || !act.outcome.conclusive) return false;
          var okind = act.outcome.kind;
          if (okind !== 'rejected' && okind !== 'authorization-denied') return false;
          var actTgt = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
          return !target || actTgt === target;
        }) : [];
        var scoredReuse = reuseFacts.map(function (rf, idx) {
          var mat = material(rf.value || {}, rf.scope);
          var regMatch = registry.find(function (x) { return x.id === mat.id; }) || mat;
          var blockerRej = blockers.filter(function (bf) {
            var bv = bf.value || {};
            var bvUser = lower(bv.user || bv.principal || '').replace(/^.*\\/, '');
            var bvDom = lower(bv.domain || '');
            var regDom = lower(regMatch.domain || '');
            var sameOrLocalRealm = !bvDom || !regDom || bvDom === regDom || reuseAliases.indexOf(bvDom) >= 0;
            var aliasFpMatch = false;
            if (!regDom && bvDom && reuseAliases.indexOf(bvDom) >= 0 && bv.credentialFingerprint && O.facts && O.facts.fingerprint) {
              var aliasFp = O.facts.fingerprint(JSON.stringify([bvDom, lower(regMatch.user), regMatch.nthash ? 'nthash' : 'password', String(regMatch.nthash || regMatch.password)]));
              aliasFpMatch = aliasFp === bv.credentialFingerprint;
            }
            var sameSecret = aliasFpMatch
              || (bv.password && String(bv.password) === regMatch.password)
              || ((bv.nthash || bv.hash) && lower(bv.nthash || bv.hash) === lower(regMatch.nthash))
              || (!bv.password && !bv.nthash && !bv.hash && !bv.credentialFingerprint);
            var idMatch = (bv.credentialId && bv.credentialId === regMatch.id)
              || (bv.credentialFingerprint && bv.credentialFingerprint === regMatch.credentialFingerprint)
              || (bvUser && bvUser === lower(regMatch.user) && sameSecret && sameOrLocalRealm);
            if (!idMatch) return false;
            if (svcHint && bv.service && lower(bv.service) !== svcHint) return false;
            return true;
          }).length;
          var actRej = targetActs.filter(function (act) {
            var pc = act.context || (act.outcome && act.outcome.context) || {};
            if (pc.credentialId && pc.credentialId !== regMatch.id) return false;
            if (!pc.credentialId && pc.credentialFingerprint && pc.credentialFingerprint !== regMatch.credentialFingerprint) return false;
            if (!pc.credentialId && !pc.credentialFingerprint) return false;
            if (svcHint && pc.service && lower(pc.service) !== svcHint) return false;
            return true;
          }).length;
          var rejectedHere = Math.max(blockerRej, actRej);
          var specCross = !!(rf.value && rf.value.speculativeCrossDomainReuse) ? 1 : 0;
          var domCompat = (!regMatch.domain || !domain || lower(regMatch.domain) === lower(domain)) ? 1 : 0;
          var isAdminName = /^(?:administrator|admin|root)$/i.test(regMatch.user) ? 1 : 0;
          return { cred: regMatch, rejected: rejectedHere, specCross: specCross, domCompat: domCompat, admin: isAdminName, idx: idx };
        });
        scoredReuse.sort(function (a, b) {
          if (a.specCross !== b.specCross) return a.specCross - b.specCross;
          if (a.rejected !== b.rejected) return a.rejected - b.rejected;
          if (b.domCompat !== a.domCompat) return b.domCompat - a.domCompat;
          if (b.admin !== a.admin) return b.admin - a.admin;
          return a.idx - b.idx;
        });
        c = scoredReuse[0].cred;
        source = 'cross-host-reuse';
      }
    }
    if (selected && !c) unresolved.push('selected-credential-unavailable');
    if (!target) unresolved.push('target');
    if (!domain) unresolved.push('target-domain');
    var svc = serviceOf(opts.command, opts.service), realm = c ? c.domain || (c.accountType === 'local' ? (source === 'cross-host-reuse' ? '.' : c.targetBinding.replace(/\$$/, '')) : '') : '', locus = opts.locus || 'remote';
    if (c && c.targetBinding && targetAliases(eng, target).indexOf(lower(c.targetBinding).replace(/\$$/, '')) < 0) conflicts.push('credential-target-binding-differs');
    if (c && realm && domain && lower(realm) !== lower(domain)) conflicts.push('authentication-realm-differs-from-target-domain');
    var principal = c ? c.principal : '';
    var projectionKey = JSON.stringify([c && c.id, svc, locus]);
    var projection = frame.projections[projectionKey];
    if (!projection) {
    function factMaterial(f) {
      if (!frame.materials.has(f)) frame.materials.set(f, material(f.value || {}, f.scope));
      return frame.materials.get(f);
    }
    scoped = scoped.filter(function (f) {
      var v = f.value || {};
      if (/^access\.(admin|system|root)$/.test(f.kind) && locus !== 'onhost' && locus !== 'overview') {
        if (!c) return false;
        if (v.credentialId && v.credentialId !== c.id) return false;
        if (v.credentialFingerprint && v.credentialFingerprint !== c.credentialFingerprint) return false;
        if (!v.credentialId && !v.credentialFingerprint) {
          if ((!v.password && !v.nthash && !v.hash) || factMaterial(f).credentialFingerprint !== c.credentialFingerprint) return false;
        }
        if (svc && v.service && lower(v.service) !== svc && !((svc === 'smb' && lower(v.service) === 'wmi') || (svc === 'wmi' && lower(v.service) === 'smb'))) return false;
      }
      if (/^credential\.(available|plaintext|ntlm_hash)$/.test(f.kind)) {
        if (c && factMaterial(f).id === c.id) return true;
        var fm = factMaterial(f);
        var isAnonPin = (source === 'explicit' && !selected) || !!(eng && shape(eng).anonymousByTarget && shape(eng).anonymousByTarget[target]);
        if (!isAnonPin && !fm.user && (fm.password || fm.nthash) && (!c || (!c.password && !c.nthash))) return true;
        return false;
      }
      if (/^credential\.(validated|validation|authorization|admin)$/.test(f.kind) || /^(smb|ldap|winrm|ssh|rdp|mssql)\.authenticated$/.test(f.kind) || (/^blocker\./.test(f.kind) && (v.credentialId || v.user || v.principal))) {
        if (!c) return false;
        if (v.credentialId) { if (v.credentialId !== c.id) return false; }
        else if (v.credentialFingerprint) { if (v.credentialFingerprint !== c.credentialFingerprint) return false; }
        else {
          if (!v.user && !v.principal) return false;
          if (lower(v.user || v.principal).replace(/^.*\\/, '') !== lower(c.user)) return false;
          if (v.domain && lower(v.domain) !== lower(c.domain)) return false;
          if (!v.password && !v.nthash && !v.hash) return false;
          if (v.password && String(v.password) !== c.password) return false;
          if ((v.nthash || v.hash) && lower(v.nthash || v.hash) !== lower(c.nthash)) return false;
        }
        if (svc && v.service && lower(v.service) !== svc) return false;
        if (svc && /\.authenticated$/.test(f.kind) && f.kind.split('.')[0] !== svc) return false;
      }
      return true;
    });
    var isSpecCrossReuse = !!(c && (c.speculativeCrossDomainReuse || scoped.some(function (rf) {
      return rf && rf.state === 'supported' && rf.kind === 'credential.reuse_candidate' && rf.value
        && rf.value.speculativeCrossDomainReuse && (rf.value.credentialId === c.id || lower(rf.value.user) === lower(c.user));
    })));
    if (c && (c.password || c.nthash) && !scoped.some(function (f) { return f.state === 'supported' && f.kind === 'credential.available'; }) && O.facts) scoped.push(O.facts.makeFact({kind:'credential.available',scope:'host:' + target,state:'supported',value:{user:c.user,domain:c.domain,password:c.password,nthash:c.nthash,credentialId:c.id,targetBinding:c.targetBinding,accountType:c.accountType,selectedMaterial:true,speculativeCrossDomainReuse:isSpecCrossReuse}}));
    projection = frame.projections[projectionKey] = O.facts ? new O.facts.FactSet(scoped) : {facts:scoped};
    Object.defineProperty(projection, '_projBase', { value: projection, configurable: true });
    }
    ['username','user','password','nthash','credentialId','authRealm','auth_realm'].forEach(function (k) { delete p[k]; });
    p.target = target; p.domain = domain; p.target_domain = domain; p.authRealm = realm; p.auth_realm = realm;
    if (c) { p.username = c.user; p.user = c.user; p.password = c.password; p.nthash = c.nthash; p.credentialId = c.id; }
    // The projection is already deduplicated. Give each action its own context
    // and array without rebuilding the ledger with quadratic FactSet.add calls.
    var view = Object.create(projection); view.facts = projection.facts.slice(); view.state_changed = [];
    var result = { target:target,targetDomain:domain,authRealm:realm,principal:principal,credentialId:c ? c.id : null,credentialFingerprint:c ? c.credentialFingerprint : '',credential:c,
      service:svc,locus:locus,facts:view,allScopedFacts:frame.scoped,params:p,engagement:eng,_frame:frame,
      selectionSource:source,conflicts:conflicts,unresolved:unresolved,actionId:opts.actionId || '' };
    result.attemptKey = JSON.stringify([target,result.credentialId,svc,result.locus,result.actionId]);
    Object.defineProperty(result.facts, '_resolvedContext', {value:result});
    result.facts.context = snapshot(result);
    result.facts.forAction = function (action, command) {
      var commands = action.commands || [], cmd = command || commands[0] || {};
      var actionLocus = commands.length && O.pack && O.pack.commandExecutionLocus
        ? O.pack.commandExecutionLocus(cmd) : action.locus === 'F' || action.locus === 'I' ? 'onhost' : 'remote';
      var commandText = cmd.web || cmd.run || action.command || '';
      var key = JSON.stringify([action.id, actionLocus, serviceOf(commandText)]);
      if (!frame.contexts[key]) frame.contexts[key] = resolve({engagement:eng,target:target,facts:allFacts,params:p,credentialId:result.credentialId,locus:actionLocus,
        command:commandText,actionId:action.id,_frame:frame}).facts;
      return frame.contexts[key];
    };
    result.facts.forActionContexts = function (action) {
      var seen = Object.create(null), candidates = [];
      ((action.commands && action.commands.length) ? action.commands : [null]).forEach(function (cmd) {
        var candidate = result.facts.forAction(action, cmd), key = candidate.context.attemptKey;
        if (!seen[key]) { seen[key] = true; candidates.push(candidate); }
      });
      return candidates;
    };
    result.facts.applicableCommands = function (action) {
      var applicable = [];
      ((action && action.commands) || []).forEach(function (cmd, index) {
        var commandFacts = result.facts.forAction(action, cmd);
        var isElig = (!action.eligible || action.eligible(commandFacts))
          && (!O.pack || !O.pack.commandIsEligible || O.pack.commandIsEligible(cmd, commandFacts, action))
          && (!O.command || !O.command.commandPortFeasible || O.command.commandPortFeasible(cmd, commandFacts).feasible !== false);
        if (isElig) applicable.push({ cmd: cmd, index: index });
      });
      return applicable;
    };
    function _privEpochKey(e) {
      return e ? (String(e).replace(/(?:^|\|)h:[^|]*/g, '') || 'anon') : '';
    }
    function _actionDryState(action, curCtx, epoch, cleanOnly) {
      var acts = (eng && eng.activities) || [];
      if (!action || !acts.length) return { retireAll: false, hasNegativeProbe: false };
      var privEp = _privEpochKey(epoch);
      var retireAll = false, hasNegativeProbe = false;
      for (var ai = 0; ai < acts.length; ai++) {
        var act = acts[ai];
        if (!act || (act.action_id || act.actionId) !== action.id) continue;
        var actTarget = act.target || (/^host:/.test(act.scope || '') ? act.scope.slice(5) : '');
        if (target && actTarget && actTarget !== target) continue;
        if (privEp && act.epoch && _privEpochKey(act.epoch) !== privEp) continue;
        var prevCtx = act.context || (act.outcome && act.outcome.context);
        if (curCtx && prevCtx && (prevCtx.credentialId || null) !== (curCtx.credentialId || null)) continue;
        var hasActiveBlocker = Array.isArray(act.blockers) && act.blockers.length && result.facts.has
          && act.blockers.some(function (b) { return result.facts.has(b); });
        var isProductive = (typeof act.addedCount === 'number' && act.addedCount > 0)
          || (Array.isArray(act.produced) && act.produced.some(function (k) { return k && !/^(?:blocker\.|credential\.validation$)/.test(k); }));
        if (hasActiveBlocker || isProductive) break;
        var ao = act.outcome;
        if (!ao || !ao.conclusive || !ao.retireCommand) continue;
        if (cleanOnly && (ao.kind === 'rejected' || ao.kind === 'authorization-denied')) continue;
        if (ao.retireMove === true || (ao.kind === 'completed-negative' && !clean(act.command))) {
          retireAll = true;
          hasNegativeProbe = true;
          break;
        }
        if (ao.kind === 'completed-negative') {
          hasNegativeProbe = true;
        }
      }
      return { retireAll: retireAll, hasNegativeProbe: hasNegativeProbe };
    }
    function _isSubCmdTokenBlocked(filledObj) {
      if (!filledObj || filledObj.blocked) return true;
      if (O.command.unfilledTokens && O.command.EARNED_TOKENS) {
        var un = O.command.unfilledTokens(filledObj.filled || '');
        for (var ui = 0; ui < un.length; ui++) {
          if (O.command.EARNED_TOKENS[un[ui]]) return true;
        }
      }
      return false;
    }
    function _checkCompleted(action, cmd, index, cleanOnly) {
      if (!eng || !O.command || !O.command.commandTriedInEpoch || !O.command.fillCommand) return false;
      var cacheKey = cleanOnly ? '__clean' : '__all';
      var attempts = frame.attempts[cacheKey];
      if (!attempts) attempts = frame.attempts[cacheKey] = (eng.activities || []).filter(function (activity) {
        var o = activity && activity.outcome;
        if (activity && o && !o.retireCommand && o.kind === 'success' && /(?:^|\s)--host\b/i.test(activity.command || '') && O.outcomes && O.outcomes.completion) {
          var comp = O.outcomes.completion(activity.stdout || '', activity.command);
          if (comp && comp.complete) { o.conclusive = true; o.retireCommand = true; }
        }
        if (!activity || !o || !o.conclusive || !o.retireCommand) return false;
        if (cleanOnly && (o.kind === 'rejected' || o.kind === 'authorization-denied')) return false;
        return true;
      });
      if (!attempts.length) return false;
      var commandFacts = result.facts.forAction(action, cmd);
      var filled = O.command.fillCommand(action, commandFacts, { params:p, target:target }, index);
      var epoch = O.pack && O.pack.accessEpoch ? O.pack.accessEpoch(result.facts) : '';
      if (O.command.commandTriedInEpoch(action, cmd, filled.blocked ? '' : filled.filled, attempts, epoch, target, commandFacts._resolvedContext)) {
        return true;
      }
      var dryState = _actionDryState(action, commandFacts._resolvedContext, epoch, cleanOnly);
      if (dryState.retireAll) return true;
      if (dryState.hasNegativeProbe && _isSubCmdTokenBlocked(filled)) {
        var appList = result.facts.applicableCommands(action);
        var anyRunnableTried = false;
        for (var ai = 0; ai < appList.length; ai++) {
          var entry = appList[ai];
          var subFacts = result.facts.forAction(action, entry.cmd);
          var subFilled = O.command.fillCommand(action, subFacts, { params:p, target:target }, entry.index);
          if (_isSubCmdTokenBlocked(subFilled)) continue;
          if (!O.command.commandTriedInEpoch(action, entry.cmd, subFilled.filled, attempts, epoch, target, subFacts._resolvedContext)) {
            return false;
          }
          anyRunnableTried = true;
        }
        return anyRunnableTried;
      }
      return false;
    }
    result.facts.commandCompleted = function (action, cmd, index) {
      return _checkCompleted(action, cmd, index, false);
    };
    result.facts.commandCompletedClean = function (action, cmd, index) {
      return _checkCompleted(action, cmd, index, true);
    };
    return result;
  }
  function snapshot(c) {
    if (!c) return null;
    return {target:c.target || '',targetDomain:c.targetDomain || '',authRealm:c.authRealm || '',principal:c.principal || '',credentialId:c.credentialId || null,credentialFingerprint:c.credentialFingerprint || '',
      service:c.service || '',locus:c.locus || 'remote',actionId:c.actionId || '',attemptKey:c.attemptKey || '',selectionSource:c.selectionSource || '',
      conflicts:(c.conflicts || []).slice(),unresolved:(c.unresolved || []).slice()};
  }
  O.context = {resolve:resolve,snapshot:snapshot,credentials:credentials,normalize:normalize,select:select,setPin:setPin,pin:pin,
    selectedId:selectedId,applySelection:applySelection,beforeUpdate:beforeUpdate,reconcile:reconcile,serviceOf:serviceOf,material:material};
})(typeof globalThis !== 'undefined' ? globalThis : this);
