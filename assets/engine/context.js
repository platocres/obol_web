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
    var binding = clean(raw.targetBinding || raw.computer || (accountType === 'local' ? raw.host || raw.target : ''));
    if (accountType === 'local' && !binding && /^host:/.test(scope || '')) binding = scope.slice(5);
    var key = JSON.stringify([lower(user), lower(domain), password, lower(nthash), accountType, lower(binding)]);
    var fingerprint = O.facts && O.facts.fingerprint ? O.facts.fingerprint(JSON.stringify([lower(domain),lower(user),nthash ? 'nthash' : 'password',String(nthash || password)])) : digest(key);
    return { id: 'cred-' + digest(key), credentialFingerprint:fingerprint, user: user, principal: domain ? domain + '\\' + user : user,
      domain: domain, realm: domain, password: password, secret: password, nthash: nthash,
      type: nthash && !password ? 'NT' : password ? 'PW' : type || '?', secretType: nthash && !password ? 'NT' : password ? 'PW' : type || 'USER',
      scope: scope || raw.scope || '', targetBinding: binding, computer: raw.computer || '', accountType: accountType,
      source: raw.source || 'recovered', sourceId: raw.id || '', method: raw.method || raw.via || '' };
  }
  function credentials(eng) {
    eng = eng || {}; var found = [], seen = Object.create(null);
    function add(raw, scope) {
      var c = material(raw, scope); if (raw.unresolved || !c.user || (!c.password && !c.nthash && c.secretType !== 'USER')) return;
      if (seen[c.id]) { if (!seen[c.id].scope && c.scope) seen[c.id].scope = c.scope; return; }
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
    normalize(eng); var pinned = pin(eng);
    return pinned !== undefined ? pinned : shape(eng).byTarget[target];
  }
  function applySelection(eng, target) {
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
  function targetDomain(eng, target, facts, params) {
    var configured = eng && shape(eng).targetDomains[target], tg = ((eng && eng.targets) || []).find(function (t) { return (t.ip || t.id) === target; });
    if (configured) return clean(configured);
    if (tg && tg.domain) return clean(tg.domain);
    var host = list(facts).filter(function (f) { return f.state === 'supported' && f.scope === 'host:' + target; });
    for (var i = 0; i < host.length; i++) {
      var f = host[i], v = f.value || {};
      if (/^(host\.domain|ad\.domain_known)$/.test(f.kind) && (v.domain || v.name)) return clean(v.domain || v.name);
      if (f.kind === 'host.fqdn' && String(v.fqdn || v.name || '').indexOf('.') > 0) return String(v.fqdn || v.name).split('.').slice(1).join('.');
    }
    if (!eng && params.domain) return clean(params.domain);
    var names = list(facts).filter(function (f) { return f.state === 'supported' && f.kind === 'ad.domain_known' && /^domain:/.test(f.scope || ''); }).map(function (f) { return clean((f.value || {}).name || (f.value || {}).domain || f.scope.slice(7)); });
    if ((!eng || (eng.targets || []).length <= 1) && names.length === 1) return names[0];
    return '';
  }
  function targetAliases(eng, target) {
    var out = [lower(target)], t = ((eng && eng.targets) || []).find(function (x) { return (x.ip || x.id) === target; });
    if (t) [t.hostname,t.fqdn].forEach(function (v) { if (v) { out.push(lower(v)); out.push(lower(v).split('.')[0]); } });
    return out;
  }
  function scopeFacts(eng, target, facts, domain) {
    var all = list(facts), multi = ((eng && eng.targets) || []).length > 1 || all.some(function (f) { return /^host:/.test(f.scope || '') && f.scope !== 'host:target' && f.scope !== 'host:' + target; });
    var aliases = targetAliases(eng, target);
    return all.filter(function (f) {
      if (!f) return false; var sc = clean(f.scope);
      if (/^host:/.test(sc)) return aliases.indexOf(lower(sc.slice(5)).replace(/\$$/, '')) >= 0 || (!multi && sc === 'host:target');
      if (/^domain:/.test(sc)) {
        if (/^(?:access\.|foothold\.|(?:smb|ldap|winrm|ssh|rdp|mssql)\.authenticated$|credential\.(?:validated|validation|admin)$)/.test(f.kind)) return false;
        return !!domain && (lower(sc.slice(7)) === lower(domain) || (!multi && sc === 'domain:domain'));
      }
      if (multi && !sc && /^(?:access\.|foothold\.|credential\.|blocker\.|loot\.)/.test(f.kind)) return false;
      return !multi || /^scope:/.test(sc) || !sc;
    });
  }
  function resolve(opts) {
    opts = opts || {}; var eng = opts.engagement || null;
    if (eng) normalize(eng);
    var p = Object.assign({}, opts.params || (eng && eng.params) || {}), target = clean(opts.target || p.target || (eng && eng.activeTarget)), allFacts = opts.facts || (eng && eng.facts) || [];
    var domain = targetDomain(eng, target, allFacts, p), selected, source = 'none', registry = credentials(eng || { facts: list(allFacts) });
    if (owns(opts, 'credentialId')) { selected = opts.credentialId; source = 'explicit'; }
    else if (eng) { selected = selectedId(eng, target); source = pin(eng) !== undefined ? 'session-pin' : 'target-memory'; }
    var c = registry.find(function (x) { return x.id === selected; }) || null;
    if (!eng && selected === undefined && (p.username || p.user)) { c = material({ user:p.username || p.user, domain:p.authRealm || '', password:p.password || '', nthash:p.nthash || '' }); source = 'explicit-params'; }
    var scoped = scopeFacts(eng, target, allFacts, domain), conflicts = [], unresolved = [];
    if (!eng && selected === undefined && !c) {
      var scopedRegistry = credentials({facts:scoped});
      if (scopedRegistry.length === 1) { c = scopedRegistry[0]; source = 'single-scoped-candidate'; }
    }
    if (selected && !c) unresolved.push('selected-credential-unavailable');
    if (!target) unresolved.push('target');
    if (!domain) unresolved.push('target-domain');
    var svc = serviceOf(opts.command, opts.service), realm = c ? c.domain || (c.accountType === 'local' ? c.targetBinding.replace(/\$$/, '') : '') : '', locus = opts.locus || 'remote';
    if (c && c.targetBinding && targetAliases(eng, target).indexOf(lower(c.targetBinding).replace(/\$$/, '')) < 0) conflicts.push('credential-target-binding-differs');
    if (c && realm && domain && lower(realm) !== lower(domain)) conflicts.push('authentication-realm-differs-from-target-domain');
    var principal = c ? c.principal : '';
    scoped = scoped.filter(function (f) {
      var v = f.value || {};
      if (/^access\.(admin|system|root)$/.test(f.kind) && locus !== 'onhost' && locus !== 'overview') {
        if (!c) return false;
        if (v.credentialId && v.credentialId !== c.id) return false;
        if (v.credentialFingerprint && v.credentialFingerprint !== c.credentialFingerprint) return false;
        if (!v.credentialId && !v.credentialFingerprint) {
          if ((!v.password && !v.nthash && !v.hash) || material(v, f.scope).credentialFingerprint !== c.credentialFingerprint) return false;
        }
        if (svc && v.service && lower(v.service) !== svc) return false;
      }
      if (/^credential\.(available|plaintext|ntlm_hash)$/.test(f.kind)) return !!c && material(v, f.scope).id === c.id;
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
    if (c && (c.password || c.nthash) && !scoped.some(function (f) { return f.state === 'supported' && f.kind === 'credential.available'; }) && O.facts) scoped.push(O.facts.makeFact({kind:'credential.available',scope:'host:' + target,state:'supported',value:{user:c.user,domain:c.domain,password:c.password,nthash:c.nthash,credentialId:c.id,targetBinding:c.targetBinding,accountType:c.accountType,selectedMaterial:true}}));
    ['username','user','password','nthash','credentialId','authRealm','auth_realm'].forEach(function (k) { delete p[k]; });
    p.target = target; p.domain = domain; p.target_domain = domain; p.authRealm = realm; p.auth_realm = realm;
    if (c) { p.username = c.user; p.user = c.user; p.password = c.password; p.nthash = c.nthash; p.credentialId = c.id; }
    var result = { target:target,targetDomain:domain,authRealm:realm,principal:principal,credentialId:c ? c.id : null,credentialFingerprint:c ? c.credentialFingerprint : '',credential:c,
      service:svc,locus:locus,facts:O.facts ? new O.facts.FactSet(scoped) : {facts:scoped},params:p,
      selectionSource:source,conflicts:conflicts,unresolved:unresolved,actionId:opts.actionId || '' };
    result.attemptKey = JSON.stringify([target,result.credentialId,svc,result.locus,result.actionId]);
    result.facts.context = snapshot(result);
    result.facts.forAction = function (action, command) {
      var commands = action.commands || [], cmd = command || commands[0] || {};
      var actionLocus = commands.length && O.pack && O.pack.commandExecutionLocus
        ? O.pack.commandExecutionLocus(cmd) : action.locus === 'F' || action.locus === 'I' ? 'onhost' : 'remote';
      return resolve({engagement:eng,target:target,facts:allFacts,params:p,credentialId:result.credentialId,locus:actionLocus,
        command:cmd.web || cmd.run || action.command || '',actionId:action.id}).facts;
    };
    result.facts.forActionContexts = function (action) {
      var seen = Object.create(null), candidates = [];
      ((action.commands && action.commands.length) ? action.commands : [null]).forEach(function (cmd) {
        var candidate = result.facts.forAction(action, cmd), key = candidate.context.attemptKey;
        if (!seen[key]) { seen[key] = true; candidates.push(candidate); }
      });
      return candidates;
    };
    result.facts.commandCompleted = function (action, cmd, index) {
      if (!eng || !O.command || !O.command.commandTriedInEpoch || !O.command.fillCommand) return false;
      var attempts = (eng.activities || []).filter(function (activity) {
        return activity && (activity.action_id || activity.actionId) === action.id
          && activity.outcome && activity.outcome.conclusive && activity.outcome.retireCommand;
      });
      if (!attempts.length) return false;
      var commandFacts = result.facts.forAction(action, cmd);
      var filled = O.command.fillCommand(action, commandFacts, { params:p, target:target }, index);
      if (filled.blocked) return false;
      var epoch = O.pack && O.pack.accessEpoch ? O.pack.accessEpoch(result.facts) : '';
      return O.command.commandTriedInEpoch(action, cmd, filled.filled, attempts, epoch, target);
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
