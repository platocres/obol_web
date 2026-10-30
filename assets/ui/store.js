/*!
 * obol ui — store.js
 * The browser database layer. IndexedDB is the primary store (async, structured, roomy),
 * fronted by an in-memory cache so reads are synchronous for the UI and writes never block
 * paint. localStorage holds only tiny per-viewer prefs (skin, last route) + a boot hint.
 *
 * Model: an engagement library. Each engagement holds params, targets,
 * credentials, activities, checklist ticks, a bloodhound summary, and a facts array. Large
 * binaries (screenshots, raw evidence blobs) live in a separate `blobs` store as Blobs.
 *
 * Degrades: if IndexedDB is unavailable (rare/private-mode), falls back to an in-memory store
 * + best-effort localStorage snapshot so the app still runs (smaller capacity).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var DB_NAME = 'obol-db';
  var DB_VERSION = 2;
  var LS_PREFS = 'obol-prefs';
  var LS_SNAPSHOT = 'obol-idb-fallback';

  var _db = null;
  var _mem = { engagements: {}, blobs: {}, settings: {} }; // in-memory cache / fallback
  var _activeId = null;
  var _useIDB = true;
  var _listeners = [];

  function uid(prefix) {
    return (prefix || 'e') + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  }

  // ---- IndexedDB primitives (promise-wrapped) ----
  function openDB() {
    return new Promise(function (resolve, reject) {
      if (typeof indexedDB === 'undefined') { reject(new Error('no-indexeddb')); return; }
      var settled = false;
      function done(fn, arg) { if (!settled) { settled = true; fn(arg); } }
      var req;
      try { req = indexedDB.open(DB_NAME, DB_VERSION); } catch (e) { reject(e); return; }
      // Another obol tab holding an older DB version open — or a pending deleteDatabase from a Full
      // Reset — BLOCKS this open, which then fires onblocked and NEVER fires success/error. Without a
      // handler the boot Promise hangs forever (the 2-minute blank page). Bail so init() falls back to
      // the localStorage snapshot and the app still boots; closing the other tab + reload restores IDB.
      req.onblocked = function () { done(reject, new Error('idb-open-blocked')); };
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains('engagements')) db.createObjectStore('engagements', { keyPath: 'id' });
        var blobs = db.objectStoreNames.contains('blobs') ? e.target.transaction.objectStore('blobs') : db.createObjectStore('blobs', { keyPath: 'id' });
        if (!blobs.indexNames.contains('engagementId')) blobs.createIndex('engagementId', 'engagementId', { unique: false });
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      };
      req.onsuccess = function () {
        var db = req.result;
        // Never be the tab that blocks ANOTHER tab's upgrade/reset — close this connection on demand.
        try { db.onversionchange = function () { try { db.close(); } catch (e) {} }; } catch (e2) {}
        done(resolve, db);
      };
      req.onerror = function () { done(reject, req.error || new Error('idb-open-failed')); };
      // Hard safety net: if IndexedDB fires nothing at all (some private-mode/locked states), don't
      // hang boot — reject after a bounded wait so the snapshot fallback + default seed still run.
      setTimeout(function () { done(reject, new Error('idb-open-timeout')); }, 8000);
    });
  }

  function idbPut(storeName, value) {
    return new Promise(function (resolve, reject) {
      try {
        var tx = _db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).put(value);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      } catch (err) { reject(err); }
    });
  }

  function idbGetAll(storeName) {
    return new Promise(function (resolve, reject) {
      try {
        var tx = _db.transaction(storeName, 'readonly');
        var req = tx.objectStore(storeName).getAll();
        req.onsuccess = function () { resolve(req.result || []); };
        req.onerror = function () { reject(req.error); };
      } catch (err) { reject(err); }
    });
  }

  function idbGet(storeName, key) {
    return new Promise(function (resolve, reject) {
      try {
        var tx = _db.transaction(storeName, 'readonly');
        var req = tx.objectStore(storeName).get(key);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () { reject(req.error); };
      } catch (err) { reject(err); }
    });
  }

  function idbDelete(storeName, key) {
    return new Promise(function (resolve, reject) {
      try {
        var tx = _db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).delete(key);
        tx.oncomplete = function () { resolve(true); };
        tx.onerror = function () { reject(tx.error); };
      } catch (err) { reject(err); }
    });
  }

  // ---- prefs (localStorage, tiny, synchronous, safe) ----
  function readPrefs() {
    try { return JSON.parse(localStorage.getItem(LS_PREFS) || '{}') || {}; } catch (e) { return {}; }
  }
  function writePref(key, val) {
    try { var p = readPrefs(); p[key] = val; localStorage.setItem(LS_PREFS, JSON.stringify(p)); } catch (e) {}
  }

  // A record left behind by the removed legacy auto-migration. Matches either the internal
  // `migratedFrom` marker, or — for a marker-less straggler — the unmistakable legacy fingerprint:
  // the exact "Imported engagement" name, the old seed target, and zero user work (no facts,
  // activities, or credentials). Anything a person actually built is never touched.
  function isLegacyImport(e) {
    if (!e || typeof e !== 'object') return false;
    if (e.migratedFrom) return true;
    var name = String(e.name || '').trim().toLowerCase();
    if (name !== 'imported engagement') return false;
    var untouched = !(e.facts && e.facts.length) && !(e.activities && e.activities.length)
      && !(e.credentials && e.credentials.length);
    var seeded = !!(e.params && e.params.target === '10.129.85.48');
    return untouched && seeded;
  }

  // ---- engagement shape ----
  // A brand-new draft carries an EMPTY name on purpose: the UI shows it as "No Run Yet" and never a
  // fake "Untitled Run" placeholder. The launch flow fills in a real name when the operator sets up.
  function newEngagement(name) {
    var seedParams = {};
    try {
      var ar = JSON.parse(localStorage.getItem('obol.arsenal-profile') || 'null');
      if (ar && typeof ar === 'object') {
        if (ar.lhost) {
          seedParams.lhost = ar.lhost;
          seedParams.lhost_iface = ar.lhost_iface || 'tun0';
        }
        if (ar.tooldir) seedParams.toolsDir = ar.tooldir;
      }
    } catch (e) {}
    return {
      id: uid('eng'),
      name: name == null ? '' : name,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      schema: 3,
      profile: { platform: 'custom', machine_type: '', candidate: '', osid: '', scope: [] }, // engagement profile
      params: seedParams,  // target/domain/username/password/lhost/...
      targets: [],         // [{id, ip, hostname, os, ...}]
      credentials: [],     // [{user, secret, secretType, ...}]
      activities: [],      // recorded outcomes (paste-back)
      checklist: {},       // {actionId: true}
      bloodhound: null,    // domain analysis summary
      facts: [],           // serialized OBOL.facts
      ui: {},              // per-engagement UI state (active target, path zoom/pan, ...)
      _rev: 1,
    };
  }

  function normalizeEngagement(raw) {
    var base = newEngagement(raw && raw.name != null ? String(raw.name) : '');
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return base;
    var e = Object.assign(base, raw);
    e.name = e.name == null ? '' : String(e.name);
    e.profile = (e.profile && typeof e.profile === 'object' && !Array.isArray(e.profile))
      ? Object.assign({ platform: 'custom', machine_type: '', candidate: '', osid: '', scope: [] }, e.profile)
      : { platform: 'custom', machine_type: '', candidate: '', osid: '', scope: [] };
    if (!Array.isArray(e.profile.scope)) e.profile.scope = [];
    e.params = (e.params && typeof e.params === 'object' && !Array.isArray(e.params)) ? e.params : {};
    e.targets = Array.isArray(e.targets) ? e.targets.filter(function (t) { return t && typeof t === 'object'; }) : [];
    e.credentials = Array.isArray(e.credentials) ? e.credentials.filter(function (c) { return c && typeof c === 'object'; }) : [];
    e.activities = Array.isArray(e.activities) ? e.activities.filter(function (a) { return a && typeof a === 'object'; }) : [];
    e.checklist = (e.checklist && typeof e.checklist === 'object' && !Array.isArray(e.checklist)) ? e.checklist : {};
    e.facts = Array.isArray(e.facts) ? e.facts.filter(function (f) { return f && typeof f === 'object' && f.kind; }) : [];
    var localFlagMap = {};
    e.facts.forEach(function (f) {
      if (f.kind === 'proof.captured' && f.value && f.value.flag && f.value.block) {
        var fl = String(f.value.flag).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var reLocal = new RegExp('===FLAG:[^\\r\\n]*(?:user|local)\\.txt::[\\s\\S]{0,160}?' + fl, 'i');
        if (reLocal.test(f.value.block)) {
          localFlagMap[f.value.flag] = 1;
          f.value.kind = 'objective.local_flag';
          f.value.slot = 'local';
          if (f.value.name === 'proof.txt') f.value.name = 'user.txt';
          if (f.value.path === 'proof.txt') f.value.path = 'user.txt';
        }
      }
    });
    function archiveLegacy(f, reason) {
      e.unresolvedLegacyFacts = e.unresolvedLegacyFacts || [];
      if (!e.unresolvedLegacyFacts.some(function (old) { return old.fact && old.fact.kind === f.kind && old.fact.scope === f.scope && JSON.stringify(old.fact.value) === JSON.stringify(f.value); })) {
        e.unresolvedLegacyFacts.push({fact:JSON.parse(JSON.stringify(f)),reason:reason});
      }
    }
    e.credentials.forEach(function(c) {
      var origin = String(c.method || c.via || c.notes || '');
      if ((/\blaps\b/i.test(origin) && !c.computer && !c.targetBinding) || (/gpp-decrypt/i.test(origin) && c.association !== 'single-gpp-source')) {
        c.unresolved = true;
        c.unresolvedReason = 'Legacy material lacks an unambiguous computer or principal association. Original material is retained.';
      }
    });
    e.facts = e.facts.filter(function (f) {
      var legacyValue = f.value || {}, legacyMethod = String(legacyValue.method || legacyValue.via || '');
      if (/^credential\.(available|plaintext)$/.test(f.kind) && ((/laps/i.test(legacyMethod) && !legacyValue.targetBinding && !legacyValue.computer)
        || (legacyMethod === 'gpp-decrypt' && legacyValue.association !== 'single-gpp-source'))) {
        archiveLegacy(f, 'Recovered legacy material had no reliable identity or computer binding. It remains an unresolved candidate.');
        f.kind = 'credential.candidate';
        f.value = Object.assign({}, legacyValue, {kind:'legacy-unresolved-material',association:'unresolved'});
      }
      var nxc = /^(nxc|pth)$/i.test(legacyMethod) && /^(smb|ldap|winrm|ssh|rdp|mssql|wmi)$/i.test(legacyValue.service || '');
      var loginOnlyShell = nxc && /^(?:foothold\.(?:windows|linux)|access\.shell)$/.test(f.kind);
      var unprovenAdmin = nxc && f.kind === 'access.admin' && legacyValue.authorizationProof !== 'nxc-pwn3d';
      if (unprovenAdmin) {
        var host = String(f.scope || '').replace(/^host:/,''), user = String(legacyValue.user || '').toLowerCase();
        var pwnProof = e.activities.some(function(a) {
          return activityTarget(a) === host && String(a.stdout || '').split(/\r?\n/).some(function(line) {
            var observed = /^\s*(SMB|LDAP|WINRM|SSH|RDP|MSSQL|WMI)\s+(\S+)\s+\d+\s+\S+\s+\[\+\]\s+(?:([^\s\\:]+)\\)?([^\s:]+):([\s\S]*?)\s+\(Pwn3d!\)/i.exec(line);
            if (!observed || observed[1].toLowerCase() !== String(legacyValue.service).toLowerCase() || observed[2] !== host || observed[4].toLowerCase() !== user) return false;
            if (String(observed[3] || '').toLowerCase() !== String(legacyValue.domain || legacyValue.realm || '').toLowerCase()) return false;
            var expected = legacyValue.nthash || legacyValue.hash || legacyValue.password || legacyValue.secret;
            return !!expected && (legacyValue.nthash || legacyValue.hash ? observed[5].toLowerCase() === String(expected).toLowerCase() : observed[5] === String(expected));
          });
        });
        if (pwnProof && legacyValue.service !== 'mssql') { f.value = Object.assign({}, legacyValue, {authorizationProof:'nxc-pwn3d'}); unprovenAdmin = false; }
        else if (pwnProof) {
          archiveLegacy(f, 'Database sysadmin authorization is separate from operating-system administrative access.');
          f.kind = 'db.admin'; f.value = Object.assign({}, legacyValue, {engine:'mssql',role:'sysadmin',authorizationProof:'nxc-pwn3d'}); unprovenAdmin = false;
        }
      }
      var materialOnly = /(?:^|[-_ ])(?:laps|gmsa|sam|ntds|dcsync|credential.dump|certipy.auth|gpp.decrypt)(?:$|[-_ ])/i.test(legacyMethod);
      var offlineProof = /^credential\.(validated|admin)$/.test(f.kind) && /^(john|hashcat|hashcat_ntlm)$/.test(legacyMethod);
      var inferredProof = materialOnly && /^(credential\.(validated|admin)|access\.(admin|system|root)|foothold\.)/.test(f.kind);
      if (offlineProof || inferredProof || loginOnlyShell || unprovenAdmin) {
        archiveLegacy(f, 'Recovered material, login alone, or an inferred role did not establish this access claim. Original evidence is retained.');
        return false;
      }
      // Older builds incorrectly promoted offline cracks to authenticated/admin proof.
      if (/^credential\.(validated|admin)$/.test(f.kind) && /^(john|hashcat|hashcat_ntlm)$/.test((f.value || {}).via || (f.value || {}).method || '')) return false;
      if (f.kind === 'objective.root_flag' && f.value && f.value.flag && localFlagMap[f.value.flag]) {
        f.kind = 'objective.local_flag';
        f.value.slot = 'local';
        if (f.value.name === 'proof.txt') f.value.name = 'user.txt';
        if (f.value.path === 'proof.txt') f.value.path = 'user.txt';
      }
      if ((f.kind === 'pivot.candidate' || f.kind === 'scan.local.routes' || f.kind === 'scan.local.interfaces') && f.value && Array.isArray(f.value.subnets)) {
        if (f.value.subnets.indexOf('0.0.0.0/3') >= 0) {
          f.value.subnets = f.value.subnets.filter(function (s) { return s !== '0.0.0.0/3' && s !== '10.0.0.0/8'; });
          if (f.kind === 'pivot.candidate' && (!Array.isArray(f.value.interfaces) || f.value.interfaces.length < 2) && f.value.subnets.length <= 1) {
            return false;
          }
        }
      }
      return true;
    });
    e.ui = (e.ui && typeof e.ui === 'object' && !Array.isArray(e.ui)) ? e.ui : {};
    e._rev = (e._rev || 0) + 1;
    if (!e.params.target && e.targets.length && (e.targets[0].ip || e.targets[0].id)) {
      e.params.target = e.targets[0].ip || e.targets[0].id;
    }
    migrateChecklist(e);
    if (OBOL.context) OBOL.context.normalize(e);
    return e;
  }

  function checklistKey(actionId, target) { return JSON.stringify([target || '*', actionId]); }
  function activityTarget(a) { return a.target || (/^host:/.test(a.scope || '') ? a.scope.slice(5) : ''); }
  function migrateChecklist(eng) {
    eng.checklist = eng.checklist || {};
    var hadLegacyKey = false;
    Object.keys(eng.checklist).forEach(function (id) {
      if (id.charAt(0) === '[') return;
      hadLegacyKey = true;
      var hosts = {};
      (eng.activities || []).forEach(function (a) {
        if ((a.action_id || a.actionId) === id && activityTarget(a)) hosts[activityTarget(a)] = true;
      });
      var ips = Object.keys(hosts);
      // Legacy manual ticks have no origin. Anchor them to their saved focus, never every host.
      var target = ips.length === 1 ? ips[0] : (eng.activeTarget || (eng.params && eng.params.target) || '*');
      var key = checklistKey(id, target);
      var state = eng.checklist[id];
      if (state === 'empty') state = 'empty:anon';
      if (!eng.checklist[key]) eng.checklist[key] = state;
      delete eng.checklist[id];
    });
    var runLegacyCheck = eng.checklistVersion !== 2 || hadLegacyKey;
    eng.checklistVersion = 2;
    if (runLegacyCheck && OBOL.context) Object.keys(eng.checklist).forEach(function(key) {
      if (!/^empty(?::|$)/.test(String(eng.checklist[key]))) return;
      var pair; try { pair = JSON.parse(key); } catch (e) { return; }
      var supported = (eng.activities || []).some(function(a) { return activityTarget(a) === pair[0] && (a.action_id || a.actionId) === pair[1] && a.outcome && a.outcome.retireMove; });
      if (!supported) {
        eng.unresolvedLegacyChecklist = eng.unresolvedLegacyChecklist || {};
        eng.unresolvedLegacyChecklist[key] = {state:eng.checklist[key],reason:'Legacy automatic retirement had no scoped, conclusive outcome. The move remains available.'};
        delete eng.checklist[key];
      }
    });
  }

  var STORE_DIR_METADATA_FACT_RE = /^ad\.(?:domain_known|base_dn|domain_sid|trusts)$/;
  function normalizeDomain(name) { return String(name || '').trim().toLowerCase().replace(/\.$/, ''); }
  function storeHasConflictingNonAdEvidence(hostFacts, targetObj) {
    if (targetObj) {
      if (targetObj.os && /\b(?:linux|unix|ubuntu|debian|centos|freebsd|openbsd|netbsd)\b/i.test(String(targetObj.os))) return true;
      var tDom = normalizeDomain(targetObj.domain);
      if (tDom && (tDom === 'workgroup' || tDom.indexOf('.') < 0)) return true;
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
        var hd = normalizeDomain(v.domain || v.name);
        if (hd && (hd === 'workgroup' || hd.indexOf('.') < 0)) hasWg = true;
      }
    }
    return hasWg || (hasLin && !hasWinOrAd);
  }
  function cleanStoreAdDomain(name) { return normalizeDomain(String(name || '').trim().replace(/0\.$/, '')); }
  function domainsForTarget(eng, ip, hostFacts, allFacts) {
    var domains = {};
    function take(name) { name = cleanStoreAdDomain(name); if (name && name !== 'domain' && name !== 'workgroup') domains[name] = true; }
    var targetObj = null;
    ((eng && eng.targets) || []).forEach(function (t) { if ((t.ip || t.id) === ip) { targetObj = t; take(t.domain); } });
    hostFacts.forEach(function (f) {
      if (f.state !== 'supported') return;
      var v = f.value || {};
      if (/^(host\.domain|ad\.domain_known)$/.test(f.kind)) take(v.domain || v.name);
      if (f.kind === 'host.fqdn' && String(v.fqdn || v.name || '').indexOf('.') >= 0) take(String(v.fqdn || v.name).split('.').slice(1).join('.'));
    });
    // A configured domain applies to its configured host, not every host in the engagement.
    if (!Object.keys(domains).length && eng && (eng.targets || []).length <= 1 && eng.params && eng.params.target === ip) take(eng.params.domain);
    if (!Object.keys(domains).length && Array.isArray(allFacts) && !storeHasConflictingNonAdEvidence(hostFacts, targetObj)) {
      var proven = {};
      allFacts.forEach(function (f) {
        if (!f || f.state !== 'supported' || f.kind !== 'ad.domain_known') return;
        var sc = String(f.scope || '');
        var dn = cleanStoreAdDomain((f.value && (f.value.name || f.value.domain)) || (sc.indexOf('domain:') === 0 ? sc.slice(7) : ''));
        if (dn && dn !== 'domain' && dn !== 'workgroup' && dn.indexOf('.') > 0) proven[dn] = true;
      });
      var pKeys = Object.keys(proven);
      if (pKeys.length === 1) take(pKeys[0]);
    }
    return domains;
  }
  function storeProjectDirMetadataFacts(allFacts, domainMap) {
    if (!Array.isArray(allFacts) || !domainMap || !Object.keys(domainMap).length) return [];
    var hostDom = {};
    allFacts.forEach(function (f) {
      if (!f || f.state !== 'supported' || f.kind !== 'ad.domain_known' || String(f.scope || '').indexOf('host:') !== 0) return;
      var d = cleanStoreAdDomain(f.value && (f.value.domain || f.value.name));
      if (d && d.indexOf('.') > 0) hostDom[String(f.scope).toLowerCase()] = d;
    });
    var out = [];
    allFacts.forEach(function (f) {
      if (!f || f.state !== 'supported' || !STORE_DIR_METADATA_FACT_RE.test(f.kind || '')) return;
      var sc = String(f.scope || ''), v = f.value || {}, fDom = '';
      if (sc.indexOf('domain:') === 0) fDom = cleanStoreAdDomain(sc.slice(7));
      if (!fDom || fDom === 'domain') fDom = cleanStoreAdDomain(v.domain || v.name);
      if (!fDom && f.kind === 'ad.base_dn' && (v.basedn || v.dn)) {
        var dcs = [], m, re = /\bDC=([A-Za-z0-9-]+)/gi, bdn = String(v.basedn || v.dn);
        while ((m = re.exec(bdn))) dcs.push(m[1].toLowerCase());
        if (dcs.length >= 2) fDom = dcs.join('.');
      }
      if (!fDom && sc.indexOf('host:') === 0) fDom = hostDom[sc.toLowerCase()] || '';
      if (!fDom || !domainMap[fDom]) return;
      if (sc.indexOf('domain:') === 0) {
        out.push(f);
      } else {
        out.push({ kind: f.kind, scope: 'domain:' + fDom, state: 'supported', source: f.source || 'domain-metadata', value: v });
      }
    });
    return out;
  }

  var STORE_AUTH_SURFACE_RE = /^(?:port:(?:21|22|23|25|80|88|110|135|139|143|389|443|445|465|587|636|993|995|1433|1521|2222|3268|3269|3306|3389|5432|5900|5901|5985|5986|6379|8000|8080|8443|8888|27017)|(?:http|https|smb|ssh|winrm|rdp|ldap|kerberos|ftp|mssql|mysql|postgres|postgresql|redis|oracle|vnc|mail|imap|pop3|smtp)\.reachable|web\.login_form|http\.(?:login|basic_auth)|ad\.dc_candidate)$/;

  function parseIpv4Bits(ipStr) {
    var m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$/.exec(String(ipStr || ''));
    if (!m) return null;
    var a = +m[1], b = +m[2], c = +m[3], d = +m[4];
    if (a > 255 || b > 255 || c > 255 || d > 255) return null;
    return ((a * 16777216) + (b * 65536) + (c * 256) + d) >>> 0;
  }

  function parseCidrSpec(cidrStr) {
    var m = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})\s*$/.exec(String(cidrStr || ''));
    if (!m) return null;
    var bits = parseIpv4Bits(m[1]), pfx = +m[2];
    if (bits === null || pfx < 1 || pfx > 32) return null;
    var mask = pfx === 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - pfx)) >>> 0);
    var net = (bits & mask) >>> 0;
    return {
      cidr: [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + pfx,
      net: net,
      mask: mask,
      pfx: pfx
    };
  }

  function ipMatchesCidr(ipStr, cidrStr) {
    var ipBits = parseIpv4Bits(ipStr);
    if (ipBits === null) return false;
    var spec = parseCidrSpec(cidrStr);
    if (!spec) return false;
    return ((ipBits & spec.mask) >>> 0) === spec.net;
  }

  function findPivotRoute(arr, ip) {
    var ipBits = parseIpv4Bits(ip);
    if (ipBits === null || !Array.isArray(arr) || !arr.length) return null;
    var byHost = Object.create(null);
    function ensureHost(h) {
      if (!byHost[h]) byHost[h] = { cidrs: Object.create(null), peers: Object.create(null), active: false, multihomed: false, explicitPeer: false, via: '' };
      return byHost[h];
    }
    function recordCidr(rec, raw, explicitTunnel, explicitDiscovered) {
      var spec = parseCidrSpec(raw);
      if (!spec) return;
      var prev = rec.cidrs[spec.cidr];
      if (!prev) {
        rec.cidrs[spec.cidr] = { cidr: spec.cidr, pfx: spec.pfx, explicitTunnel: !!explicitTunnel, explicitDiscovered: !!explicitDiscovered };
      } else {
        if (explicitTunnel) prev.explicitTunnel = true;
        if (explicitDiscovered) prev.explicitDiscovered = true;
      }
    }
    function recordPeer(rec, rawIp) {
      var s = String(rawIp || '').trim();
      if (parseIpv4Bits(s) !== null) rec.peers[s] = true;
    }
    for (var i = 0; i < arr.length; i++) {
      var f = arr[i];
      if (!f || f.state !== 'supported' || !f.scope || f.scope.indexOf('host:') !== 0) continue;
      var pHost = f.scope.slice(5);
      if (!pHost || pHost === ip || pHost === 'target') continue;
      var k = f.kind || '', v = f.value || {};
      if (/^(?:pivot\.active|tunnel\.(?:route|socks|established|dns))$/.test(k)) {
        var r1 = ensureHost(pHost);
        r1.active = true;
        if (!r1.via && (v.via || v.tool)) r1.via = String(v.via || v.tool);
        if (v.subnet) recordCidr(r1, v.subnet, true, false);
        if (v.cidr) recordCidr(r1, v.cidr, true, false);
        if (Array.isArray(v.subnets)) v.subnets.forEach(function (s) { recordCidr(r1, s, true, false); });
        if (Array.isArray(v.cidrs)) v.cidrs.forEach(function (s) { recordCidr(r1, s, true, false); });
      } else if (/^(?:pivot\.(?:subnet_discovered|candidate)|network\.subnet_candidate)$/.test(k)) {
        var r2 = ensureHost(pHost);
        var isExplicitSub = k === 'pivot.subnet_discovered' || k === 'network.subnet_candidate';
        if (v.subnet) recordCidr(r2, v.subnet, false, isExplicitSub);
        if (v.cidr) recordCidr(r2, v.cidr, false, isExplicitSub);
        if (Array.isArray(v.subnets)) v.subnets.forEach(function (s) { recordCidr(r2, s, false, isExplicitSub); });
        if (Array.isArray(v.cidrs)) v.cidrs.forEach(function (s) { recordCidr(r2, s, false, isExplicitSub); });
      } else if (/^(?:scan\.local\.(?:routes|interfaces)|host\.route)$/.test(k)) {
        var r3 = ensureHost(pHost);
        if (v.subnet) recordCidr(r3, v.subnet, false, false);
        if (v.cidr) recordCidr(r3, v.cidr, false, false);
        if (v.destination) recordCidr(r3, v.destination, false, false);
        if (Array.isArray(v.subnets)) v.subnets.forEach(function (s) { recordCidr(r3, s, false, false); });
        if (Array.isArray(v.cidrs)) v.cidrs.forEach(function (s) { recordCidr(r3, s, false, false); });
        if (Array.isArray(v.routes)) v.routes.forEach(function (rt) { recordCidr(r3, typeof rt === 'string' ? rt : (rt && (rt.cidr || rt.subnet || rt.destination)), false, false); });
        if (Array.isArray(v.interfaces)) v.interfaces.forEach(function (ifc) {
          if (ifc && ifc.cidr) recordCidr(r3, ifc.cidr, false, false);
          else if (ifc && ifc.ip && ifc.prefix) recordCidr(r3, ifc.ip + '/' + ifc.prefix, false, false);
        });
      } else if (k === 'host.multihomed') {
        ensureHost(pHost).multihomed = true;
      } else if (/^(?:host\.arp_(?:peer|neighbor)|scan\.local\.neighbors)$/.test(k)) {
        var r4 = ensureHost(pHost);
        if (/^host\.arp_(?:peer|neighbor)$/.test(k)) r4.explicitPeer = true;
        if (v.ip) recordPeer(r4, v.ip);
        if (v.peer) recordPeer(r4, v.peer);
        if (v.host) recordPeer(r4, v.host);
        if (Array.isArray(v.hosts)) v.hosts.forEach(function (p) { recordPeer(r4, p); });
        if (Array.isArray(v.peers)) v.peers.forEach(function (p) { recordPeer(r4, p); });
        if (Array.isArray(v.neighbors)) v.neighbors.forEach(function (p) { recordPeer(r4, typeof p === 'string' ? p : (p && p.ip)); });
      }
    }
    var best = null;
    Object.keys(byHost).forEach(function (pHost) {
      var rec = byHost[pHost];
      Object.keys(rec.cidrs).forEach(function (cidrKey) {
        var entry = rec.cidrs[cidrKey];
        if (!ipMatchesCidr(ip, entry.cidr)) return;
        if (ipMatchesCidr(pHost, entry.cidr) && !entry.explicitTunnel && !entry.explicitDiscovered) return;
        var score = (rec.active ? 1000 : 0) + entry.pfx;
        if (!best || score > best.score) {
          best = { pivotHost: pHost, subnet: entry.cidr, via: rec.via || (rec.active ? 'tunnel' : 'route'), active: !!rec.active, peerMatch: false, score: score };
        }
      });
      if (rec.peers[ip]) {
        var pHostBits = parseIpv4Bits(pHost);
        var cross24 = pHostBits === null || ((pHostBits & 0xFFFFFF00) >>> 0) !== ((ipBits & 0xFFFFFF00) >>> 0);
        if (rec.active || rec.multihomed || rec.explicitPeer || cross24) {
          var peerSpec = parseCidrSpec(ip + '/24');
          var matchedSub = (best && best.pivotHost === pHost && best.subnet) ? best.subnet : (peerSpec ? peerSpec.cidr : ip + '/24');
          var peerScore = (rec.active ? 1000 : 0) + 32;
          if (!best || peerScore >= best.score) {
            best = { pivotHost: pHost, subnet: matchedSub, via: rec.via || (rec.active ? 'tunnel' : 'arp'), active: !!rec.active, peerMatch: true, score: peerScore };
          }
        }
      }
    });
    if (!best) return null;
    return { pivotHost: best.pivotHost, subnet: best.subnet, via: best.via, active: best.active, peerMatch: best.peerMatch };
  }

  function storeTargetAliases(eng, ip, hostFacts) {
    var out = [String(ip || '').trim().toLowerCase()];
    function addName(n) {
      var s = String(n || '').trim().toLowerCase().replace(/\.$/, '').replace(/\$$/, '');
      if (!s) return;
      if (out.indexOf(s) < 0) out.push(s);
      var shortName = s.split('.')[0];
      if (shortName && out.indexOf(shortName) < 0) out.push(shortName);
    }
    ((eng && eng.targets) || []).forEach(function (t) {
      if ((t.ip || t.id) === ip) { addName(t.hostname); addName(t.fqdn); }
    });
    (hostFacts || []).forEach(function (f) {
      if (!f || f.state !== 'supported') return;
      if (f.kind === 'host.hostname' || f.kind === 'host.fqdn') {
        var v = f.value || {};
        addName(v.name || v.hostname);
        addName(v.fqdn);
      }
    });
    return out;
  }

  function extractCredMaterial(raw, scope) {
    if (OBOL.context && OBOL.context.material) return OBOL.context.material(raw, scope);
    raw = raw || {};
    var user = String(raw.user || raw.username || '').trim();
    var domain = String(raw.domain || raw.realm || '').trim();
    if (user.indexOf('\\') >= 0) { var up = user.split('\\'); domain = domain || up.shift(); user = up.join('\\'); }
    if (user.indexOf('@') > 0 && !domain) { domain = user.slice(user.indexOf('@') + 1); user = user.slice(0, user.indexOf('@')); }
    var password = raw.password != null ? String(raw.password) : raw.secret != null ? String(raw.secret) : '';
    var nthash = String(raw.nthash || raw.hash || '').trim();
    var type = String(raw.secretType || raw.secret_type || raw.type || '').trim().toUpperCase();
    if (/^(NT|NTHASH|NTLM)$/.test(type) && !nthash) { nthash = password; password = ''; }
    var accountType = raw.accountType || (raw.local ? 'local' : domain ? 'domain' : 'unknown');
    var rawScope = String(scope || raw.scope || '').trim();
    var originHost = String(raw.originHost || raw.reuseFrom || (/^host:/i.test(rawScope) && rawScope.toLowerCase() !== 'host:target' ? rawScope.slice(5) : '')).trim();
    var binding = String(raw.targetBinding || raw.computer || (accountType === 'local' ? raw.host || raw.target || '' : '')).trim();
    if (accountType === 'local' && !binding) binding = originHost || (/^host:/.test(scope || '') ? scope.slice(5) : '');
    var key = JSON.stringify([user.toLowerCase(), domain.toLowerCase(), password, nthash.toLowerCase(), accountType, binding.toLowerCase()]);
    var fp = (OBOL.facts && OBOL.facts.fingerprint) ? OBOL.facts.fingerprint(key) : key;
    return {
      id: 'cred-' + fp,
      user: user,
      domain: domain,
      password: password,
      nthash: nthash,
      accountType: accountType,
      targetBinding: binding,
      method: raw.method || raw.via || ''
    };
  }

  function isStoreLapsBoundElsewhere(v, originHost, aliases) {
    v = v || {};
    var tag = String(v.method || v.via || v.kind || v.source || '').trim();
    if (!/\blaps\b/i.test(tag) && !v.machineBound) return false;
    var bound = String(v.targetBinding || v.computer || originHost || '').trim().toLowerCase().replace(/\.$/, '').replace(/\$$/, '');
    if (!bound) return true;
    return aliases.indexOf(bound) < 0 && aliases.indexOf(bound.split('.')[0]) < 0;
  }

  function isStoreSshPassphraseOnly(v) {
    v = v || {};
    if (String(v.user || v.username || '').trim()) return false;
    return /ssh/i.test(String(v.kind || v.via || v.method || v.format || '')) || /^id_(?:rsa|ed25519|ecdsa|dsa)/i.test(String(v.file || v.path || '').trim());
  }

  function referencesBlob(value, id) {
    if (value === id) return true;
    if (!value || typeof value !== 'object') return false;
    return Object.keys(value).some(function (key) { return referencesBlob(value[key], id); });
  }
  // Also repairs legacy blob ownership and removes previously orphaned binary evidence.
  function reconcileBlobs(deletedIds, clearAll) {
    deletedIds = deletedIds || [];
    function ownerOf(rec) {
      if (rec.engagementId && deletedIds.indexOf(rec.engagementId) < 0 && _mem.engagements[rec.engagementId]) return rec.engagementId;
      return Object.keys(_mem.engagements).find(function (id) {
        return deletedIds.indexOf(id) < 0 && referencesBlob(_mem.engagements[id], rec.id);
      }) || '';
    }
    Object.keys(_mem.blobs).forEach(function (id) {
      var owner = clearAll ? '' : ownerOf(_mem.blobs[id]);
      if (owner) _mem.blobs[id].engagementId = owner; else delete _mem.blobs[id];
    });
    if (!_useIDB || !_db) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      try {
        var tx = _db.transaction(['engagements', 'blobs'], 'readwrite');
        var engagements = tx.objectStore('engagements'), blobs = tx.objectStore('blobs');
        if (clearAll) { engagements.clear(); blobs.clear(); }
        else {
          deletedIds.forEach(function (id) { engagements.delete(id); });
          var req = blobs.openCursor();
          req.onsuccess = function () {
            var cursor = req.result; if (!cursor) return;
            var rec = cursor.value, owner = ownerOf(rec);
            if (!owner) cursor.delete();
            else if (rec.engagementId !== owner) { rec.engagementId = owner; cursor.update(rec); }
            cursor.continue();
          };
        }
        tx.oncomplete = function () { resolve(); };
        tx.onerror = tx.onabort = function () { reject(tx.error || new Error('Evidence cleanup failed')); };
      } catch (err) { reject(err); }
    });
  }

  // ---- change notification ----
  function onChange(fn) { _listeners.push(fn); }
  function emit(reason) { _listeners.forEach(function (fn) { try { fn(reason); } catch (e) {} }); }

  // ---- persistence of the active engagement (debounced) ----
  var _saveTimer = null;
  var _dirtyIds = {};

  function flushSave() {
    if (_saveTimer) {
      clearTimeout(_saveTimer);
      _saveTimer = null;
    }
    var ids = Object.keys(_dirtyIds);
    _dirtyIds = {};
    if (!ids.length) return Promise.resolve();
    var promises = [];
    ids.forEach(function (id) {
      var eng = _mem.engagements[id];
      if (!eng) return;
      eng.updatedAt = Date.now();
      if (_useIDB && _db) {
        promises.push(idbPut('engagements', eng).catch(function () { snapshotFallback(); }));
      } else {
        snapshotFallback();
      }
    });
    return Promise.all(promises);
  }

  function scheduleSave(id) {
    var targetId = id || _activeId;
    if (targetId) {
      _dirtyIds[targetId] = true;
      var eng = _mem.engagements[targetId];
      if (eng) {
        eng.updatedAt = Date.now();
        eng._rev = (eng._rev || 0) + 1;
      }
    }
    if (_saveTimer) return;
    _saveTimer = setTimeout(function () {
      flushSave();
    }, 250);
  }
  function snapshotFallback() {
    // Best-effort: only used when IndexedDB is unavailable. May exceed quota on huge state.
    try { localStorage.setItem(LS_SNAPSHOT, JSON.stringify({ activeId: _activeId, engagements: _mem.engagements })); } catch (e) {}
  }

  // ---- public API ----
  var Store = {
    async init() {
      try {
        try { if (_db) _db.close(); } catch (e0) {} // never leak a prior connection (would block a reset)
        _db = await openDB();
        _useIDB = true;
        var list = await idbGetAll('engagements');
        list.forEach(function (e) { if (e && e.id) _mem.engagements[e.id] = normalizeEngagement(e); });
        var act = await idbGet('settings', 'activeEngagement');
        _activeId = (act && act.value) || null;
      } catch (e) {
        _useIDB = false;
        try {
          var snap = JSON.parse(localStorage.getItem(LS_SNAPSHOT) || 'null');
          if (snap) {
            var rawMap = snap.engagements || {};
            _mem.engagements = {};
            Object.keys(rawMap).forEach(function (k) {
              if (rawMap[k] && typeof rawMap[k] === 'object') {
                var ne = normalizeEngagement(rawMap[k]);
                ne.id = rawMap[k].id || k;
                _mem.engagements[ne.id] = ne;
              }
            });
            _activeId = snap.activeId || null;
          }
        } catch (e2) {}
      }
      // One-time cleanup: the removed legacy auto-migration left auto-imported engagements in
      // some browsers (never user-created). A first-time visitor should never land in an
      // "Imported engagement" — we don't import anything by default. Purge them so a fresh,
      // empty run is what loads. User-created engagements are untouched.
      Object.keys(_mem.engagements).forEach(function (id) {
        if (isLegacyImport(_mem.engagements[id])) {
          delete _mem.engagements[id];
          if (_useIDB && _db) idbDelete('engagements', id).catch(function () {});
          if (_activeId === id) _activeId = null;
        }
      });

      // ensure at least one (clean, empty) engagement exists as a starting point — unnamed, so it
      // shows as "No Run Yet" until the operator actually sets up a run (never a fake "Untitled Run").
      if (!Object.keys(_mem.engagements).length) {
        var eng = newEngagement('');
        _mem.engagements[eng.id] = eng;
        _activeId = eng.id;
        await this._persistEngagement(eng);
        await this.setSetting('activeEngagement', eng.id);
      }
      if (!_activeId || !_mem.engagements[_activeId]) {
        _activeId = Object.keys(_mem.engagements)[0];
      }
      await reconcileBlobs();
      return this;
    },

    usingIndexedDB() { return _useIDB; },

    // engagements
    listEngagements() {
      return Object.keys(_mem.engagements).map(function (k) { return _mem.engagements[k]; })
        .sort(function (a, b) { return b.updatedAt - a.updatedAt; });
    },
    active() { return _mem.engagements[_activeId] || null; },
    activeId() { return _activeId; },
    // One source of truth for how a run's name is shown. An unnamed draft, or a legacy placeholder
    // name from before this change, reads as "Set Up Engagement..." everywhere (chip, selector, library).
    runLabel(eng) {
      var n = eng && eng.name != null ? String(eng.name).trim() : '';
      return (!n || /^(untitled run|new engagement|no run yet|set up engagement\.{0,3})$/i.test(n)) ? 'Set Up Engagement...' : n;
    },
    isConfigured(eng) {
      var e = eng === undefined ? this.active() : eng;
      if (!e) return false;
      var n = e.name != null ? String(e.name).trim() : '';
      return !!n && !/^(untitled run|new engagement|no run yet|set up engagement\.{0,3})$/i.test(n);
    },
    async setActive(id) {
      if (_mem.engagements[id]) {
        await flushSave();
        _activeId = id;
        await this.setSetting('activeEngagement', id);
        emit('active');
      }
    },
    async createEngagement(name, profile) {
      var eng = newEngagement(name);
      if (profile && typeof profile === 'object') {
        eng.profile = Object.assign(eng.profile, profile);
        if (profile.platform) eng.params.platform = profile.platform;
      }
      _mem.engagements[eng.id] = eng;
      _activeId = eng.id;
      await this._persistEngagement(eng);
      await this.setSetting('activeEngagement', eng.id);
      emit('active');
      return eng;
    },
    async deleteEngagement(id) {
      await flushSave();
      await reconcileBlobs([id]);
      delete _mem.engagements[id];
      var remaining = Object.keys(_mem.engagements);
      if (!remaining.length) {
        var fresh = newEngagement('');
        _mem.engagements[fresh.id] = fresh;
        _activeId = fresh.id;
        await this._persistEngagement(fresh);
      } else if (_activeId === id || !_mem.engagements[_activeId]) {
        _activeId = remaining[0];
      }
      await this.setSetting('activeEngagement', _activeId).catch(function () {});
      if (!_useIDB || !_db) snapshotFallback();
      emit('active');
    },
    // Delete every engagement (keeps appearance prefs). The caller reloads; init() then seeds a
    // fresh, empty "Untitled Run".
    async clearEngagements() {
      await flushSave();
      await reconcileBlobs([], true);
      _mem.engagements = {}; _mem.blobs = {}; _activeId = null;
      if (_useIDB && _db) {
        await this.setSetting('activeEngagement', null).catch(function () {});
      } else { snapshotFallback(); }
      emit('active');
    },
    // Full factory reset: erase ALL obol data in this browser — the IndexedDB database (engagements,
    // blobs, settings) plus every obol localStorage/sessionStorage key. The caller reloads afterward.
    async resetAll() {
      if (_saveTimer) clearTimeout(_saveTimer);
      _saveTimer = null; _dirtyIds = {};
      _mem = { engagements: {}, blobs: {}, settings: {} }; _activeId = null;
      try {
        for (var i = localStorage.length - 1; i >= 0; i--) {
          var k = localStorage.key(i);
          if (k && (/^obol(?:[.:-]|$)/i.test(k) || k === LS_PREFS || k === LS_SNAPSHOT)) localStorage.removeItem(k);
        }
      } catch (e) {}
      try {
        for (var si = sessionStorage.length - 1; si >= 0; si--) {
          var sk = sessionStorage.key(si);
          if (sk && /^obol(?:[.:-]|$)/i.test(sk)) sessionStorage.removeItem(sk);
        }
      } catch (e2) {}
      try { if (_db) { _db.close(); _db = null; } } catch (e3) {}
      await new Promise(function (resolve) {
        try {
          if (typeof indexedDB === 'undefined') { resolve(); return; }
          var req = indexedDB.deleteDatabase(DB_NAME);
          req.onsuccess = req.onerror = req.onblocked = function () { resolve(); };
        } catch (e4) { resolve(); }
      });
    },
    async _persistEngagement(eng) {
      if (_useIDB && _db) { try { await idbPut('engagements', eng); return; } catch (e) {} }
      snapshotFallback();
    },

    // ---- export / import (workspace portability) ----
    exportEngagement(id) {
      var e = _mem.engagements[id || _activeId];
      if (!e) return null;
      return { format: 'obol-engagement', version: 1, exportedAt: Date.now(), engagement: JSON.parse(JSON.stringify(e)) };
    },
    exportAll() {
      return {
        format: 'obol-workspace', version: 1, exportedAt: Date.now(),
        engagements: Object.keys(_mem.engagements).map(function (k) { return JSON.parse(JSON.stringify(_mem.engagements[k])); }),
      };
    },
    // Accepts a single engagement, {engagement}, or {engagements:[...]}. Always assigns fresh ids
    // (never clobbers existing engagements). Returns the count imported.
    async importData(data) {
      var list = [];
      if (!data || typeof data !== 'object') return 0;
      if (Array.isArray(data)) list = data;
      else if (Array.isArray(data.engagements)) list = data.engagements;
      else if (data.engagement && typeof data.engagement === 'object' && !Array.isArray(data.engagement)) list = [data.engagement];
      else if (data.id || Array.isArray(data.facts) || Array.isArray(data.targets) || typeof data.name === 'string') list = [data];   // a bare engagement object
      var added = 0;
      for (var i = 0; i < list.length; i++) {
        var raw = list[i];
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)
          || (typeof raw.name !== 'string' && !raw.id && !Array.isArray(raw.facts) && !Array.isArray(raw.targets))) continue;
        var cloned;
        try { cloned = JSON.parse(JSON.stringify(raw)); } catch (err) { continue; }
        var e = normalizeEngagement(cloned);
        e.id = uid('eng');
        e.importedAt = Date.now();
        e.updatedAt = Date.now();
        delete e.migratedFrom;
        _mem.engagements[e.id] = e;
        await this._persistEngagement(e);
        _activeId = e.id;
        added++;
      }
      if (added) { await this.setSetting('activeEngagement', _activeId); emit('active'); }
      return added;
    },

    // mutate the active engagement then persist + notify
    update(mutator, reason) {
      var eng = _mem.engagements[_activeId];
      if (!eng) return;
      var contextBefore = OBOL.context ? OBOL.context.beforeUpdate(eng) : null;
      mutator(eng);
      if (OBOL.context) OBOL.context.reconcile(eng, contextBefore);
      scheduleSave();
      emit(reason || 'update');
    },

    // ---- facts (as OBOL.facts, stored serialized on the engagement) ----
    factSet() {
      var eng = this.active();
      var arr = ((eng && eng.facts) || []).filter(function (f) { return f && typeof f === 'object' && f.kind; });
      var fs = new OBOL.facts.FactSet(arr.map(OBOL.facts.factFromJson));
      return fs;
    },
    // Active target focus for multi-target engagements: null / '' means engagement-wide ('all'),
    // while an IP string focuses the coach and command templating on that specific box.
    activeTarget() {
      var eng = this.active();
      return (eng && eng.activeTarget) || null;
    },
    setActiveTarget(ip) {
      this.update(function (eng) {
        var clean = ip ? String(ip).trim() : null;
        eng.activeTarget = clean;
        if (clean) {
          eng.params = eng.params || {};
          eng.params.target = clean;
        }
      }, 'active-target');
    },
    // In-place Target Edit & Atomic Re-IP Migration:
    // Updates IP, hostname, domain, OS (and optional LHOST) for a target. When the IP changes
    // (e.g., lab instance respawned on a new address), migrates all scoped facts, checklist progress,
    // credentials, context selections, screenshots, and Run Log activities (rewriting commands to the
    // new IP while preserving originalCommand and keeping raw stdout untouched).
    editTarget(oldIpOrId, patch) {
      patch = patch || {};
      var eng = this.active();
      if (!eng) return { ok: false, error: 'No active engagement' };
      var key = String(oldIpOrId || '').trim();
      if (!key) return { ok: false, error: 'Missing target identifier' };

      function replaceIpExact(str, fromIp, toIp) {
        if (!str || !fromIp || !toIp || fromIp === toIp) return str;
        var escIp = String(fromIp).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        var re = new RegExp('(^|[^0-9.])' + escIp + '(?![0-9.])', 'g');
        return String(str).replace(re, '$1' + toIp);
      }

      var result = {
        ok: true,
        reIp: false,
        oldIp: key,
        newIp: key,
        hostname: '',
        domain: '',
        os: '',
        lhostChanged: false,
        oldLhost: '',
        newLhost: '',
        rewrittenCommands: 0,
      };

      this.update(function (e) {
        e.targets = e.targets || [];
        e.params = e.params || {};
        var t = e.targets.find(function (x) { return x && (x.ip === key || x.id === key); });
        if (!t) {
          t = { id: uid('t'), ip: key, hostname: '', domain: '', os: '' };
          e.targets.push(t);
        }
        var oldIp = String(t.ip || t.id || key).trim();
        var newIp = patch.ip != null && String(patch.ip).trim() ? String(patch.ip).trim() : oldIp;
        var reIp = newIp !== oldIp;

        var oldLhost = String(e.params.lhost || '').trim();
        var newLhost = patch.lhost !== undefined ? String(patch.lhost || '').trim() : oldLhost;
        var lhostChanged = !!(newLhost && oldLhost && newLhost !== oldLhost);
        if (patch.lhost !== undefined && newLhost) {
          e.params.lhost = newLhost;
        }

        // If newIp already exists as another target record in scope, merge cleanly into `t`
        if (reIp) {
          var dupIdx = e.targets.findIndex(function (x) { return x && x !== t && (x.ip === newIp || x.id === newIp); });
          if (dupIdx >= 0) {
            var dup = e.targets[dupIdx];
            if (!t.hostname && dup.hostname) t.hostname = dup.hostname;
            if (!t.domain && dup.domain) t.domain = dup.domain;
            if (!t.os && dup.os) t.os = dup.os;
            if (Array.isArray(dup.previousIps)) {
              t.previousIps = (t.previousIps || []).concat(dup.previousIps);
            }
            e.targets.splice(dupIdx, 1);
          }
          var prevList = Array.isArray(t.previousIps) ? t.previousIps.slice() : [];
          if (prevList.indexOf(oldIp) < 0) prevList.push(oldIp);
          prevList = prevList.filter(function (p) { return p && p !== newIp; });
          t.previousIps = prevList;
          t.lastReIpAt = Date.now();
          t.ip = newIp;
        }

        if (patch.hostname !== undefined) t.hostname = String(patch.hostname || '').trim();
        if (patch.domain !== undefined) t.domain = String(patch.domain || '').trim().replace(/\.$/, '');
        if (patch.os !== undefined) t.os = String(patch.os || '').trim();

        var oldScope = 'host:' + oldIp;
        var newScope = 'host:' + newIp;

        // 1. Migrate facts scope & host bindings
        if (reIp && Array.isArray(e.facts)) {
          e.facts.forEach(function (f) {
            if (!f || typeof f !== 'object') return;
            if (f.scope === oldScope) f.scope = newScope;
            if (f.value && typeof f.value === 'object' && !Array.isArray(f.value)) {
              if (f.value.host === oldIp) f.value.host = newIp;
              if (f.value.ip === oldIp) f.value.ip = newIp;
              if (f.value.target === oldIp) f.value.target = newIp;
              if (f.value.targetBinding === oldIp) f.value.targetBinding = newIp;
            }
          });
        }

        // 2. Sync edited identity fields (hostname, domain, os) into facts for newScope
        if (OBOL.facts) {
          var SUP = OBOL.facts.ProofState ? OBOL.facts.ProofState.SUPPORTED : 'supported';
          var fs = new OBOL.facts.FactSet((e.facts || []).filter(Boolean).map(OBOL.facts.factFromJson).filter(Boolean));
          if (patch.hostname !== undefined) {
            fs.facts = fs.facts.filter(function (f) { return !(f.scope === newScope && f.kind === 'host.hostname'); });
            if (t.hostname) {
              var hParts = t.hostname.split('.');
              fs.add(OBOL.facts.makeFact({
                kind: 'host.hostname',
                scope: newScope,
                value: { name: hParts[0], fqdn: hParts.length > 1 ? t.hostname : (t.domain ? hParts[0] + '.' + t.domain : '') },
                state: SUP,
                source: 'target-edit',
              }));
            }
          }
          if (patch.domain !== undefined) {
            fs.facts = fs.facts.filter(function (f) { return !(f.scope === newScope && f.kind === 'host.domain'); });
            if (t.domain) {
              fs.add(OBOL.facts.makeFact({
                kind: 'host.domain',
                scope: newScope,
                value: { domain: t.domain },
                state: SUP,
                source: 'target-edit',
              }));
            }
          }
          if (patch.os !== undefined) {
            fs.facts = fs.facts.filter(function (f) { return !(f.scope === newScope && (f.kind === 'host.os' || f.kind === 'host.os_hint') && f.source === 'target-edit'); });
            if (t.os) {
              var fam = /win/i.test(t.os) ? 'windows' : (/linux|ubuntu|debian|centos|redhat|rhel|fedora|arch|kali|freebsd|unix/i.test(t.os) ? 'linux' : '');
              fs.add(OBOL.facts.makeFact({
                kind: 'host.os',
                scope: newScope,
                value: { os: t.os, family: fam },
                state: SUP,
                source: 'target-edit',
              }));
            }
          }
          fs.add(OBOL.facts.makeFact({ kind: 'target.configured', scope: newScope, source: 'targets' }));
          e.facts = fs.facts.map(OBOL.facts.factToJson);
        }

        // 3. Migrate checklist keys
        if (reIp && e.checklist && typeof e.checklist === 'object') {
          migrateChecklist(e);
          Object.keys(e.checklist).forEach(function (ck) {
            var pair; try { pair = JSON.parse(ck); } catch (err) { return; }
            if (!Array.isArray(pair) || pair[0] !== oldIp) return;
            var newCk = checklistKey(pair[1], newIp);
            if (!e.checklist[newCk] || e.checklist[ck] === 'done') {
              e.checklist[newCk] = e.checklist[ck];
            }
            delete e.checklist[ck];
          });
        }

        // 4. Migrate credentials & contextSelections
        if (reIp && Array.isArray(e.credentials)) {
          e.credentials.forEach(function (c) {
            if (!c || typeof c !== 'object') return;
            if (c.scope === oldScope) c.scope = newScope;
            if (c.targetBinding === oldIp) c.targetBinding = newIp;
          });
        }
        if (e.contextSelections && typeof e.contextSelections === 'object') {
          var cs = e.contextSelections;
          if (reIp) {
            if (cs.byTarget && cs.byTarget[oldIp] !== undefined) {
              if (cs.byTarget[newIp] === undefined) cs.byTarget[newIp] = cs.byTarget[oldIp];
              delete cs.byTarget[oldIp];
            }
            if (cs.targetDomains && cs.targetDomains[oldIp] !== undefined) {
              if (cs.targetDomains[newIp] === undefined) cs.targetDomains[newIp] = cs.targetDomains[oldIp];
              delete cs.targetDomains[oldIp];
            }
            if (cs.anonymousByTarget && cs.anonymousByTarget[oldIp] !== undefined) {
              if (cs.anonymousByTarget[newIp] === undefined) cs.anonymousByTarget[newIp] = cs.anonymousByTarget[oldIp];
              delete cs.anonymousByTarget[oldIp];
            }
          }
          if (patch.domain !== undefined) {
            cs.targetDomains = cs.targetDomains || {};
            if (t.domain) cs.targetDomains[newIp] = t.domain;
            else delete cs.targetDomains[newIp];
          }
        }

        // 5. Migrate Run Log activities & rewrite commands (keeping stdout untouched)
        var rewritten = 0;
        (e.activities || []).forEach(function (a) {
          if (!a || typeof a !== 'object') return;
          var isTargetAct = (a.target === oldIp || a.target === newIp || a.scope === oldScope || a.scope === newScope);
          if (reIp && (a.target === oldIp || a.scope === oldScope)) {
            a.target = newIp;
            a.scope = newScope;
          }
          if (a.command) {
            var nextCmd = a.command;
            if (reIp && isTargetAct) {
              nextCmd = replaceIpExact(nextCmd, oldIp, newIp);
            }
            if (lhostChanged) {
              nextCmd = replaceIpExact(nextCmd, oldLhost, newLhost);
            }
            if (nextCmd !== a.command) {
              if (!a.originalCommand) a.originalCommand = a.command;
              a.command = nextCmd;
              if (reIp && isTargetAct) a.reIpFrom = a.reIpFrom || oldIp;
              if (lhostChanged) a.reLhostFrom = a.reLhostFrom || oldLhost;
              rewritten++;
            }
          }
        });

        // 6. Migrate screenshots
        if (reIp && Array.isArray(e.screenshots)) {
          e.screenshots.forEach(function (s) {
            if (s && s.target === oldIp) s.target = newIp;
          });
        }

        // 7. Update active target & params
        if (reIp) {
          if (e.params.target === oldIp || !e.params.target) e.params.target = newIp;
          if (e.activeTarget === oldIp || !e.activeTarget) e.activeTarget = newIp;
          try {
            var oldLsKey = 'obol.apath:' + e.id + ':' + oldIp;
            var newLsKey = 'obol.apath:' + e.id + ':' + newIp;
            var remembered = localStorage.getItem(oldLsKey);
            if (remembered != null) {
              localStorage.setItem(newLsKey, remembered);
              localStorage.removeItem(oldLsKey);
            }
          } catch (err) {}
        }
        if (patch.domain !== undefined && (e.params.target === newIp || e.targets.length <= 1)) {
          e.params.domain = t.domain || '';
        }

        result.reIp = reIp;
        result.oldIp = oldIp;
        result.newIp = newIp;
        result.hostname = t.hostname || '';
        result.domain = t.domain || '';
        result.os = t.os || '';
        result.lhostChanged = lhostChanged;
        result.oldLhost = oldLhost;
        result.newLhost = newLhost;
        result.rewrittenCommands = rewritten;
      }, 'targets');

      return result;
    },
    resolvedContext(opts) {
      return OBOL.context.resolve(Object.assign({ engagement: this.active() }, opts || {}));
    },
    selectCredential(id, target) {
      this.update(function (eng) { OBOL.context.select(eng, id, target); }, 'credential-selection');
    },
    setCredentialPin(enabled) {
      this.update(function (eng) { OBOL.context.setPin(eng, !!enabled); }, 'credential-pin');
    },
    credentialPin() {
      var selected = OBOL.context && OBOL.context.pin(this.active());
      return { enabled: selected !== undefined, credentialId: selected === undefined ? null : selected };
    },
    checklistKey: checklistKey,
    setChecklist(actionId, state, target) {
      this.update(function (eng) {
        migrateChecklist(eng);
        eng.checklist[checklistKey(actionId, target || eng.activeTarget || (eng.params && eng.params.target))] = state;
      }, 'done');
    },
    doneIdsForTarget(target, facts, engagement) {
      var eng = engagement || this.active() || {}, out = {};
      migrateChecklist(eng);
      target = target || eng.activeTarget || (eng.params && eng.params.target) || '*';
      var targetFacts = this.factSetForTarget ? this.factSetForTarget(target) : null;
      var epochTarget = targetFacts ? OBOL.pack.accessEpoch(targetFacts) : null;
      var epochFacts = facts ? OBOL.pack.accessEpoch(facts) : epochTarget;
      Object.keys(eng.checklist).forEach(function (key) {
        var pair; try { pair = JSON.parse(key); } catch (e) { return; }
        if (!Array.isArray(pair) || pair[0] !== target) return;
        var state = eng.checklist[key], id = pair[1];
        if (state === 'done'
          || (epochFacts && state === 'empty:' + epochFacts)
          || (epochTarget && state === 'empty:' + epochTarget)) out[id] = true;
        if (state === 'empty' && !(eng.activities || []).some(function (a) {
          return (a.action_id || a.actionId) === id && activityTarget(a) === target && (a.addedCount > 0 || (a.produced || []).some(function (k) { return !/^(blocker\.|credential\.validation$)/.test(k); }));
        })) out[id] = true;
      });
      return out;
    },
    pivotRouteForTarget(ip) {
      var targetIp = String(ip || '').trim();
      if (!targetIp) return null;
      var eng = this.active();
      var arr = ((eng && eng.facts) || []).filter(function (f) { return f && typeof f === 'object' && f.kind; });
      return findPivotRoute(arr, targetIp);
    },
    // A per-target FactSet: this host's facts + applicable domain-/engagement-scoped facts.
    // Unscanned targets in multi-target engagements do not inherit other hosts' domain credentials/loot
    // until they have been scanned, and non-AD Linux hosts do not inherit Windows AD/DC compromise facts.
    factSetForTarget(ip) {
      var eng = this.active();
      var arr = ((eng && eng.facts) || []).filter(function (f) { return f && typeof f === 'object' && f.kind; });
      var hostScope = 'host:' + ip;
      var targetList = (eng && eng.targets) || [];
      var multiTarget = targetList.length > 1 || arr.some(function (f) {
        return f && f.scope && f.scope.indexOf('host:') === 0 && f.scope !== hostScope && f.scope !== 'host:target';
      });
      var hostFacts = arr.filter(function (f) { return f && (f.scope === hostScope || (!multiTarget && f.scope === 'host:target')); });
      var hasHostActivity = hostFacts.some(function (f) {
        return f.state === 'supported' && f.kind.indexOf('target.') !== 0
          && f.kind !== 'host.hostname' && f.kind !== 'host.domain' && f.kind !== 'host.fqdn'
          && !((f.kind === 'host.os' || f.kind === 'host.os_hint') && f.source === 'target-edit');
      });
      if (multiTarget && !hasHostActivity) {
        var isRegTarget = targetList.some(function (t) { return (t.ip || t.id) === ip; });
        if (isRegTarget) {
          var unscannedDomains = domainsForTarget(eng, ip, hostFacts, arr);
          if (Object.keys(unscannedDomains).length) {
            var dirFacts = storeProjectDirMetadataFacts(arr, unscannedDomains);
            if (dirFacts.length) {
              return new OBOL.facts.FactSet(hostFacts.concat(dirFacts).map(OBOL.facts.factFromJson));
            }
          }
        }
        return new OBOL.facts.FactSet(hostFacts.map(OBOL.facts.factFromJson));
      }
      var isLinux = hostFacts.some(function (f) {
        if (f.state !== 'supported') return false;
        if (f.kind === 'foothold.linux' || f.kind === 'os.linux') return true;
        if (f.kind === 'host.os_family' || f.kind === 'host.os_hint') {
          var fam = String((f.value && f.value.family) || '').toLowerCase();
          return fam === 'linux' || fam === 'unix';
        }
        return false;
      }) && !hostFacts.some(function (f) {
        return f.state === 'supported' && (f.kind === 'foothold.windows' || f.kind === 'os.windows'
          || ((f.kind === 'host.os_family' || f.kind === 'host.os_hint') && String((f.value && f.value.family) || '').toLowerCase() === 'windows'));
      });
      var hasAdOrSmb = hostFacts.some(function (f) {
        return f.state === 'supported' && /^(smb|ldap|kerberos|winrm)\.reachable$|^ad\.dc_candidate$|^port:(445|389|636|88|5985|5986)$/.test(f.kind);
      });
      var isDc = !multiTarget || hostFacts.some(function (f) {
        return f.state === 'supported' && /^(kerberos\.reachable|ad\.dc_candidate|port:(88|3268|3269))$/.test(f.kind);
      });
      var DC_ONLY_DOMAIN_RE = /^(access\.admin|loot\.ntds|hash\.krbtgt|persistence\.domain|ad\.(acl_lead|control_paths|attack_paths|group_joined|domain_control)|adcs\.vulnerable)$/;
      var targetDomains = domainsForTarget(eng, ip, hostFacts, arr);
      var sel = arr.filter(function (f) {
        var s = f.scope || '';
        if (s === hostScope || (!multiTarget && s === 'host:target')) return true;
        if (s === '' || s.indexOf('scope:') === 0) return !multiTarget || hasHostActivity;
        if (s.indexOf('domain:') === 0) {
          if (!multiTarget && s === 'domain:domain' && /^(credential\.|dns\.)/.test(f.kind)) return true;
          if (!targetDomains[normalizeDomain(s.slice(7))]) return false;
          if (isLinux && !hasAdOrSmb) {
            return s === 'domain:domain' && (f.kind.indexOf('credential.') === 0 || f.kind.indexOf('dns.') === 0);
          }
          if (!isDc && DC_ONLY_DOMAIN_RE.test(f.kind)) return false;
          return true;
        }
        return false;
      });
      var mapped = sel.map(OBOL.facts.factFromJson);
      if (multiTarget && hasHostActivity && !(isLinux && !hasAdOrSmb) && Object.keys(targetDomains).length) {
        var projDir = storeProjectDirMetadataFacts(arr, targetDomains);
        for (var pdi = 0; pdi < projDir.length; pdi++) {
          var pdf = OBOL.facts.factFromJson(projDir[pdi]);
          if (pdf && !mapped.some(function (mf) { return mf && mf.state === 'supported' && mf.kind === pdf.kind; })) {
            mapped.push(pdf);
          }
        }
      }
      if (multiTarget && hasHostActivity && OBOL.facts && OBOL.facts.makeFact) {
        var piv = findPivotRoute(arr, ip);
        if (piv && !mapped.some(function (f) { return f && f.state === 'supported' && f.kind === 'tunnel.reachable_via_pivot'; })) {
          mapped.push(OBOL.facts.makeFact({
            kind: 'tunnel.reachable_via_pivot',
            scope: hostScope,
            state: 'supported',
            source: 'pivot-projection',
            value: { pivotHost: piv.pivotHost, subnet: piv.subnet, via: piv.via, active: piv.active }
          }));
        }
        var aliases = storeTargetAliases(eng, ip, hostFacts);
        var otherSources = [];
        for (var oi = 0; oi < arr.length; oi++) {
          var of = arr[oi];
          if (!of || of.state !== 'supported' || !of.scope || of.scope.indexOf('host:') !== 0 || of.scope === 'host:target') continue;
          var ohost = of.scope.slice(5);
          if (ohost === ip || aliases.indexOf(ohost.toLowerCase().replace(/\$$/, '')) >= 0) continue;
          if (/^credential\.(?:available|plaintext|ntlm_hash|ssh_key|certificate)$|^loot\.ssh_key$|^ssh\.private_key$/.test(of.kind)) {
            otherSources.push({ fact: of, originHost: ohost });
          }
        }
        if (otherSources.length) {
          var hasAuthSurface = hostFacts.some(function (f) { return f && f.state === 'supported' && STORE_AUTH_SURFACE_RE.test(f.kind); });
          var hasSshSurface = hostFacts.some(function (f) { return f && f.state === 'supported' && /^(?:port:(?:22|2222)|ssh\.reachable)$/.test(f.kind); });
          var destHasAdSurface = Object.keys(targetDomains).some(function (dk) { return dk.indexOf('.') > 0 && dk !== 'workgroup' && dk !== 'domain'; }) || hostFacts.some(function (f) {
            if (!f || f.state !== 'supported') return false;
            if (/^(?:kerberos\.reachable|ldap\.reachable|ad\.dc_candidate|ad\.domain_controller|port:(?:88|389|636|3268|3269))$/.test(f.kind)) return true;
            if (f.kind === 'ad.domain_known' && f.value && String(f.value.name || '').indexOf('.') > 0) return true;
            if (f.kind === 'host.domain' && f.value && String(f.value.domain || f.value.name || '').indexOf('.') > 0 && String(f.value.domain || f.value.name || '').toLowerCase() !== 'workgroup') return true;
            return false;
          });
          var destIsLinux = hostFacts.some(function (f) {
            if (!f || f.state !== 'supported') return false;
            if (/^(?:foothold\.linux|os\.linux)$/.test(f.kind)) return true;
            if ((f.kind === 'host.os_family' || f.kind === 'host.os_hint') && f.value && /^(?:linux|unix|ubuntu|debian|centos|freebsd)$/i.test(String(f.value.family || f.value.os || ''))) return true;
            return false;
          }) && !hostFacts.some(function (f) {
            return f && f.state === 'supported' && /^(?:foothold\.windows|os\.windows|winrm\.reachable|port:5985)$/.test(f.kind);
          });
          var destIsWorkgroupWin = !destHasAdSurface && !destIsLinux && hostFacts.some(function (f) {
            if (!f || f.state !== 'supported') return false;
            if (f.kind === 'host.domain' && f.value) {
              var hd = String(f.value.domain || f.value.name || '').trim();
              if (hd && (hd.toLowerCase() === 'workgroup' || hd.indexOf('.') < 0)) return true;
            }
            if (f.kind === 'smb.signing' && f.value && f.value.workgroup === true) return true;
            return false;
          });
          var hasNativeCred = mapped.some(function (f) {
            if (!f || f.state !== 'supported' || !/^credential\.(?:available|plaintext|ntlm_hash)$/.test(f.kind)) return false;
            var fv = f.value || {};
            if (fv.unvalidatedOnTarget) return false;
            return !!(String(fv.user || fv.username || '').trim() && (fv.password || fv.secret || fv.nthash || fv.hash));
          });
          var isAnon = !!(((eng && eng.contextSelections && eng.contextSelections.anonymousByTarget) || {})[ip]);
          var hasPinnedOrSelected = (OBOL.context && OBOL.context.pin(eng) !== undefined)
            || !!(OBOL.context && OBOL.context.selectedId(eng, ip))
            || isAnon
            || hasNativeCred;
          var seenReuse = Object.create(null), seenAvail = Object.create(null), seenKey = Object.create(null);
          mapped.forEach(function (bf) {
            if (!bf || bf.state !== 'supported') return;
            var bv = bf.value || {};
            if (bf.kind === 'credential.reuse_candidate') {
              seenReuse[[String(bv.user || '').toLowerCase(), bv.password || bv.secret || '', String(bv.nthash || '').toLowerCase(), String(bv.keyPath || '').trim()].join('|')] = 1;
            } else if (bf.kind === 'credential.available') {
              seenAvail[extractCredMaterial(bv, bf.scope).id] = 1;
            } else if (bf.kind === 'loot.ssh_key') {
              seenKey[String(bv.keyPath || bv.path || bv.file || '').trim()] = 1;
            }
          });
          var hasCertKey = mapped.some(function (bf) { return bf && bf.state === 'supported' && bf.kind === 'credential.certificate'; });
          for (var si = 0; si < otherSources.length; si++) {
            var srcFact = otherSources[si].fact, srcHost = otherSources[si].originHost, sv = srcFact.value || {};
            if (/^credential\.(?:available|plaintext|ntlm_hash)$/.test(srcFact.kind)) {
              if (sv.unresolved || sv.association === 'unresolved') continue;
              if (isStoreLapsBoundElsewhere(sv, srcHost, aliases) || isStoreSshPassphraseOnly(sv)) continue;
              var mat = extractCredMaterial(sv, srcFact.scope);
              if (!mat.password && !mat.nthash) continue;
              var srcHasAdFact = arr.some(function (af) {
                return af && af.state === 'supported' && af.scope === ('host:' + srcHost) && /^(?:ad\.domain_known|ad\.dc_candidate|kerberos\.reachable|ldap\.reachable)$/.test(af.kind);
              });
              var srcIsAdDomainCred = (!!mat.domain && mat.domain.indexOf('.') > 0 && String(mat.domain).toLowerCase() !== 'workgroup')
                || /^domain:/i.test(srcFact.scope || '')
                || (srcHasAdFact && mat.accountType !== 'local');
              var specCrossDomain = !!(srcIsAdDomainCred && ((destIsLinux && !destHasAdSurface) || destIsWorkgroupWin));
              var rKey = [String(mat.user || '').toLowerCase(), mat.password, String(mat.nthash || '').toLowerCase(), ''].join('|');
              if (!seenReuse[rKey]) {
                seenReuse[rKey] = 1;
                mapped.push(OBOL.facts.makeFact({
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
                mapped.push(OBOL.facts.makeFact({
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
              var kp = String(sv.ssh_key_path || sv.sshKeyPath || sv.keyPath || sv.key_path || sv.keyfile || sv.path || sv.file || 'id_rsa').trim();
              var ku = String(sv.user || sv.username || sv.owner || '').trim();
              var rkKey = [ku.toLowerCase(), '', '', kp].join('|');
              if (!seenReuse[rkKey]) {
                seenReuse[rkKey] = 1;
                mapped.push(OBOL.facts.makeFact({
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
                  mapped.push(OBOL.facts.makeFact({
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
                  mapped.push(OBOL.facts.makeFact({
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
      return new OBOL.facts.FactSet(mapped);
    },
    // The identity of a target at a glance: IP + the hostname and AD domain obol has proven for it (or
    // the domain the operator scoped). Both the target page and the engagement Attack Path render this,
    // so "Hostname: FOREST / Domain: corp.local" fills in the moment the fact is captured. Empty strings
    // for anything not yet known - the caller decides whether to show the slot or hide it.
    targetIdentity(ip) {
      var eng = this.active() || {};
      var params = eng.params || {};
      var tgt = (eng.targets || []).find(function (t) { return t.ip === ip || t.id === ip; }) || {};
      var realIp = tgt.ip || ip;
      var fs = this.factSetForTarget(realIp);
      function first(kind, keys) {
        var vals = fs.values(kind) || [];
        for (var i = 0; i < vals.length; i++) {
          for (var k = 0; k < keys.length; k++) { var v = vals[i] && vals[i][keys[k]]; if (v) return String(v).trim(); }
        }
        return '';
      }
      var fqdn = first('host.fqdn', ['fqdn', 'name']);
      var hostname = (tgt.hostname || first('host.hostname', ['name', 'hostname']) || (fqdn ? fqdn.split('.')[0] : '')).trim();
      var domain = (tgt.domain || first('host.domain', ['domain', 'name']) || first('ad.domain_known', ['name', 'domain']) || ((eng.targets || []).length <= 1 ? params.domain || '' : '')).trim();
      var os = (tgt.os || (OBOL.targets && OBOL.targets.hostOs ? OBOL.targets.hostOs(fs, tgt) : '') || '').trim();
      return { ip: realIp, hostname: hostname, domain: domain, fqdn: fqdn, os: os };
    },
    addFacts(facts, reason, observedTarget) {
      // facts: array of OBOL.facts (or serialized). Returns count actually added (deduped).
      var eng = this.active();
      if (!eng) return 0;
      var fs = new OBOL.facts.FactSet((eng.facts || []).filter(Boolean).map(OBOL.facts.factFromJson).filter(Boolean));
      var added = 0, addedKinds = [], normalizedInput = [];
      (facts || []).forEach(function (f) {
        if (!f) return;
        var fact = f.kind ? (f.state ? f : OBOL.facts.factFromJson(f)) : null;
        if (fact) {
          normalizedInput.push(fact);
          if (fs.add(fact)) { added++; addedKinds.push(fact.kind); }
        }
      });
      // Reflect a proven hostname onto its target record, so the UI can show "IP · HOSTNAME"
      // (the header/list already render target.hostname when set; nothing populated it before).
      if (added) {
        var SUP = OBOL.facts.ProofState.SUPPORTED;
        fs.facts.forEach(function (f) {
          if ((f.kind === 'host.hostname' || f.kind === 'host.fqdn') && f.state === SUP && String(f.scope).indexOf('host:') === 0) {
            var ip = f.scope.slice(5), v = f.value || {};
            var name = String(v.name || v.hostname || v.fqdn || '').split('.')[0];
            if (!name) return;
            (eng.targets || []).forEach(function (tg) { if (tg.ip === ip && !tg.hostname) tg.hostname = name; });
          }
          if ((f.kind === 'ad.domain_known' || f.kind === 'ad.domain' || f.kind === 'host.domain') && f.state === SUP) {
            var dv = f.value || {};
            var dName = String(dv.domain || dv.name || '').trim().replace(/0\.$/, '').replace(/\.$/, '');
            if (dName && dName.toLowerCase() !== 'domain' && dName.toLowerCase() !== 'workgroup' && dName.indexOf('.') > 0) {
              eng.params = eng.params || {};
              var domainHost = /^host:/.test(f.scope || '') ? f.scope.slice(5) : '';
              if (domainHost) {
                (eng.targets || []).forEach(function (tg) { if (tg.ip === domainHost && !tg.domain) tg.domain = dName; });
              }
              if (!eng.params.domain && (domainHost === eng.params.target || (!domainHost && (eng.targets || []).length <= 1))) eng.params.domain = dName;
            }
          }
          if ((f.kind === 'host.os_hint' || f.kind === 'host.os' || f.kind === 'host.os_family') && f.state === SUP && String(f.scope).indexOf('host:') === 0) {
            var ipOs = f.scope.slice(5), ov = f.value || {};
            var rawOs = ov.os || ov.family || ov.name || '';
            var clean = (OBOL.targets && OBOL.targets.cleanOs) ? OBOL.targets.cleanOs(rawOs) : rawOs;
            if (clean && clean.toLowerCase() !== 'windows' && clean.toLowerCase() !== 'linux') {
              (eng.targets || []).forEach(function (tg) { if (tg.ip === ipOs) tg.os = clean; });
            } else if (clean) {
              (eng.targets || []).forEach(function (tg) { if (tg.ip === ipOs && !tg.os) tg.os = clean.charAt(0).toUpperCase() + clean.slice(1); });
            }
          }
          var isCredFact = (f.kind === 'credential.available' || f.kind === 'credential.plaintext' || f.kind === 'credential.ntlm_hash'
            || f.type === 'credential.available' || f.type === 'credential.plaintext');
          if (isCredFact && f.state === SUP) {
            var cv = f.value || {};
            var u = String(cv.user || cv.username || '').trim();
            var rawH = String(cv.nthash || cv.hash || '').trim();
            var rawP = String(cv.secret || cv.password || '');
            var isNT = (cv.secret_type === 'NT' || cv.secretType === 'NT' || cv.hash_type === 'ntlm' || (!!rawH && !rawP));
            var h = String(rawH || (isNT ? rawP : '') || '').trim();
            var p = isNT ? '' : rawP;
            var d = String(cv.domain || '').trim() || ((f.scope && f.scope.indexOf('domain:') === 0 && f.scope !== 'domain:domain') ? f.scope.slice(7) : '');
            var st = isNT ? 'NT' : (cv.secretType || cv.secret_type || 'password');
            if (u && (p || h)) {
              eng.credentials = eng.credentials || [];
              var exists = eng.credentials.some(function (c) {
                return (c.user || '').toLowerCase() === u.toLowerCase()
                  && String(c.domain || '').toLowerCase() === d.toLowerCase()
                  && (c.secret || c.password || '') === (p || '')
                  && (c.nthash || '') === (h || '')
                  && String(c.targetBinding || c.computer || '') === String(cv.targetBinding || cv.computer || '');
              });
              if (!exists) {
                eng.credentials.push({
                  id: uid('cred'),
                  user: u,
                  domain: d,
                  secret: p || '',
                  nthash: h || '',
                  secretType: st,
                  source: 'recovered',
                  scope: f.scope || '',
                  targetBinding: cv.targetBinding || '',
                  computer: cv.computer || '',
                  accountType: cv.accountType || '',
                  association: cv.association || '',
                  notes: 'Discovered via ' + (cv.method || f.source || 'evidence')
                });
              }
              // New material is offered as a candidate. Selection is deliberate and target-specific.
            }
          }
        });
      }
      if (added || normalizedInput.length) {
        eng.facts = fs.facts.map(OBOL.facts.factToJson);
        var activeIp = String((eng.params || {}).target || eng.activeTarget || '').trim();
        var selected = OBOL.context && OBOL.context.selectedId(eng, activeIp);
        if (OBOL.context && activeIp && (!selected || !OBOL.context.credentials(eng).some(function (c) { return c.id === selected; })) && OBOL.context.pin(eng) === undefined
          && !((eng.contextSelections || {}).anonymousByTarget || {})[activeIp]) {
          var applicable = this.factSetForTarget(activeIp).facts;
          var domainUnknown = !Object.keys(domainsForTarget(eng, activeIp, applicable.filter(function (f) { return f.scope === 'host:' + activeIp; }))).length;
          var candidateFacts = normalizedInput.filter(function (f) {
            return f && f.state === 'supported' && /^credential\.(available|plaintext|ntlm_hash)$/.test(f.kind)
              && ((observedTarget === activeIp && domainUnknown && /^domain:/.test(f.scope || ''))
                || applicable.some(function (a) { return a.kind === f.kind && a.scope === f.scope && OBOL.facts.valuesEqual(a.value, f.value); }));
          });
          candidateFacts.sort(function (a, b) {
            var aUser = String((a.value && (a.value.user || a.value.username || a.value.principal)) || '').replace(/^.*\\/, '');
            var bUser = String((b.value && (b.value.user || b.value.username || b.value.principal)) || '').replace(/^.*\\/, '');
            var aAdm = /^(?:administrator|admin|root|krbtgt)$/i.test(aUser) ? 1 : 0;
            var bAdm = /^(?:administrator|admin|root|krbtgt)$/i.test(bUser) ? 1 : 0;
            return bAdm - aAdm;
          });
          var candidateFact = candidateFacts[0];
          if (candidateFact) {
            var materialValue = Object.assign({}, candidateFact.value);
            if (!materialValue.domain && /^domain:/.test(candidateFact.scope || '') && candidateFact.scope !== 'domain:domain') materialValue.domain = candidateFact.scope.slice(7);
            var candidateId = OBOL.context.material(materialValue, candidateFact.scope).id;
            if (OBOL.context.credentials(eng).some(function (c) { return c.id === candidateId; })) OBOL.context.select(eng, candidateId, activeIp);
          }
        }
        scheduleSave();
        emit(reason || 'facts');
      }
      // celebrate genuine milestone proof (foothold/admin/flag/loot) — presentation only.
      if (addedKinds.length && OBOL.coins) { try { OBOL.coins.burstForFactKinds(addedKinds); } catch (e) {} }
      return added;
    },
    setFacts(factset, reason) {
      var eng = this.active();
      if (!eng) return;
      eng.facts = factset.facts.map(OBOL.facts.factToJson);
      scheduleSave();
      emit(reason || 'facts');
    },
    retractFactKind(kind, scope) {
      if (typeof scope !== 'string') throw new Error('A fact scope is required for retraction');
      var eng = this.active();
      if (!eng) return;
      var fs = this.factSet();
      fs.facts = fs.facts.filter(function (f) { return f.kind !== kind || f.scope !== scope; });
      this.setFacts(fs, 'retract');
    },

    // ---- blobs (screenshots / large evidence) ----
    async putBlob(blob, meta) {
      var id = uid('blob');
      if (!_activeId) throw new Error('An engagement is required for binary evidence');
      var rec = Object.assign({ at: Date.now() }, meta || {}, { id: id, engagementId: _activeId, blob: blob });
      _mem.blobs[id] = rec;
      if (_useIDB && _db) { try { await idbPut('blobs', rec); } catch (e) {} }
      return id;
    },
    async getBlob(id) {
      if (_mem.blobs[id]) return _mem.blobs[id];
      if (_useIDB && _db) { try { return await idbGet('blobs', id); } catch (e) {} }
      return null;
    },

    // ---- settings ----
    async setSetting(key, value) {
      _mem.settings[key] = value;
      if (_useIDB && _db) { try { await idbPut('settings', { key: key, value: value }); } catch (e) {} }
      else { writePref(key, value); }
    },
    getSetting(key) {
      if (key in _mem.settings) return _mem.settings[key];
      var p = readPrefs();
      return p[key];
    },

    // prefs (sync, tiny) — for pre-paint skin/route
    pref: readPrefs,
    setPref: writePref,

    onChange: onChange,
    _newEngagement: newEngagement,
  };

  OBOL.store = Store;
})(typeof globalThis !== 'undefined' ? globalThis : this);
