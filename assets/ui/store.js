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
  var DB_VERSION = 1;
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
        if (!db.objectStoreNames.contains('blobs')) db.createObjectStore('blobs', { keyPath: 'id' });
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
    return {
      id: uid('eng'),
      name: name == null ? '' : name,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      schema: 3,
      profile: { platform: 'custom', machine_type: '', candidate: '', osid: '', scope: [] }, // engagement profile
      params: {},          // target/domain/username/password/lhost/…
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
    e.facts = e.facts.filter(function (f) {
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
    return e;
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
    // name from before this change, reads as "No Run Yet" everywhere (chip, selector, library).
    runLabel(eng) {
      var n = eng && eng.name != null ? String(eng.name).trim() : '';
      return (!n || /^(untitled run|new engagement)$/i.test(n)) ? 'No Run Yet' : n;
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
      delete _mem.engagements[id];
      if (_useIDB && _db) await idbDelete('engagements', id).catch(function () {});
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
      var ids = Object.keys(_mem.engagements);
      _mem.engagements = {}; _mem.blobs = {}; _activeId = null;
      if (_useIDB && _db) {
        for (var i = 0; i < ids.length; i++) await idbDelete('engagements', ids[i]).catch(function () {});
        await this.setSetting('activeEngagement', null).catch(function () {});
      } else { snapshotFallback(); }
      emit('active');
    },
    // Full factory reset: erase ALL obol data in this browser — the IndexedDB database (engagements,
    // blobs, settings) plus every obol localStorage/sessionStorage key. The caller reloads afterward.
    async resetAll() {
      _mem = { engagements: {}, blobs: {}, settings: {} }; _activeId = null;
      try {
        for (var i = localStorage.length - 1; i >= 0; i--) {
          var k = localStorage.key(i);
          if (k && (/^obol/i.test(k) || k === LS_PREFS || k === LS_SNAPSHOT)) localStorage.removeItem(k);
        }
      } catch (e) {}
      try { sessionStorage.clear(); } catch (e2) {}
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
      mutator(eng);
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
    // A per-target FactSet: this host's facts + applicable domain-/engagement-scoped facts.
    // Unscanned targets in multi-target engagements do not inherit other hosts' domain credentials/loot
    // until they have been scanned, and non-AD Linux hosts do not inherit Windows AD/DC compromise facts.
    factSetForTarget(ip) {
      var eng = this.active();
      var arr = ((eng && eng.facts) || []).filter(function (f) { return f && typeof f === 'object' && f.kind; });
      var hostScope = 'host:' + ip;
      var multiTarget = ((eng && eng.targets) || []).length > 1 || arr.some(function (f) {
        return f && f.scope && f.scope.indexOf('host:') === 0 && f.scope !== hostScope && f.scope !== 'host:target';
      });
      var hostFacts = arr.filter(function (f) { return f && (f.scope === hostScope || (!multiTarget && f.scope === 'host:target')); });
      var hasHostActivity = hostFacts.some(function (f) {
        return f.state === 'supported' && f.kind.indexOf('target.') !== 0
          && f.kind !== 'host.hostname' && f.kind !== 'host.domain' && f.kind !== 'host.fqdn';
      });
      if (multiTarget && !hasHostActivity) {
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
      var sel = arr.filter(function (f) {
        var s = f.scope || '';
        if (s === hostScope || (!multiTarget && s === 'host:target')) return true;
        if (s === '' || s.indexOf('scope:') === 0) return !multiTarget || hasHostActivity;
        if (s.indexOf('domain:') === 0) {
          if (isLinux && !hasAdOrSmb) {
            return s === 'domain:domain' && (f.kind.indexOf('credential.') === 0 || f.kind.indexOf('dns.') === 0);
          }
          if (!isDc && DC_ONLY_DOMAIN_RE.test(f.kind)) return false;
          return true;
        }
        return false;
      });
      return new OBOL.facts.FactSet(sel.map(OBOL.facts.factFromJson));
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
      var domain = (first('host.domain', ['domain', 'name']) || first('ad.domain_known', ['name', 'domain']) || (params.domain || '')).trim();
      var os = (tgt.os || (OBOL.targets && OBOL.targets.hostOs ? OBOL.targets.hostOs(fs, tgt) : '') || '').trim();
      return { ip: realIp, hostname: hostname, domain: domain, fqdn: fqdn, os: os };
    },
    addFacts(facts, reason) {
      // facts: array of OBOL.facts (or serialized). Returns count actually added (deduped).
      var eng = this.active();
      if (!eng) return 0;
      var fs = new OBOL.facts.FactSet((eng.facts || []).filter(Boolean).map(OBOL.facts.factFromJson).filter(Boolean));
      var added = 0, addedKinds = [];
      (facts || []).forEach(function (f) {
        if (!f) return;
        var fact = f.kind ? (f.state ? f : OBOL.facts.factFromJson(f)) : null;
        if (fact && fs.add(fact)) { added++; addedKinds.push(fact.kind); }
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
              if (!eng.params.domain) eng.params.domain = dName;
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
          var isCredFact = (f.kind === 'credential.available' || f.kind === 'credential.plaintext' || f.kind === 'credential.admin'
            || f.type === 'credential.available' || f.type === 'credential.plaintext' || f.type === 'credential.admin');
          if (isCredFact && f.state === SUP) {
            var cv = f.value || {};
            var u = String(cv.user || cv.username || '').trim();
            var rawH = String(cv.nthash || cv.hash || '').trim();
            var rawP = String(cv.secret || cv.password || '').trim();
            var isNT = (cv.secret_type === 'NT' || cv.secretType === 'NT' || cv.hash_type === 'ntlm' || (!!rawH && !rawP));
            var h = String(rawH || (isNT ? rawP : '') || '').trim();
            var p = isNT ? '' : rawP;
            var d = String(cv.domain || '').trim() || ((f.scope && f.scope.indexOf('domain:') === 0 && f.scope !== 'domain:domain') ? f.scope.slice(7) : '');
            var st = isNT ? 'NT' : (cv.secretType || cv.secret_type || 'password');
            if (u && (p || h)) {
              eng.credentials = eng.credentials || [];
              var exists = eng.credentials.some(function (c) {
                return (c.user || '').toLowerCase() === u.toLowerCase()
                  && (c.secret || c.password || '') === (p || '')
                  && (c.nthash || '') === (h || '');
              });
              if (!exists) {
                eng.credentials.push({
                  id: uid('cred'),
                  user: u,
                  domain: d,
                  secret: p || '',
                  nthash: h || '',
                  secretType: st,
                  source: 'proven',
                  scope: f.scope || '',
                  notes: 'Discovered via ' + (cv.method || f.source || 'evidence')
                });
              }
              eng.params = eng.params || {};
              var isAdmFact = (f.kind === 'credential.admin' || f.type === 'credential.admin');
              if (!eng.params.username || (isAdmFact && !/^(?:administrator|root)$/i.test(eng.params.username))) {
                eng.params.username = u;
                if (h && !p) { eng.params.nthash = h; eng.params.password = ''; }
                else if (p) { eng.params.password = p; eng.params.nthash = ''; }
                if (d && !eng.params.domain) eng.params.domain = d;
              }
            }
          }
        });
      }
      if (added || (facts && facts.length)) {
        eng.facts = fs.facts.map(OBOL.facts.factToJson);
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
    retractFactKind(kind) {
      var eng = this.active();
      if (!eng) return;
      var fs = this.factSet();
      fs.facts = fs.facts.filter(function (f) { return f.kind !== kind; });
      this.setFacts(fs, 'retract');
    },

    // ---- blobs (screenshots / large evidence) ----
    async putBlob(blob, meta) {
      var id = uid('blob');
      var rec = Object.assign({ id: id, at: Date.now() }, meta || {}, { blob: blob });
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
