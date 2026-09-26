/*!
 * obol ui — store.js
 * The browser database layer. IndexedDB is the primary store (async, structured, roomy),
 * fronted by an in-memory cache so reads are synchronous for the UI and writes never block
 * paint. localStorage holds only tiny per-viewer prefs (skin, last route) + a boot hint.
 *
 * Model: an engagement library (mirroring obol-local). Each engagement holds params, targets,
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
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains('engagements')) db.createObjectStore('engagements', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('blobs')) db.createObjectStore('blobs', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error || new Error('idb-open-failed')); };
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

  // ---- engagement shape ----
  function newEngagement(name) {
    return {
      id: uid('eng'),
      name: name || 'New engagement',
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
      ui: {},              // per-engagement UI state (active target, path zoom/pan, …)
    };
  }

  // ---- change notification ----
  function onChange(fn) { _listeners.push(fn); }
  function emit(reason) { _listeners.forEach(function (fn) { try { fn(reason); } catch (e) {} }); }

  // ---- persistence of the active engagement (debounced) ----
  var _saveTimer = null;
  function scheduleSave() {
    if (_saveTimer) return;
    _saveTimer = setTimeout(function () {
      _saveTimer = null;
      var eng = _mem.engagements[_activeId];
      if (!eng) return;
      eng.updatedAt = Date.now();
      if (_useIDB && _db) {
        idbPut('engagements', eng).catch(function () { snapshotFallback(); });
      } else {
        snapshotFallback();
      }
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
        _db = await openDB();
        _useIDB = true;
        var list = await idbGetAll('engagements');
        list.forEach(function (e) { _mem.engagements[e.id] = e; });
        var act = await idbGet('settings', 'activeEngagement');
        _activeId = (act && act.value) || null;
      } catch (e) {
        _useIDB = false;
        try {
          var snap = JSON.parse(localStorage.getItem(LS_SNAPSHOT) || 'null');
          if (snap) { _mem.engagements = snap.engagements || {}; _activeId = snap.activeId || null; }
        } catch (e2) {}
      }
      // ensure at least one (clean, empty) engagement exists as a starting point
      if (!Object.keys(_mem.engagements).length) {
        var eng = newEngagement('Untitled run');
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
    async setActive(id) {
      if (_mem.engagements[id]) { _activeId = id; await this.setSetting('activeEngagement', id); emit('active'); }
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
      if (_activeId === id) _activeId = Object.keys(_mem.engagements)[0] || null;
      emit('active');
    },
    async _persistEngagement(eng) {
      if (_useIDB && _db) { try { await idbPut('engagements', eng); return; } catch (e) {} }
      snapshotFallback();
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
      var arr = (eng && eng.facts) || [];
      var fs = new OBOL.facts.FactSet(arr.map(OBOL.facts.factFromJson));
      return fs;
    },
    // A per-target FactSet: this host's facts + domain-/engagement-scoped facts (mirrors
    // obol-local ws.facts_for_target so a target ranks by its own progress).
    factSetForTarget(ip) {
      var eng = this.active();
      var arr = (eng && eng.facts) || [];
      var hostScope = 'host:' + ip;
      var sel = arr.filter(function (f) {
        var s = f.scope || '';
        return s === hostScope || s.indexOf('domain:') === 0 || s === '' || s.indexOf('scope:') === 0;
      });
      return new OBOL.facts.FactSet(sel.map(OBOL.facts.factFromJson));
    },
    addFacts(facts, reason) {
      // facts: array of OBOL.facts (or serialized). Returns count actually added (deduped).
      var eng = this.active();
      if (!eng) return 0;
      var fs = new OBOL.facts.FactSet((eng.facts || []).map(OBOL.facts.factFromJson));
      var added = 0;
      (facts || []).forEach(function (f) {
        var fact = f.kind ? (f.state ? f : OBOL.facts.factFromJson(f)) : null;
        if (fact && fs.add(fact)) added++;
      });
      if (added || (facts && facts.length)) {
        eng.facts = fs.facts.map(OBOL.facts.factToJson);
        scheduleSave();
        emit(reason || 'facts');
      }
      return added;
    },
    setFacts(factset, reason) {
      var eng = this.active();
      if (!eng) return;
      eng.facts = factset.facts.map(OBOL.facts.factToJson);
      scheduleSave();
      emit(reason || 'facts');
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
