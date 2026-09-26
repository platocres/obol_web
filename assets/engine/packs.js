/*!
 * obol engine — packs.js
 * Loads the Action list from the generated OBOL.packData global (data/packs-bundle.js).
 * Caches the deduped Action array. Also exposes the non-action data packs (findings
 * catalog, web fingerprints, known exploits, KEV, scripts) for the report/tools surfaces.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var _actions = null;

  function packData() { return OBOL.packData || {}; }

  function actions() {
    if (_actions) return _actions;
    var names = OBOL.ACTION_PACKS || OBOL.pack.PACK_NAMES;
    var list = names.map(function (n) { return packData()[n]; }).filter(Boolean);
    _actions = OBOL.pack.loadPacks(list);
    return _actions;
  }

  function dataPack(name) { return packData()[name] || null; }

  // The tool universe obol-local is prepared to equip: union of every action's tool + tools[].
  function equippedTools() {
    var set = {};
    actions().forEach(function (a) {
      if (a.tool) set[a.tool] = true;
      (a.tools || []).forEach(function (t) { if (t) set[t] = true; });
      (a.commands || []).forEach(function (c) { if (c.tool) set[c.tool] = true; });
    });
    return Object.keys(set).sort();
  }

  OBOL.packs = { actions: actions, dataPack: dataPack, equippedTools: equippedTools, packData: packData };
})(typeof globalThis !== 'undefined' ? globalThis : this);
