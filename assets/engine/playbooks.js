/*!
 * obol engine — playbooks.js
 * Playbooks: named, ordered sequences of pack actions expressed as data. A playbook is NOT a
 * second engine — each step names an existing pack Action by id, so it inherits that action's
 * fact-gating, command variants and attribution. This module only lets the operator read a
 * runbook and resolve its steps back to the real Actions; the *ordering* is the composition.
 *
 * Faithful JS port of obol-local/obol/playbook.py (list/get/resolve_steps/applicable). Pure and
 * Node-safe: reads playbooks from the generated OBOL.playbookData global and resolves against
 * OBOL.packs.actions() (or a caller-supplied pack).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function playbookData() { return OBOL.playbookData || {}; }
  function names() {
    return OBOL.PLAYBOOK_NAMES || Object.keys(playbookData()).sort();
  }

  // The live pack Action list (cached by OBOL.packs). Callers may pass their own for purity.
  function packOf(pack) { return pack || OBOL.packs.actions(); }

  function actionById(id, pack) {
    pack = packOf(pack);
    for (var i = 0; i < pack.length; i++) { if (pack[i].id === id) return pack[i]; }
    return null;
  }

  // All shipped playbooks, in OBOL.PLAYBOOK_NAMES order (obol-local sorts by name).
  function list() {
    var d = playbookData();
    return names().map(function (n) { return d[n]; }).filter(Boolean);
  }

  // One playbook by name, or null.
  function get(name) { return playbookData()[name] || null; }

  // Resolve every step to its pack Action, preserving order. Each entry keeps the step's own
  // fields (label/action_id/cmd/args_extra/require_approval/note) plus `.action` (the resolved
  // Action, or null if a pack no longer ships it — surfaced, never silently dropped).
  function resolveSteps(pb, pack) {
    pack = packOf(pack);
    var steps = (pb && pb.steps) || [];
    return steps.map(function (s) {
      return {
        label: s.label || s.action_id || '',
        action_id: s.action_id,
        cmd: parseInt(s.cmd != null ? s.cmd : 1, 10) || 1,
        args_extra: s.args_extra || '',
        require_approval: !!s.require_approval,
        note: s.note || '',
        action: actionById(s.action_id, pack),
      };
    });
  }

  // The playbooks whose FIRST resolvable step's action is eligible on the given FactSet — a
  // "what runbooks apply right now" projection. Nothing runs; read-only.
  function applicable(factSet, pack) {
    pack = packOf(pack);
    return list().filter(function (pb) {
      var steps = (pb && pb.steps) || [];
      for (var i = 0; i < steps.length; i++) {
        var a = actionById(steps[i].action_id, pack);
        if (a) return a.eligible(factSet); // first RESOLVABLE step gates the playbook
      }
      return false;
    });
  }

  OBOL.playbooks = {
    list: list,
    get: get,
    resolveSteps: resolveSteps,
    applicable: applicable,
    actionById: actionById,
    names: names,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
