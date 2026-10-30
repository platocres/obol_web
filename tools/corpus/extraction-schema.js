/* obol corpus - extraction-schema.js - the Stage 1 record contract (qa-only; never ships, never runs at runtime).
 *
 * Stage 1 of corpus mining (docs/CORPUS-MINING.md Section 6) locks Section 4 ("The Extraction Schema") from
 * prose into ONE machine-checkable contract, plus the dedup and provenance rules. Two things live here:
 *
 *   1. The ASSET RECORD. Every mined asset emits exactly one structured record so the asset is never
 *      re-mined (the Whole-Asset Rule, Principle 4). validateRecord() enforces the field set, the asset-type
 *      and fidelity enums, the dedup key (asset.hash = contentHash of the normalized raw text), the
 *      provenance floor (source url + retrieval date), the output-block shape, and the "at least one axis of
 *      value present" rule so an empty record cannot be marked done.
 *
 *   2. The FACTS-AXIS LABEL sub-contract. The human-authored tools/corpus/labels/*.json file is additive and
 *      the one artifact that already instantiates part of the schema (its facts_implied ground truth).
 *      validateLabelsFile() enforces its envelope and, crucially, validates every referenced fact kind
 *      against the LIVE engine vocabulary (PARSER_SIGNATURES emits, exact or prefix-wildcard, plus
 *      environmental facts) via buildKindVocabulary(). Before Stage 1 a typo in expected_kinds silently
 *      registered as a facts-axis miss (inflating the backlog) instead of an error; now it is caught.
 *
 * Pure Node, no DOM, no third-party deps. Stores no verbatim corpus output (Principle 7). The caller passes
 * OBOL.PARSER_SIGNATURES in, so this module stays decoupled from the engine load order. House style: no em or
 * en dashes. */
'use strict';
var crypto = require('crypto');

var ASSET_TYPES = ['code_block', 'asciinema', 'screenshot', 'tool_fixture', 'source_strings', 'forum_thread'];
var FIDELITIES = ['text', 'ocr'];
// The axes of value a record can carry (Section 4). A record must carry at least one (Whole-Asset Rule).
var AXES = ['output_blocks', 'facts_implied', 'failures', 'flow'];
// Schema v2 optional enums (v13.0 Dual-Pass + Multi-Target harness).
var OUTCOME_KINDS = ['completed-negative', 'authorization-denied', 'rejected', 'environment-error', 'success', 'partial'];
var TIER_ATTRIBUTIONS = ['tier1', 'tier2_shape', 'tier3_inference'];

// The dedup key (Section 4: asset.hash). sha256 over the raw text with CRLF normalized so the same block
// pulled on two platforms hashes identically. qa-only; not a security boundary, just a stable content key.
function contentHash(text) {
  return crypto.createHash('sha256').update(String(text == null ? '' : text).replace(/\r\n/g, '\n')).digest('hex');
}
function isHex64(s) { return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s); }
function isNonEmptyString(s) { return typeof s === 'string' && s.length > 0; }

function validateOutcomeExpected(val, prefix, errors) {
  if (val === undefined || val === null) return;
  if (typeof val !== 'string' || OUTCOME_KINDS.indexOf(val) < 0) {
    errors.push(prefix + ': "' + val + '" not in ' + OUTCOME_KINDS.join('|'));
  }
}

function validateTierAttribution(val, prefix, isKnownKind, errors) {
  if (val === undefined || val === null) return;
  if (typeof val === 'string') {
    if (TIER_ATTRIBUTIONS.indexOf(val) < 0) {
      errors.push(prefix + ': "' + val + '" not in ' + TIER_ATTRIBUTIONS.join('|'));
    }
    return;
  }
  if (typeof val === 'object' && !Array.isArray(val)) {
    var keys = Object.keys(val);
    if (!keys.length) {
      errors.push(prefix + ': tier attribution map cannot be empty');
      return;
    }
    keys.forEach(function (k) {
      if (isKnownKind && !isKnownKind(k)) {
        errors.push(prefix + '["' + k + '"]: "' + k + '" is not a known engine fact kind');
      }
      if (typeof val[k] !== 'string' || TIER_ATTRIBUTIONS.indexOf(val[k]) < 0) {
        errors.push(prefix + '["' + k + '"]: "' + val[k] + '" not in ' + TIER_ATTRIBUTIONS.join('|'));
      }
    });
    return;
  }
  errors.push(prefix + ': must be one of ' + TIER_ATTRIBUTIONS.join('|') + ' or a {kind: tier} object');
}

function validateTrajectoryCheckpoint(cp, opts) {
  opts = opts || {};
  var isKnownKind = typeof opts === 'function' ? opts : opts.isKnownKind;
  var p = (opts && opts.prefix) || 'trajectory_checkpoint';
  var e = [];
  if (!cp || typeof cp !== 'object' || Array.isArray(cp)) {
    return { ok: false, errors: [p + ': not an object'] };
  }
  if (typeof cp.step_index !== 'number' || !Number.isInteger(cp.step_index) || cp.step_index < 0) {
    e.push(p + '.step_index: must be a non-negative integer');
  }
  if (!isNonEmptyString(cp.target_ip)) {
    e.push(p + '.target_ip: missing or empty');
  }
  if (!Array.isArray(cp.expected_move_ids) || cp.expected_move_ids.length === 0) {
    e.push(p + '.expected_move_ids: must be a non-empty array of move ids');
  } else {
    cp.expected_move_ids.forEach(function (m, idx) {
      if (!isNonEmptyString(m)) e.push(p + '.expected_move_ids[' + idx + ']: must be a non-empty string');
    });
  }
  if (cp.required_gates != null) {
    if (!Array.isArray(cp.required_gates)) {
      e.push(p + '.required_gates: must be an array');
    } else {
      cp.required_gates.forEach(function (g, idx) {
        if (!isNonEmptyString(g)) e.push(p + '.required_gates[' + idx + ']: must be a non-empty string');
        else if (isKnownKind && !isKnownKind(g)) e.push(p + '.required_gates[' + idx + ']: "' + g + '" is not a known engine fact kind');
      });
    }
  }
  if (cp.earned_tokens != null) {
    if (Array.isArray(cp.earned_tokens)) {
      cp.earned_tokens.forEach(function (tok, idx) {
        if (!isNonEmptyString(tok)) e.push(p + '.earned_tokens[' + idx + ']: must be a non-empty string');
      });
    } else if (typeof cp.earned_tokens === 'object') {
      Object.keys(cp.earned_tokens).forEach(function (tok) {
        if (!isNonEmptyString(tok)) e.push(p + '.earned_tokens: empty token key');
        var tv = cp.earned_tokens[tok];
        if (tv != null && typeof tv !== 'string' && typeof tv !== 'number' && typeof tv !== 'boolean') {
          e.push(p + '.earned_tokens["' + tok + '"]: must be a scalar token value');
        }
      });
    } else {
      e.push(p + '.earned_tokens: must be an array of token names or a {token: value} object');
    }
  }
  if (cp.require_closed_loop_top1 != null && typeof cp.require_closed_loop_top1 !== 'boolean') {
    e.push(p + '.require_closed_loop_top1: must be a boolean');
  }
  if (cp.retired_dry_moves != null) {
    if (!Array.isArray(cp.retired_dry_moves)) {
      e.push(p + '.retired_dry_moves: must be an array');
    } else {
      cp.retired_dry_moves.forEach(function (m, idx) {
        if (!isNonEmptyString(m)) e.push(p + '.retired_dry_moves[' + idx + ']: must be a non-empty string');
      });
    }
  }
  return { ok: e.length === 0, errors: e };
}

function validateTrajectoryCheckpoints(arr, prefix, isKnownKind, errors) {
  if (arr === undefined || arr === null) return;
  if (!Array.isArray(arr)) {
    errors.push(prefix + ': must be an array');
    return;
  }
  arr.forEach(function (cp, idx) {
    var r = validateTrajectoryCheckpoint(cp, { prefix: prefix + '[' + idx + ']', isKnownKind: isKnownKind });
    if (!r.ok) r.errors.forEach(function (msg) { errors.push(msg); });
  });
}

// Mirror the engine's parser-capability test (assets/engine/decisionmap.js capability/capable): a kind is
// "known" if it exactly matches an emits entry, or begins with a trailing-dot prefix family, or is an
// environmental fact the engagement hands over (same regex as decisionmap.isEnv). Built from the signatures
// the caller passes so this file never imports the engine.
function buildKindVocabulary(parserSignatures) {
  var exact = {}, pref = [];
  var S = parserSignatures || {};
  Object.keys(S).forEach(function (k) {
    (S[k].emits || []).forEach(function (e) {
      if (typeof e !== 'string' || !e) return;
      if (e.charAt(e.length - 1) === '.') pref.push(e); else exact[e] = 1;
    });
  });
  function isEnv(f) { return /^(target\.|host\.up$|ports\.open$|port:|scan\.|service\.)/.test(f) || /\.reachable$/.test(f); }
  function isKnownKind(f) {
    if (typeof f !== 'string' || !f) return false;
    if (exact[f]) return true;
    for (var i = 0; i < pref.length; i++) if (f.indexOf(pref[i]) === 0) return true;
    return isEnv(f);
  }
  return { isKnownKind: isKnownKind, exactCount: Object.keys(exact).length, prefixCount: pref.length };
}

// ---- the asset record ----
function validateRecord(rec, opts) {
  var e = [];
  opts = opts || {};
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) { return { ok: false, errors: ['record is not an object'] }; }

  // provenance floor
  var src = rec.source;
  if (!src || typeof src !== 'object') { e.push('source: missing (need url/repo path and retrieval date)'); }
  else {
    if (!isNonEmptyString(src.url)) e.push('source.url: missing or empty (url or repo path required)');
    if (!isNonEmptyString(src.retrieved)) e.push('source.retrieved: missing or empty (retrieval date required)');
  }

  // asset: dedup key + type/fidelity enums
  var a = rec.asset;
  if (!a || typeof a !== 'object') { e.push('asset: missing (need hash, type, fidelity)'); }
  else {
    if (!isHex64(a.hash)) e.push('asset.hash: not a sha256 hex digest (the dedup key, use contentHash)');
    if (ASSET_TYPES.indexOf(a.type) < 0) e.push('asset.type: "' + a.type + '" not in ' + ASSET_TYPES.join('|'));
    if (FIDELITIES.indexOf(a.fidelity) < 0) e.push('asset.fidelity: "' + a.fidelity + '" not in ' + FIDELITIES.join('|'));
  }

  // output_blocks shape
  if (rec.output_blocks != null) {
    if (!Array.isArray(rec.output_blocks)) e.push('output_blocks: must be an array');
    else rec.output_blocks.forEach(function (b, i) {
      var p = 'output_blocks[' + i + ']';
      if (!b || typeof b !== 'object') { e.push(p + ': not an object'); return; }
      if (!isNonEmptyString(b.command_shown)) e.push(p + '.command_shown: missing');
      if (!isNonEmptyString(b.tool)) e.push(p + '.tool: missing');
      if (typeof b.raw_output !== 'string') e.push(p + '.raw_output: missing (empty string allowed for a no-output block)');
      if (typeof b.truncated !== 'boolean') e.push(p + '.truncated: must be a boolean');
      if (FIDELITIES.indexOf(b.fidelity) < 0) e.push(p + '.fidelity: "' + b.fidelity + '" not in ' + FIDELITIES.join('|'));
      validateOutcomeExpected(b.outcome_expected, p + '.outcome_expected', e);
      validateTierAttribution(b.tier_attribution, p + '.tier_attribution', opts.isKnownKind, e);
    });
  }
  ['facts_implied', 'failures', 'flow'].forEach(function (k) {
    if (rec[k] != null && !Array.isArray(rec[k])) e.push(k + ': must be an array');
  });
  if (rec.notes != null && typeof rec.notes !== 'string') e.push('notes: must be a string');

  validateOutcomeExpected(rec.outcome_expected, 'outcome_expected', e);
  validateTierAttribution(rec.tier_attribution, 'tier_attribution', opts.isKnownKind, e);
  validateTrajectoryCheckpoints(rec.trajectory_checkpoints, 'trajectory_checkpoints', opts.isKnownKind, e);

  // Whole-Asset Rule: an asset is not "done" until at least one axis of value is captured.
  var carried = AXES.some(function (k) { return Array.isArray(rec[k]) && rec[k].length > 0; })
    || (Array.isArray(rec.trajectory_checkpoints) && rec.trajectory_checkpoints.length > 0);
  if (!carried) e.push('no axis of value captured (need a non-empty one of ' + AXES.join(', ') + ')');

  // optional kind validation for facts_implied entries that name a kind
  if (Array.isArray(rec.facts_implied)) {
    rec.facts_implied.forEach(function (f, i) {
      var kind = f && typeof f === 'object' ? f.kind : f;
      if (opts.isKnownKind && kind != null && !opts.isKnownKind(kind)) {
        e.push('facts_implied[' + i + '].kind: "' + kind + '" is not a known engine fact kind');
      }
      if (f && typeof f === 'object' && f.tier_attribution !== undefined) {
        validateTierAttribution(f.tier_attribution, 'facts_implied[' + i + '].tier_attribution', opts.isKnownKind, e);
      }
    });
  }
  return { ok: e.length === 0, errors: e };
}

// ---- the facts-axis label sub-contract ----
function validateLabelCase(c, isKnownKind) {
  var e = [];
  if (!c || typeof c !== 'object' || Array.isArray(c)) { return { ok: false, errors: ['case is not an object'] }; }
  if (!isNonEmptyString(c.id)) e.push('id: missing or empty');
  if (!isNonEmptyString(c.file)) e.push('file: missing or empty');
  if (!isNonEmptyString(c.command)) e.push('command: missing or empty');
  if (c.note != null && typeof c.note !== 'string') e.push('note: must be a string');
  if (!Array.isArray(c.expected_kinds)) e.push('expected_kinds: must be an array');
  if (c.forbidden_kinds != null && !Array.isArray(c.forbidden_kinds)) e.push('forbidden_kinds: must be an array');

  var exp = Array.isArray(c.expected_kinds) ? c.expected_kinds : [];
  var forb = Array.isArray(c.forbidden_kinds) ? c.forbidden_kinds : [];
  exp.forEach(function (k) { if (!isNonEmptyString(k)) e.push('expected_kinds: contains a non-string'); else if (isKnownKind && !isKnownKind(k)) e.push('expected_kinds: "' + k + '" is not a known engine fact kind'); });
  forb.forEach(function (k) { if (!isNonEmptyString(k)) e.push('forbidden_kinds: contains a non-string'); else if (isKnownKind && !isKnownKind(k)) e.push('forbidden_kinds: "' + k + '" is not a known engine fact kind'); });
  // a kind cannot be both the floor and a forbidden guard in the same case
  exp.forEach(function (k) { if (forb.indexOf(k) >= 0) e.push('kind "' + k + '" is in both expected_kinds and forbidden_kinds'); });

  if (c.expected_values != null) {
    if (!Array.isArray(c.expected_values)) e.push('expected_values: must be an array');
    else c.expected_values.forEach(function (v, i) {
      if (!v || typeof v !== 'object') { e.push('expected_values[' + i + ']: not an object'); return; }
      if (!isNonEmptyString(v.kind)) e.push('expected_values[' + i + '].kind: missing');
      else if (isKnownKind && !isKnownKind(v.kind)) e.push('expected_values[' + i + '].kind: "' + v.kind + '" is not a known engine fact kind');
      if (!('value_contains' in v)) e.push('expected_values[' + i + '].value_contains: missing');
    });
  }

  validateOutcomeExpected(c.outcome_expected, 'outcome_expected', e);
  validateTierAttribution(c.tier_attribution, 'tier_attribution', isKnownKind, e);
  validateTrajectoryCheckpoints(c.trajectory_checkpoints, 'trajectory_checkpoints', isKnownKind, e);

  return { ok: e.length === 0, errors: e };
}

function validateLabelsFile(obj, isKnownKind) {
  var e = [];
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) { return { ok: false, errors: ['labels file is not an object'], cases: 0 }; }
  if (typeof obj.version !== 'number') e.push('version: must be a number');
  if (!isNonEmptyString(obj.description)) e.push('description: missing or empty');
  if (!Array.isArray(obj.cases)) { e.push('cases: must be an array'); return { ok: false, errors: e, cases: 0 }; }
  var seen = {};
  obj.cases.forEach(function (c, i) {
    var r = validateLabelCase(c, isKnownKind);
    if (!r.ok) r.errors.forEach(function (m) { e.push('cases[' + i + '] (' + (c && c.id || '?') + '): ' + m); });
    if (c && c.id != null) { if (seen[c.id]) e.push('cases[' + i + ']: duplicate id "' + c.id + '"'); seen[c.id] = 1; }
  });
  validateTrajectoryCheckpoints(obj.trajectory_checkpoints, 'trajectory_checkpoints', isKnownKind, e);
  return { ok: e.length === 0, errors: e, cases: obj.cases.length };
}

module.exports = {
  ASSET_TYPES: ASSET_TYPES,
  FIDELITIES: FIDELITIES,
  AXES: AXES,
  OUTCOME_KINDS: OUTCOME_KINDS,
  TIER_ATTRIBUTIONS: TIER_ATTRIBUTIONS,
  contentHash: contentHash,
  buildKindVocabulary: buildKindVocabulary,
  validateRecord: validateRecord,
  validateLabelCase: validateLabelCase,
  validateLabelsFile: validateLabelsFile,
  validateTrajectoryCheckpoint: validateTrajectoryCheckpoint
};
