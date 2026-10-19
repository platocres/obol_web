/*!
 * obol engine - facts.js
 * The fact layer: obol's single source of truth. A Fact is one thing the operator
 * has *proven* (or refuted, or found inconclusive) about a target, always tied to the
 * command/evidence that established it. Actions are gated on facts; the report is
 * narrated from them. Nothing becomes "true" unless a Fact records it, scoped to
 * exactly what the evidence supports.
 *
 * Faithful JS port of  Environment-agnostic: attaches to
 * `self` so it works in both the window and inside a Web Worker (importScripts).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // How strongly the evidence backs a fact. Deliberately small: "we ran a command"
  // is never the same as "it worked".
  var ProofState = {
    SUPPORTED: 'supported',       // evidence affirmatively established this
    REFUTED: 'refuted',           // evidence establishes this is NOT so
    INCONCLUSIVE: 'inconclusive', // attempted, ambiguous - no claim earned
  };

  function now() { return Date.now() / 1000; }

  // One proven/refuted/inconclusive claim about a target, tied to the evidence that
  // established it.
  //   kind    e.g. "ldap.reachable", "ad.user", "credential.available"
  //   scope   "host:10.10.10.10" | "domain:corp.local"
  //   value   kind-specific payload (object)
  //   state   ProofState
  //   source  the command / run that produced it (lineage)
  function makeFact(opts) {
    opts = opts || {};
    return {
      kind: opts.kind,
      scope: opts.scope || '',
      value: opts.value ? Object.assign({}, opts.value) : {},
      state: opts.state || ProofState.SUPPORTED,
      source: opts.source || '',
      created_at: (typeof opts.created_at === 'number') ? opts.created_at : now(),
    };
  }

  function factToJson(f) {
    return {
      kind: f.kind, scope: f.scope, value: f.value,
      state: f.state, source: f.source, created_at: f.created_at,
    };
  }

  function factFromJson(d) {
    d = d || {};
    return makeFact({
      kind: d.kind,
      scope: d.scope || '',
      // copy the value dict so a Fact never aliases the payload it was decoded from
      value: (d.value && typeof d.value === 'object') ? Object.assign({}, d.value) : {},
      state: d.state || ProofState.SUPPORTED,
      source: d.source || '',
      created_at: (typeof d.created_at === 'number') ? d.created_at : now(),
    });
  }

  function valuesEqual(a, b) {
    // Structural equality of two plain fact-value payloads (order-independent).
    if (a === b) return true;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return a === b;
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (var i = 0; i < ka.length; i++) {
      var k = ka[i];
      if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
      var va = a[k], vb = b[k];
      if (va && vb && typeof va === 'object' && typeof vb === 'object') {
        if (!valuesEqual(va, vb)) return false;
      } else if (va !== vb) {
        return false;
      }
    }
    return true;
  }

  var FLAG_FACT_KINDS = {
    'objective.local_flag': 1,
    'objective.root_flag': 1,
    'objective.flag': 1,
    'proof.captured': 1,
  };

  function mergeFlagFactIfDuplicate(list, fact) {
    if (!fact || !FLAG_FACT_KINDS[fact.kind] || !fact.value || typeof fact.value !== 'object') return -1;
    var fHash = String(fact.value.flag || '').trim().toLowerCase();
    var fSlot = String(fact.value.slot || '').trim().toLowerCase();
    for (var i = 0; i < list.length; i++) {
      var ex = list[i];
      if (!ex || ex.kind !== fact.kind || ex.scope !== fact.scope || !ex.value || typeof ex.value !== 'object') continue;
      var exHash = String(ex.value.flag || '').trim().toLowerCase();
      var exSlot = String(ex.value.slot || '').trim().toLowerCase();
      var sameHash = !!(fHash && exHash && fHash === exHash);
      var sameSlot = !!(fact.kind !== 'objective.flag' && fact.kind !== 'proof.captured' && fSlot && exSlot && fSlot === exSlot && (!fHash || !exHash || fHash === exHash));
      if (sameHash || sameSlot) {
        var newPath = String(fact.value.path || '');
        var oldPath = String(ex.value.path || '');
        if ((/[\/\\]/.test(newPath) && !/[\/\\]/.test(oldPath)) || (newPath.length > oldPath.length && !/[\/\\]/.test(oldPath))) {
          ex.value.path = fact.value.path;
          if (fact.value.name) ex.value.name = fact.value.name;
        }
        if (fact.value.block && (!ex.value.block || String(fact.value.block).length > String(ex.value.block).length)) {
          ex.value.block = fact.value.block;
        }
        if (fact.source && (!ex.source || /\.log$/i.test(ex.source)) && !/\.log$/i.test(fact.source)) {
          ex.source = fact.source;
        }
        return i;
      }
    }
    return -1;
  }

  // A small queryable collection of facts. Actions ask two questions of it:
  // "is this kind proven?" and "what are the proven values for this kind?".
  function FactSet(facts) {
    this.facts = [];
    // (kind, scope, value) of facts whose PROOF STATE this session changed in place.
    this.state_changed = [];
    var src = facts || [];
    for (var i = 0; i < src.length; i++) {
      if (src[i]) this.add(src[i]);
    }
  }

  FactSet.prototype.has = function (kind) {
    // True if at least one SUPPORTED fact of this kind exists.
    for (var i = 0; i < this.facts.length; i++) {
      var f = this.facts[i];
      if (f.kind === kind && f.state === ProofState.SUPPORTED) return true;
    }
    return false;
  };

  FactSet.prototype.values = function (kind) {
    // The payloads of every SUPPORTED fact of this kind.
    var out = [];
    for (var i = 0; i < this.facts.length; i++) {
      var f = this.facts[i];
      if (f.kind === kind && f.state === ProofState.SUPPORTED) out.push(f.value);
    }
    return out;
  };

  FactSet.prototype.kinds = function () {
    // The set of kinds with at least one SUPPORTED fact.
    var s = {};
    for (var i = 0; i < this.facts.length; i++) {
      var f = this.facts[i];
      if (f.state === ProofState.SUPPORTED) s[f.kind] = true;
    }
    return s; // plain object used as a set
  };

  FactSet.prototype.kindSet = function () {
    // Same as kinds() but returns a real Set (for callers that prefer it).
    return new Set(Object.keys(this.kinds()));
  };

  function isKnownFalsePositiveFact(fact) {
    if (!fact || !fact.value || typeof fact.value !== 'object') return false;
    var v = fact.value;
    if (fact.kind === 'host.notable_program' && String(v.name || '').toLowerCase() === 'runner.run') return true;
    if (fact.kind === 'loot.keepass_dump' && String(v.file || '').toUpperCase() === 'PATTERN.KDBX' && !v.has_hash) return true;
    if ((fact.kind === 'ad.rbcd' || fact.kind === 'ad.delegation') && Array.isArray(v.evidence) && v.evidence.length > 0 && v.evidence.every(function (e) {
      return /:\s*(?:WRITE|READ|CREATE_CHILD)\s*$/i.test(String(e || ''));
    })) return true;
    return false;
  }

  FactSet.prototype.add = function (fact) {
    // Add a fact unless an identical (kind, scope, value) one is present.
    // Returns true if it was actually new. A correction (same key, different state)
    // supersedes the old one in place so a mis-proven fact stops gating the planner.
    if (isKnownFalsePositiveFact(fact)) return false;
    for (var i = 0; i < this.facts.length; i++) {
      var existing = this.facts[i];
      if (existing.kind === fact.kind && existing.scope === fact.scope
          && valuesEqual(existing.value, fact.value)) {
        if (existing.state !== fact.state) {
          existing.state = fact.state;
          existing.source = fact.source;
          existing.created_at = fact.created_at;
          this.state_changed.push([existing.kind, existing.scope, Object.assign({}, existing.value)]);
          return true;
        }
        return false;
      }
    }
    var flagIdx = mergeFlagFactIfDuplicate(this.facts, fact);
    if (flagIdx >= 0) {
      var exFlag = this.facts[flagIdx];
      if (exFlag.state !== fact.state) {
        exFlag.state = fact.state;
        exFlag.created_at = fact.created_at;
        this.state_changed.push([exFlag.kind, exFlag.scope, Object.assign({}, exFlag.value)]);
        return true;
      }
      return false;
    }
    this.facts.push(fact);
    return true;
  };

  OBOL.facts = {
    ProofState: ProofState,
    makeFact: makeFact,
    factToJson: factToJson,
    factFromJson: factFromJson,
    valuesEqual: valuesEqual,
    FactSet: FactSet,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
