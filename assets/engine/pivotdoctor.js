/*!
 * obol engine — pivotdoctor.js — OBOL.pivotDoctor
 *
 * The diagnostic half of the pivot troubleshooter. Pure, DOM-free, testable. Runs the conservative
 * recognizers in data/pivot-troubleshooter.js over output the operator pasted for a chosen symptom,
 * and returns a verdict: the problem line to highlight and a suggested fix. When nothing matches it
 * returns matched:false with the general checklist, so it hands over honestly instead of guessing.
 *
 * It produces DIAGNOSTIC findings for the UI only; it never mints attack facts into the ledger, so
 * the proof discipline is untouched. Recognizing a broken config is a different muscle than
 * recognizing attack evidence, hence its own small engine rather than the attack-fact parsers.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  function symptoms() { return OBOL.PIVOT_SYMPTOMS || []; }
  function get(key) { var a = symptoms(); for (var i = 0; i < a.length; i++) if (a[i].key === key) return a[i]; return null; }

  // Fill {{tokens}} from engagement params; {{user}} falls back to username; an unknown token stays
  // as a visible <token> so the operator knows what to supply. Mirrors the tunnel wizard's fill.
  function fill(cmd, params) {
    params = params || {};
    return String(cmd == null ? '' : cmd).replace(/\{\{(\w+)\}\}/g, function (m, k) {
      var v = params[k];
      if ((v === undefined || v === '') && k === 'user') v = params.username;
      return (v !== undefined && v !== '') ? v : '<' + k + '>';
    });
  }

  // First line of `text` that matches `re` (for highlighting the problem line in the paste).
  function matchingLine(text, re) {
    var lines = String(text || '').split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) { if (re.test(lines[i])) return lines[i].trim(); }
    return '';
  }

  // Run the recognizers for one symptom over pasted output. First diagnosis whose `re` matches and
  // whose `notRe` (if any) does NOT match wins. Returns a verdict, or matched:false + the checklist.
  function diagnose(key, text, params) {
    var s = get(key); if (!s) return null;
    var t = String(text || '');
    var trimmed = t.replace(/\s+/g, '');
    if (!trimmed) {
      return { matched: false, empty: true,
        verdict: 'No output to read yet. Run the probe command above on the right machine, then paste what it prints here.',
        checklist: (OBOL.PIVOT_CHECKLIST || []).map(function (c) { return fill(c, params); }) };
    }
    var ds = s.diagnoses || [];
    for (var i = 0; i < ds.length; i++) {
      var d = ds[i], re, notRe = null;
      try { re = new RegExp(d.re, 'i'); } catch (e) { continue; }
      if (d.notRe) { try { notRe = new RegExp(d.notRe, 'i'); } catch (e2) { notRe = null; } }
      if (re.test(t) && !(notRe && notRe.test(t))) {
        return {
          matched: true, id: d.id, healthy: !!d.healthy,
          verdict: fill(d.verdict, params),
          fix: d.fix ? fill(d.fix, params) : '',
          line: matchingLine(t, re),
        };
      }
    }
    return { matched: false,
      verdict: 'obol could not pin the cause from this output. That is honest, not a dead end: here is the short checklist that catches most lab pivots.',
      checklist: (OBOL.PIVOT_CHECKLIST || []).map(function (c) { return fill(c, params); }) };
  }

  OBOL.pivotDoctor = { symptoms: symptoms, get: get, fill: fill, diagnose: diagnose };
})(typeof globalThis !== 'undefined' ? globalThis : this);
