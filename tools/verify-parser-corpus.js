'use strict';

// Observe the actual parser return before comparing the fixture expectations.
// Expected kinds are assertions only; they never become observed parser emits.
function deepContains(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && expected.every(e => actual.some(a => deepContains(a, e)));
  if (expected && typeof expected === 'object') return !!actual && typeof actual === 'object' && Object.keys(expected).every(k => deepContains(actual[k], expected[k]));
  return actual === expected;
}
function verifyCorpus(manifest, readOutput, parse) {
  const cases = [], minted = Object.create(null), defaults = manifest.defaults || {};
  for (const tc of manifest.cases || []) {
    const errors = []; let facts = [];
    try {
      const result = parse({ actionId:tc.action_id || '',command:tc.command || '',stdout:readOutput(tc),stderr:'',source:tc.command || '',
        scope:'host:' + (tc.target || defaults.target || '10.10.10.10'),domain:tc.domain || '' });
      facts = result.facts || [];
      if(result.error)errors.push('Parser error: ' + result.error);
      for(const d of result.diagnostics || [])errors.push('Parser diagnostic: ' + (d.parser || '') + ' ' + (d.message || ''));
    } catch(error) {errors.push('Fixture or parser error: ' + error.message);}
    const supported = new Set(), refuted = new Set();
    for(const f of facts){minted[f.kind]=true;if(f.state==='supported')supported.add(f.kind);if(f.state==='refuted')refuted.add(f.kind);}
    for(const kind of tc.expected_supported_kinds || [])if(!supported.has(kind))errors.push('Missing supported kind: ' + kind);
    for(const kind of tc.expected_refuted_kinds || [])if(!refuted.has(kind))errors.push('Missing refuted kind: ' + kind);
    const allowed = new Set(tc.allow_default_forbidden_supported_kinds || []);
    const forbidden = new Set((defaults.forbidden_supported_kinds || []).filter(k => !allowed.has(k)).concat(tc.forbidden_supported_kinds || []));
    for(const kind of forbidden)if(supported.has(kind))errors.push('Forbidden supported kind: ' + kind);
    for(const expected of tc.expected_facts || [])if(!facts.some(f => f.kind === expected.kind && f.state === (expected.state || 'supported')
      && (expected.scope === undefined || expected.scope === f.scope) && (expected.value_contains === undefined || deepContains(f.value, expected.value_contains))))errors.push('Expected fact not satisfied: ' + expected.kind);
    if(typeof tc.expected_fact_count === 'number' && tc.expected_fact_count !== facts.length)errors.push('Fact count mismatch');
    for(const f of facts)if(f.source !== (tc.command || ''))errors.push('Fact lineage mismatch: ' + f.kind);
    cases.push({id:tc.id,passed:errors.length===0,errors,observed:Array.from(supported)});
  }
  return {minted,cases,total:cases.length,passed:cases.filter(c=>c.passed).length,failures:cases.filter(c=>!c.passed)};
}
module.exports = {verifyCorpus};
