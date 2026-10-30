/*
 * tools/corpus/sandbox-loader.js - Unified v13.0 VM Sandbox & Stateful Engagement Loader
 * (qa-only; never ships to prod, never runs at runtime).
 *
 * Loads the complete OBOL v13.0 engine + UI store/ingest/coach runtime into an isolated Node VM
 * sandbox in exact browser dependency order (matching tests/engine/adversarial-stateful-replays-smoke.js,
 * plus conditional loading of optional tunnels.js, tool-staging.js, and parsers/edb.js whenever
 * present on disk before parsers/index.js).
 *
 * Exposes:
 *   - createSandbox(opts)
 *   - classifyFactTier(fact)
 *   - summarizeTierAttribution(facts)
 *   - probeBlockStateless(OBOL, opts)
 *   - createEngagementSession(OBOL, opts)
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DEFAULT_QA_ROOT = path.resolve(__dirname, '..', '..');

const BASE_PRE_PARSER_FILES = [
  'assets/engine/facts.js',
  'assets/engine/loot.js',
  'assets/engine/profile.js',
  'assets/engine/vfs.js',
  'assets/engine/phases.js',
  'assets/engine/outcomes.js',
  'assets/engine/context.js',
  'assets/engine/pack.js',
  'assets/engine/packs.js',
  'data/packs-bundle.js',
  'data/field-notes.js',
  'data/decision-forks.js',
  'data/parser-signatures.js',
  'assets/engine/command.js',
  'assets/engine/workspace.js',
  'assets/engine/graph.js',
  'assets/engine/chain.js',
  'assets/engine/engmap.js',
  'assets/engine/decisionmap.js'
];

const OPTIONAL_PRE_PARSER_FILES = [
  'assets/engine/tunnels.js',
  'assets/engine/tool-staging.js'
];

const CORE_PARSER_FILES = [
  'assets/engine/parsers/common.js',
  'assets/engine/parsers/nmap.js',
  'assets/engine/parsers/directory.js',
  'assets/engine/parsers/creds.js',
  'assets/engine/parsers/host.js',
  'assets/engine/parsers/services.js',
  'assets/engine/parsers/database.js',
  'assets/engine/parsers/web.js',
  'assets/engine/parsers/websource.js',
  'assets/engine/parsers/findings.js',
  'assets/engine/parsers/shape.js',
  'assets/engine/parsers/pivot.js',
  'assets/engine/parsers/dns.js',
  'assets/engine/parsers/blockers.js',
  'assets/engine/parsers/nxc-catalog.js',
  'assets/engine/parsers/inference.js'
];

const OPTIONAL_PRE_INDEX_PARSER_FILES = [
  'assets/engine/parsers/edb.js'
];

const POST_INDEX_FILES = [
  'assets/engine/parsers/index.js',
  'assets/engine/bloodhound.js',
  'assets/engine/resolve.js',
  'assets/ui/util.js',
  'assets/ui/icons.js',
  'assets/ui/store.js',
  'assets/ui/ctxbar.js',
  'assets/ui/ingest.js',
  'assets/ui/routes/path.js'
];

function resolveLoadOrder(qaRoot) {
  const root = qaRoot ? path.resolve(qaRoot) : DEFAULT_QA_ROOT;
  const out = BASE_PRE_PARSER_FILES.slice();
  for (const rel of OPTIONAL_PRE_PARSER_FILES) {
    if (fs.existsSync(path.join(root, rel))) out.push(rel);
  }
  for (const rel of CORE_PARSER_FILES) out.push(rel);
  for (const rel of OPTIONAL_PRE_INDEX_PARSER_FILES) {
    if (fs.existsSync(path.join(root, rel))) out.push(rel);
  }
  for (const rel of POST_INDEX_FILES) out.push(rel);
  return out;
}

function makeStorageStub(backing) {
  const mem = backing || Object.create(null);
  return {
    get length() { return Object.keys(mem).length; },
    key: function (i) { const ks = Object.keys(mem); return ks[i] !== undefined ? ks[i] : null; },
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },
    setItem: function (k, v) { mem[k] = String(v); },
    removeItem: function (k) { delete mem[k]; },
    clear: function () { for (const k of Object.keys(mem)) delete mem[k]; }
  };
}

function createSandbox(opts) {
  opts = opts || {};
  const root = opts.qaRoot ? path.resolve(opts.qaRoot) : DEFAULT_QA_ROOT;
  const verbose = !!opts.verbose;
  const localMem = Object.create(null);
  const sessionMem = Object.create(null);

  const consoleProxy = verbose
    ? console
    : {
        log: function () {},
        warn: function () {},
        error: function () {},
        info: function () {}
      };

  const sandbox = {
    console: consoleProxy,
    Date: Date,
    Math: Math,
    JSON: JSON,
    Object: Object,
    Array: Array,
    String: String,
    Number: Number,
    Boolean: Boolean,
    RegExp: RegExp,
    Error: Error,
    Map: Map,
    Set: Set,
    WeakMap: WeakMap,
    Promise: Promise,
    Uint8Array: Uint8Array,
    ArrayBuffer: ArrayBuffer,
    Buffer: Buffer,
    parseInt: parseInt,
    parseFloat: parseFloat,
    isNaN: isNaN,
    isFinite: isFinite,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    setTimeout: function (fn) { if (opts.runTimers && typeof fn === 'function') fn(); return 0; },
    clearTimeout: function () {},
    document: {
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      createElement: function (tag) {
        return {
          tagName: String(tag || 'DIV').toUpperCase(),
          innerHTML: '',
          textContent: '',
          style: {},
          children: [],
          classList: {
            add: function () {},
            remove: function () {},
            toggle: function () {},
            contains: function () { return false; }
          },
          setAttribute: function () {},
          getAttribute: function () { return null; },
          hasAttribute: function () { return false; },
          removeAttribute: function () {},
          appendChild: function () {},
          insertBefore: function () {},
          querySelector: function () { return null; },
          querySelectorAll: function () { return []; },
          addEventListener: function () {}
        };
      },
      getElementById: function (id) {
        if (!sandbox._elements) sandbox._elements = Object.create(null);
        if (!sandbox._elements[id]) {
          sandbox._elements[id] = {
            id: id,
            innerHTML: '',
            textContent: '',
            value: '',
            style: {},
            children: [],
            classList: {
              add: function () {},
              remove: function () {},
              toggle: function () {},
              contains: function () { return false; }
            },
            setAttribute: function () {},
            getAttribute: function () { return null; },
            addEventListener: function () {}
          };
        }
        return sandbox._elements[id];
      }
    },
    localStorage: makeStorageStub(localMem),
    sessionStorage: makeStorageStub(sessionMem),
    navigator: {},
    location: { hash: '#/path' }
  };

  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  sandbox.root = sandbox;
  vm.createContext(sandbox);

  const files = resolveLoadOrder(root);
  for (const rel of files) {
    const abs = path.join(root, rel);
    const code = fs.readFileSync(abs, 'utf8');
    vm.runInContext(code, sandbox, { filename: rel });
  }

  sandbox.OBOL._sandboxLoadedFiles = files;
  sandbox.OBOL._sandboxContext = sandbox;
  return sandbox.OBOL;
}

const TIER_RANK = { tier1: 1, tier2_shape: 2, tier3_inference: 3 };

function classifyFactTier(fact) {
  const v = (fact && fact.value && typeof fact.value === 'object') ? fact.value : {};
  const via = String(v.via || '');
  if (via === 'shape' || via === 'vulnmatch' || v.shape === true) return 'tier2_shape';
  if (/^(?:context-|prompt-telemetry|causal-entailment|entailment|inference)/.test(via)) return 'tier3_inference';
  return 'tier1';
}

function summarizeTierAttribution(facts) {
  const counts = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  const byKind = Object.create(null);
  const kindsByTier = { tier1: [], tier2_shape: [], tier3_inference: [] };
  const seenTierKind = { tier1: Object.create(null), tier2_shape: Object.create(null), tier3_inference: Object.create(null) };

  for (const f of facts || []) {
    if (!f || !f.kind) continue;
    const tier = classifyFactTier(f);
    counts[tier] = (counts[tier] || 0) + 1;
    if (!seenTierKind[tier][f.kind]) {
      seenTierKind[tier][f.kind] = 1;
      kindsByTier[tier].push(f.kind);
    }
    if (!byKind[f.kind] || TIER_RANK[tier] < TIER_RANK[byKind[f.kind]]) {
      byKind[f.kind] = tier;
    }
  }

  let dominant = null;
  if (counts.tier1 > 0) dominant = 'tier1';
  else if (counts.tier2_shape > 0) dominant = 'tier2_shape';
  else if (counts.tier3_inference > 0) dominant = 'tier3_inference';

  return {
    counts: counts,
    by_kind: byKind,
    kinds_by_tier: kindsByTier,
    dominant_tier: dominant
  };
}

const IPV4_SNIFF_RE = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;

function inferTargetIp(text, fallbackIp) {
  const m = String(text || '').match(IPV4_SNIFF_RE);
  return m ? m[1] : (fallbackIp || '10.10.10.10');
}

function probeBlockStateless(OBOL, opts) {
  opts = opts || {};
  const command = String(opts.command || '');
  const stdout = String(opts.stdout != null ? opts.stdout : (opts.output || ''));
  const stderr = String(opts.stderr || '');
  const promptLine = String(opts.promptLine || '');
  const explicitTarget = opts.target
    || (/^host:/.test(String(opts.scope || '')) ? String(opts.scope).slice(5) : '');
  const targetIp = explicitTarget || inferTargetIp(stdout + ' ' + command, '10.10.10.10');
  const scope = opts.scope || ('host:' + targetIp);
  const seedFacts = Array.isArray(opts.seedFacts) ? opts.seedFacts : [];
  const params = Object.assign({ target: targetIp }, opts.params || {});
  // Do not set context.target in stateless probes unless opts.entail is requested:
  // inference.js uses context.target / opts.entail to detect live stateful engagements
  // for out-of-order causal entailment, whereas Pass 1 probes single blocks statelessly.
  let parseContext = opts.context ? Object.assign({}, opts.context) : undefined;
  if (promptLine) {
    parseContext = Object.assign({ params: params }, parseContext || {}, { promptLine: promptLine });
  } else if (parseContext && !parseContext.params) {
    parseContext.params = params;
  }

  const parsed = OBOL.parsers.parseActionOutput({
    actionId: opts.actionId || '',
    command: command,
    stdout: stdout,
    stderr: stderr,
    source: opts.source !== undefined ? opts.source : command,
    scope: scope,
    domain: opts.domain || '',
    seedFacts: seedFacts,
    entail: !!opts.entail,
    context: parseContext
  });

  const facts = (parsed && parsed.facts) || [];
  const diagnostics = (parsed && parsed.diagnostics) || [];
  const supported = [];
  const refuted = [];
  for (const f of facts) {
    if (!f || !f.kind) continue;
    if (f.state === 'refuted') {
      if (refuted.indexOf(f.kind) < 0) refuted.push(f.kind);
    } else if (supported.indexOf(f.kind) < 0) {
      supported.push(f.kind);
    }
  }

  const tierInfo = summarizeTierAttribution(facts);
  const outcome = (OBOL.outcomes && typeof OBOL.outcomes.classify === 'function')
    ? OBOL.outcomes.classify({
        text: stdout,
        command: command,
        facts: facts,
        diagnostics: diagnostics,
        context: { target: targetIp, command: command, actionId: opts.actionId || '' },
        previousFacts: seedFacts
      })
    : { kind: facts.length ? 'success' : 'unknown', conclusive: facts.length > 0 };

  return {
    target: targetIp,
    scope: scope,
    facts: facts,
    diagnostics: diagnostics,
    supported_kinds: supported,
    refuted_kinds: refuted,
    tier_attribution: tierInfo,
    outcome: outcome
  };
}

function normalizeBloodHoundJsonFiles(payload) {
  if (!payload) return [];
  const out = [];
  if (typeof payload === 'string') {
    const trimmed = payload.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      return normalizeBloodHoundJsonFiles(JSON.parse(trimmed));
    }
    if (fs.existsSync(payload)) {
      const stat = fs.statSync(payload);
      if (stat.isDirectory()) {
        for (const fn of fs.readdirSync(payload).filter(f => f.toLowerCase().endsWith('.json'))) {
          out.push({ name: fn, text: fs.readFileSync(path.join(payload, fn), 'utf8') });
        }
        return out;
      }
      return [{ name: path.basename(payload), text: fs.readFileSync(payload, 'utf8') }];
    }
    return out;
  }

  if (Array.isArray(payload)) {
    payload.forEach((item, idx) => {
      if (!item) return;
      if (typeof item === 'string') {
        out.push(...normalizeBloodHoundJsonFiles(item));
        return;
      }
      if (typeof item === 'object') {
        if (item.name && (typeof item.text === 'string' || item.data !== undefined)) {
          const nm = item.name.toLowerCase().endsWith('.json') ? item.name : (item.name + '.json');
          const txt = typeof item.text === 'string' ? item.text : JSON.stringify(item.data);
          out.push({ name: nm, text: txt });
          return;
        }
        const meta = item.meta || item.Meta;
        if (meta && (meta.type || meta.Type)) {
          const kind = String(meta.type || meta.Type).toLowerCase();
          out.push({ name: kind + '-' + idx + '.json', text: JSON.stringify(item) });
          return;
        }
      }
    });
    return out;
  }

  if (typeof payload === 'object') {
    const meta = payload.meta || payload.Meta;
    if (meta && (meta.type || meta.Type)) {
      const kind = String(meta.type || meta.Type).toLowerCase();
      return [{ name: kind + '.json', text: JSON.stringify(payload) }];
    }
    const knownBuckets = ['users', 'groups', 'computers', 'domains', 'gpos', 'ous', 'containers', 'certtemplates'];
    for (const k of knownBuckets) {
      if (payload[k] !== undefined) {
        const val = payload[k];
        const wrapped = Array.isArray(val) ? { meta: { type: k }, data: val } : val;
        out.push({ name: k + '.json', text: JSON.stringify(wrapped) });
      }
    }
  }
  return out;
}

function createEngagementSession(OBOL, opts) {
  opts = opts || {};
  const initialTargets = Array.isArray(opts.targets) ? opts.targets.slice() : [];
  const primaryIp = opts.target
    || (initialTargets[0] && (typeof initialTargets[0] === 'string' ? initialTargets[0] : initialTargets[0].ip))
    || '10.10.10.50';
  const lhost = opts.lhost || '10.10.14.5';
  const lport = String(opts.lport || '4444');
  const multiTarget = !!opts.multiTarget || initialTargets.length > 1;

  const eng = OBOL.store._newEngagement(opts.name || 'CorpusReplay');
  if (opts.profile && typeof opts.profile === 'object') {
    eng.profile = Object.assign(eng.profile || {}, opts.profile);
  }
  if (opts.lens && OBOL._sandboxContext && OBOL._sandboxContext.localStorage) {
    const normLens = opts.lens === 'all' ? 'all' : 'oscp+';
    OBOL._sandboxContext.localStorage.setItem('obol.scope-lens', normLens);
    OBOL._sandboxContext.localStorage.setItem('obol.scope.lens.v1', normLens);
  }

  eng.params = Object.assign(eng.params || {}, {
    target: primaryIp,
    lhost: lhost,
    lport: lport,
    domain: opts.domain || '',
    scope_defined: true
  });
  eng.activeTarget = primaryIp;
  eng.targets = [];

  OBOL.store.active = function () { return eng; };
  OBOL.store.update = function (mutator) {
    const contextBefore = OBOL.context ? OBOL.context.beforeUpdate(eng) : null;
    mutator(eng);
    if (OBOL.context) OBOL.context.reconcile(eng, contextBefore);
  };

  function registerTarget(ip, meta) {
    const cleanIp = String(ip || '').trim();
    if (!cleanIp || cleanIp === lhost || cleanIp === '127.0.0.1' || cleanIp === '0.0.0.0') return null;
    meta = meta || {};
    const existing = (eng.targets || []).find(t => t && t.ip === cleanIp);
    const patch = { ip: cleanIp };
    if (meta.hostname !== undefined || !existing) patch.hostname = meta.hostname || (existing && existing.hostname) || '';
    if (meta.domain !== undefined || !existing) patch.domain = meta.domain || (existing && existing.domain) || '';
    if (meta.os !== undefined || !existing) patch.os = meta.os || (existing && existing.os) || '';
    OBOL.store.editTarget(cleanIp, patch);
    return (eng.targets || []).find(t => t && t.ip === cleanIp) || null;
  }

  if (initialTargets.length) {
    for (const t of initialTargets) {
      if (typeof t === 'string') registerTarget(t, {});
      else if (t && t.ip) registerTarget(t.ip, t);
    }
  } else {
    registerTarget(primaryIp, { hostname: opts.hostname || '', os: opts.os || '', domain: opts.domain || '' });
  }
  OBOL.store.setActiveTarget(primaryIp);

  function setActiveTarget(ip, meta) {
    if (!ip) {
      OBOL.store.setActiveTarget(null);
      return null;
    }
    const cleanIp = String(ip).trim();
    registerTarget(cleanIp, meta);
    OBOL.store.setActiveTarget(cleanIp);
    return cleanIp;
  }

  function getActiveTarget() {
    return (OBOL.store.activeTarget && OBOL.store.activeTarget()) || (eng.params && eng.params.target) || primaryIp;
  }

  function getTargets() {
    return (eng.targets || []).slice();
  }

  function factSetForTarget(ip) {
    const t = ip || getActiveTarget();
    return (t && OBOL.store.factSetForTarget) ? OBOL.store.factSetForTarget(t) : OBOL.store.factSet();
  }

  function computeCoach(overrideTarget) {
    const t = overrideTarget !== undefined ? overrideTarget : getActiveTarget();
    return OBOL.coach.compute(t);
  }

  function nextActionsV2(overrideTarget) {
    const t = overrideTarget !== undefined ? overrideTarget : getActiveTarget();
    const facts = factSetForTarget(t);
    const pack = OBOL.packs.actions();
    const doneIds = OBOL.store.doneIdsForTarget ? OBOL.store.doneIdsForTarget(t, facts, eng) : {};
    return OBOL.pack.nextActionsV2(facts, pack, { doneIds: doneIds });
  }

  function ingestTurn(turnOpts) {
    turnOpts = turnOpts || {};
    const cmd = String(turnOpts.command || '');
    const stdout = String(turnOpts.stdout != null ? turnOpts.stdout : (turnOpts.text || turnOpts.output || ''));
    const promptLine = String(turnOpts.promptLine || '');

    let targetIp = turnOpts.target || '';
    if (!targetIp && multiTarget) {
      const m = (cmd + ' ' + stdout).match(IPV4_SNIFF_RE);
      if (m && m[1] !== lhost) targetIp = m[1];
    }
    if (!targetIp) targetIp = getActiveTarget();
    if (targetIp && targetIp !== lhost) {
      const known = (eng.targets || []).some(t => t && t.ip === targetIp);
      if (!known && (multiTarget || opts.autoRegisterTargets !== false)) {
        registerTarget(targetIp, turnOpts.targetMeta || {});
      }
      if (turnOpts.switchActiveTarget !== false && getActiveTarget() !== targetIp) {
        OBOL.store.setActiveTarget(targetIp);
      }
    }

    const factsBefore = (eng.facts || []).length;
    let ingestResult = null;
    if (OBOL.ingest && typeof OBOL.ingest.run === 'function' && turnOpts.direct !== true) {
      ingestResult = OBOL.ingest.run({
        actionId: turnOpts.actionId || '',
        command: cmd,
        text: stdout,
        promptLine: promptLine,
        scope: 'host:' + targetIp,
        target: targetIp,
        forceTarget: turnOpts.forceTarget !== undefined ? turnOpts.forceTarget : targetIp
      });
    } else {
      const fsBefore = factSetForTarget(targetIp);
      const probed = probeBlockStateless(OBOL, {
        actionId: turnOpts.actionId || '',
        command: cmd,
        stdout: stdout,
        promptLine: promptLine,
        target: targetIp,
        scope: 'host:' + targetIp,
        domain: eng.params.domain || '',
        params: eng.params,
        seedFacts: fsBefore.facts || []
      });
      if (probed.facts.length) OBOL.store.addFacts(probed.facts);
      ingestResult = {
        facts: probed.facts,
        diagnostics: probed.diagnostics,
        outcome: probed.outcome,
        target: targetIp
      };
    }

    const mintedFacts = (ingestResult && ingestResult.facts) || [];
    const tierInfo = summarizeTierAttribution(mintedFacts);
    return {
      target: targetIp,
      facts_before: factsBefore,
      facts_after: (eng.facts || []).length,
      minted_facts: mintedFacts,
      tier_attribution: tierInfo,
      outcome: (ingestResult && ingestResult.outcome) || null,
      ingest_result: ingestResult
    };
  }

  function ingestBloodHound(payload, bhOpts) {
    bhOpts = bhOpts || {};
    const jsonFiles = normalizeBloodHoundJsonFiles(payload);
    if (!jsonFiles.length) return { summary: null, facts: [] };
    const summary = OBOL.bloodhound.parseJson(jsonFiles);
    let owned = Array.isArray(bhOpts.owned) ? bhOpts.owned.slice() : [];
    if (!owned.length) {
      const fsAll = OBOL.store.factSet();
      for (const kind of ['credential.validated', 'credential.available']) {
        for (const v of (fsAll.values(kind) || [])) {
          const u = v && (v.user || v.username || v.account);
          if (u && owned.indexOf(u) < 0) owned.push(u);
        }
      }
    }
    const paths = owned.length
      ? OBOL.bloodhound.ownedPaths(summary, owned)
      : OBOL.bloodhound.nearestToGoal(summary);
    const scope = bhOpts.scope || (summary.domain ? ('domain:' + summary.domain) : 'domain:unknown');
    const bhFacts = OBOL.bloodhound.toFacts(summary, paths, scope);
    if (bhFacts.length) OBOL.store.addFacts(bhFacts);
    OBOL.store.update(function (e) {
      e.bloodhound = summary;
      if (summary.domain && !(e.params && e.params.domain)) {
        e.params = e.params || {};
        e.params.domain = summary.domain;
      }
    });
    return { summary: summary, paths: paths, facts: bhFacts };
  }

  function snapshot() {
    return JSON.parse(JSON.stringify(eng));
  }

  function restore(snap) {
    if (!snap || typeof snap !== 'object') return;
    const cloned = JSON.parse(JSON.stringify(snap));
    for (const k of Object.keys(eng)) delete eng[k];
    Object.assign(eng, cloned);
  }

  return {
    OBOL: OBOL,
    eng: eng,
    registerTarget: registerTarget,
    setActiveTarget: setActiveTarget,
    getActiveTarget: getActiveTarget,
    getTargets: getTargets,
    factSetForTarget: factSetForTarget,
    ingestTurn: ingestTurn,
    ingestBloodHound: ingestBloodHound,
    computeCoach: computeCoach,
    nextActionsV2: nextActionsV2,
    snapshot: snapshot,
    restore: restore
  };
}

module.exports = {
  resolveLoadOrder: resolveLoadOrder,
  createSandbox: createSandbox,
  classifyFactTier: classifyFactTier,
  summarizeTierAttribution: summarizeTierAttribution,
  inferTargetIp: inferTargetIp,
  probeBlockStateless: probeBlockStateless,
  normalizeBloodHoundJsonFiles: normalizeBloodHoundJsonFiles,
  createEngagementSession: createEngagementSession
};
