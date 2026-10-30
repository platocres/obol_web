/*
 * tools/corpus/facts-axis.js - FACTS, OUTCOME, and TIER-ATTRIBUTION axis of OBOL's v13.0
 * Dual-Pass Corpus Mining program (see docs/CORPUS-MINING.md).
 *
 * Rebased onto tools/corpus/markdown-extractor.js and tools/corpus/sandbox-loader.js:
 *   - Supports both 0xdf HTML-wrapped walkthroughs and standard CommonMark walkthroughs
 *     (e.g. --corpus-dir ../corpus/pg-practice-2026-10-29) plus chronological OCR sidecars.
 *   - Evaluates every block (including negative and empty blocks) through probeBlockStateless
 *     (full v13.0 sandbox: OBOL.packs, promptLine, parseActionOutput, OBOL.outcomes.classify).
 *   - Reports fact-kind confusion matrix (expected, correct, miss, forbidden_hit), Tier-1 vs
 *     Tier-2 (shape.js) vs Tier-3 (inference.js) attribution, and outcome classification
 *     (completed-negative, authorization-denied, rejected, environment-error, success, partial).
 *
 * CLI:
 *   node tools/corpus/facts-axis.js
 *   node tools/corpus/facts-axis.js --corpus-dir ../corpus/pg-practice-2026-10-29 --worksheet
 *   node tools/corpus/facts-axis.js --corpus-dir <dir> --labels <labels.json> --out <matrix.json>
 *   node tools/corpus/facts-axis.js --show <blockId>
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { createSandbox, probeBlockStateless, inferTargetIp } = require('./sandbox-loader.js');
const {
  extractWalkthroughTurns,
  detectTool,
  classifyAxis,
  outputHead,
  blockId,
  resolveCorpusWalkthroughsDir
} = require('./markdown-extractor.js');
const { verifyCorpus } = require('../verify-parser-corpus.js');

const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = fs.existsSync(path.resolve(ROOT, '..', 'corpus', '0xdf-htb'))
  ? path.resolve(ROOT, '..', 'corpus', '0xdf-htb')
  : path.resolve(ROOT, '..', '0xdf-offsec-complete-2026-08-20');
const DEFAULT_LABELS = path.resolve(__dirname, 'labels', '0xdf-facts.json');
const DEFAULT_MATRIX = path.resolve(__dirname, 'reports', '0xdf-facts-matrix.json');
const DEFAULT_WORKSHEET = path.resolve(__dirname, 'reports', '0xdf-facts-worksheet.json');

function buildCorpusIndex(corpusRoot, walkthroughsDir) {
  const substantialIndex = new Map();
  const negativeOrEmptyIndex = new Map();
  const files = fs.readdirSync(walkthroughsDir)
    .filter(f => f.toLowerCase().endsWith('.md'))
    .sort((a, b) => a.localeCompare(b));

  for (const file of files) {
    const md = fs.readFileSync(path.join(walkthroughsDir, file), 'utf8');
    const extracted = extractWalkthroughTurns(md, {
      corpusDir: corpusRoot,
      slug: file.slice(0, -3)
    });
    for (const u of extracted.turns) {
      const id = blockId(file, u.rawCommand != null ? u.rawCommand : u.command, u.output);
      const nonWsLen = (u.output || '').replace(/\s/g, '').length;
      const entry = {
        id: id,
        file: file,
        unit: u,
        lead: u.lead || '',
        follow: u.follow || '',
        isShortOrEmpty: nonWsLen < 20
      };
      if (nonWsLen >= 20) {
        if (!substantialIndex.has(id)) substantialIndex.set(id, entry);
      } else {
        if (!negativeOrEmptyIndex.has(id)) negativeOrEmptyIndex.set(id, entry);
      }
    }
  }

  // Merge: substantial blocks take priority on id lookup so all 102 existing 0xdf-facts.json ids
  // stay 100% deterministic, while negative/empty blocks are also addressable and gradable.
  const allIndex = new Map(substantialIndex);
  for (const [id, entry] of negativeOrEmptyIndex.entries()) {
    if (!allIndex.has(id)) allIndex.set(id, entry);
  }
  return {
    filesCount: files.length,
    allIndex: allIndex,
    substantialCount: substantialIndex.size,
    shortOrEmptyCount: negativeOrEmptyIndex.size
  };
}

function resolveDefaultPaths(corpusRoot, isDefaultCorpus, opts) {
  if (isDefaultCorpus) {
    return {
      labelsPath: opts.labels ? path.resolve(opts.labels) : DEFAULT_LABELS,
      matrixPath: opts.out ? path.resolve(opts.out) : DEFAULT_MATRIX,
      worksheetPath: opts.out ? path.resolve(opts.out) : DEFAULT_WORKSHEET
    };
  }
  const tag = path.basename(corpusRoot).replace(/[^a-zA-Z0-9_-]+/g, '-').toLowerCase() || 'corpus';
  const candidateLabels = [
    opts.labels ? path.resolve(opts.labels) : '',
    path.join(corpusRoot, 'facts-labels.json'),
    path.resolve(__dirname, 'labels', tag + '-facts.json')
  ].filter(Boolean);
  const chosenLabels = candidateLabels.find(p => fs.existsSync(p)) || candidateLabels[0];
  return {
    labelsPath: chosenLabels,
    matrixPath: opts.out ? path.resolve(opts.out) : path.resolve(ROOT, 'artifacts', tag + '-facts-matrix.json'),
    worksheetPath: opts.out ? path.resolve(opts.out) : path.resolve(ROOT, 'artifacts', tag + '-facts-worksheet.json')
  };
}

function readLabels(labelsPath) {
  if (!labelsPath || !fs.existsSync(labelsPath)) return { version: 2, description: 'unlabeled corpus', cases: [] };
  return JSON.parse(fs.readFileSync(labelsPath, 'utf8'));
}

function evaluateTierExpectation(expectedTier, tierInfo) {
  if (!expectedTier) return { checked: false, ok: true, mismatches: [] };
  if (typeof expectedTier === 'string') {
    const ok = tierInfo.dominant_tier === expectedTier;
    return {
      checked: true,
      ok: ok,
      mismatches: ok ? [] : ['dominant_tier expected ' + expectedTier + ', got ' + (tierInfo.dominant_tier || 'none')]
    };
  }
  if (typeof expectedTier === 'object') {
    const mismatches = [];
    for (const k of Object.keys(expectedTier)) {
      const got = (tierInfo.by_kind && tierInfo.by_kind[k]) || 'none';
      if (got !== expectedTier[k]) {
        mismatches.push(k + ': expected ' + expectedTier[k] + ', got ' + got);
      }
    }
    return { checked: true, ok: mismatches.length === 0, mismatches: mismatches };
  }
  return { checked: false, ok: true, mismatches: [] };
}

function runFactsAxis(opts) {
  opts = opts || {};
  const rawCorpusDir = opts.corpusDir
    ? path.resolve(opts.corpusDir)
    : (process.env.OBOL_CORPUS_DIR ? path.resolve(process.env.OBOL_CORPUS_DIR) : DEFAULT_CORPUS_DIR);
  const isDefaultCorpus = path.resolve(rawCorpusDir) === path.resolve(DEFAULT_CORPUS_DIR);
  const { corpusRoot, walkthroughsDir } = resolveCorpusWalkthroughsDir(rawCorpusDir);

  if (!fs.existsSync(walkthroughsDir)) {
    const err = new Error('facts-axis: local corpus not found at ' + walkthroughsDir);
    err.code = 'CORPUS_NOT_FOUND';
    throw err;
  }

  const paths = resolveDefaultPaths(corpusRoot, isDefaultCorpus, opts);
  const OBOL = opts.OBOL || createSandbox();
  const built = buildCorpusIndex(corpusRoot, walkthroughsDir);
  const index = built.allIndex;

  // ---- Show mode ----
  if (opts.showId) {
    const entry = index.get(opts.showId);
    if (!entry) {
      const err = new Error('facts-axis --show: no block with id ' + opts.showId);
      err.code = 'BLOCK_NOT_FOUND';
      throw err;
    }
    const probed = probeBlockStateless(OBOL, {
      command: entry.unit.command,
      stdout: entry.unit.output,
      promptLine: entry.unit.promptLine || '',
      source: entry.unit.command || ''
    });
    return { mode: 'show', entry: entry, probed: probed };
  }

  // ---- Worksheet mode ----
  const labelDoc = readLabels(paths.labelsPath);
  if (opts.worksheet) {
    const labeled = new Set((labelDoc.cases || []).map(c => c.id));
    const wsLimit = typeof opts.limit === 'number' && opts.limit > 0 ? opts.limit : 60;
    const rows = [];
    const tierSummary = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
    const outcomeSummary = Object.create(null);
    let negativeGraded = 0;

    for (const entry of index.values()) {
      if (labeled.has(entry.id)) continue;
      if (entry.isShortOrEmpty && opts.includeEmpty === false) continue;
      const tool = detectTool(entry.unit);
      const axis = classifyAxis(entry.unit, tool);
      if (opts.axis && axis !== opts.axis) continue;
      if (opts.tool && tool !== opts.tool) continue;

      const probed = probeBlockStateless(OBOL, {
        command: entry.unit.command,
        stdout: entry.unit.output,
        promptLine: entry.unit.promptLine || '',
        source: entry.unit.command || ''
      });
      const outKind = (probed.outcome && probed.outcome.kind) || 'unknown';
      outcomeSummary[outKind] = (outcomeSummary[outKind] || 0) + 1;
      if (entry.isShortOrEmpty || probed.facts.length === 0) negativeGraded++;
      tierSummary.tier1 += probed.tier_attribution.counts.tier1 || 0;
      tierSummary.tier2_shape += probed.tier_attribution.counts.tier2_shape || 0;
      tierSummary.tier3_inference += probed.tier_attribution.counts.tier3_inference || 0;

      rows.push({
        id: entry.id,
        file: entry.file,
        tool: tool,
        axis: axis,
        is_short_or_empty: entry.isShortOrEmpty,
        command: (entry.unit.command || '').slice(0, 120),
        observed_supported_kinds: probed.supported_kinds,
        observed_refuted_kinds: probed.refuted_kinds,
        observed_outcome: outKind,
        observed_tier_attribution: probed.tier_attribution.dominant_tier,
        observed_tier_by_kind: probed.tier_attribution.by_kind,
        output_head: outputHead(entry.unit.output).slice(0, 600),
        expected_kinds: [],
        forbidden_kinds: []
      });
    }

    rows.sort((a, b) => (a.tool + a.file).localeCompare(b.tool + b.file));
    const shown = rows.slice(0, wsLimit);
    const wsReport = {
      generated_at: new Date().toISOString(),
      corpus_dir: corpusRoot,
      filter: { axis: opts.axis || null, tool: opts.tool || null },
      total_unlabeled_matching: rows.length,
      negative_or_empty_blocks_graded: negativeGraded,
      tier_attribution_facts: tierSummary,
      outcome_distribution: outcomeSummary,
      shown: shown.length,
      rows: shown
    };

    if (opts.writeReports !== false) {
      fs.mkdirSync(path.dirname(paths.worksheetPath), { recursive: true });
      fs.writeFileSync(paths.worksheetPath, JSON.stringify(wsReport, null, 2));
    }
    return { mode: 'worksheet', worksheetPath: paths.worksheetPath, report: wsReport };
  }

  // ---- Matrix + Corpus Outcome/Tier Grading mode ----
  // Also grade negative/empty corpus blocks through OBOL.outcomes.classify so negative probes are measured.
  const corpusOutcomeDistribution = Object.create(null);
  const corpusNegativeOutcomeDistribution = Object.create(null);
  const corpusTierFacts = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  let negativeOrEmptyBlocksGraded = 0;

  if (opts.gradeAllBlocks || !isDefaultCorpus || !(labelDoc.cases && labelDoc.cases.length)) {
    for (const entry of index.values()) {
      const probed = probeBlockStateless(OBOL, {
        command: entry.unit.command,
        stdout: entry.unit.output,
        promptLine: entry.unit.promptLine || '',
        source: entry.unit.command || ''
      });
      const outKind = (probed.outcome && probed.outcome.kind) || 'unknown';
      corpusOutcomeDistribution[outKind] = (corpusOutcomeDistribution[outKind] || 0) + 1;
      if (entry.isShortOrEmpty || probed.facts.length === 0) {
        negativeOrEmptyBlocksGraded++;
        corpusNegativeOutcomeDistribution[outKind] = (corpusNegativeOutcomeDistribution[outKind] || 0) + 1;
      }
      corpusTierFacts.tier1 += probed.tier_attribution.counts.tier1 || 0;
      corpusTierFacts.tier2_shape += probed.tier_attribution.counts.tier2_shape || 0;
      corpusTierFacts.tier3_inference += probed.tier_attribution.counts.tier3_inference || 0;
    }
  }

  const missingBlocks = [];
  const cases = [];
  const outputs = Object.create(null);
  const promptLines = Object.create(null);
  const probeCache = Object.create(null);

  for (const lab of labelDoc.cases || []) {
    const entry = index.get(lab.id);
    if (!entry) {
      missingBlocks.push(lab.id);
      continue;
    }
    outputs[lab.id] = entry.unit.output;
    promptLines[lab.id] = entry.unit.promptLine || '';
    const targetIp = inferTargetIp(entry.unit.output + ' ' + entry.unit.command, '10.10.10.10');
    cases.push({
      id: lab.id,
      command: entry.unit.command,
      target: targetIp,
      expected_supported_kinds: lab.expected_kinds || [],
      forbidden_supported_kinds: lab.forbidden_kinds || [],
      expected_facts: lab.expected_values || []
    });
  }

  const idByCmdAndOut = new Map();
  for (const c of cases) {
    idByCmdAndOut.set(c.command + '\u0000' + (outputs[c.id] || ''), c.id);
  }
  const usePromptLineInMatrix = opts.includePromptLine === true
    || (opts.includePromptLine !== false && Number(labelDoc.version || 1) >= 2);

  function parseAdapter(parseOpts) {
    const key = (parseOpts.command || '') + '\u0000' + (parseOpts.stdout || '');
    const cid = idByCmdAndOut.get(key) || '';
    const probed = probeBlockStateless(OBOL, {
      actionId: parseOpts.actionId || '',
      command: parseOpts.command || '',
      stdout: parseOpts.stdout || '',
      stderr: parseOpts.stderr || '',
      promptLine: (usePromptLineInMatrix && cid) ? (promptLines[cid] || '') : '',
      source: parseOpts.source !== undefined ? parseOpts.source : (parseOpts.command || ''),
      scope: parseOpts.scope,
      domain: parseOpts.domain || ''
    });
    if (cid) probeCache[cid] = probed;
    return { facts: probed.facts, diagnostics: probed.diagnostics };
  }

  const manifest = { defaults: { target: '10.10.10.10' }, cases: cases };
  const result = verifyCorpus(manifest, tc => outputs[tc.id] || '', parseAdapter);

  const perKind = Object.create(null);
  function krow(k) {
    if (!perKind[k]) perKind[k] = { expected: 0, correct: 0, miss: 0 };
    return perKind[k];
  }

  const caseRows = [];
  let totalExpected = 0;
  let totalCorrect = 0;
  let totalMiss = 0;
  let forbiddenHits = 0;
  let lineageIssues = 0;
  let outcomeChecked = 0;
  let outcomeMismatches = 0;
  let tierChecked = 0;
  let tierMismatches = 0;
  const extraKinds = Object.create(null);
  const labeledTierFacts = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  const labeledDominantTiers = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  const labeledOutcomeDistribution = Object.create(null);

  for (const c of result.cases) {
    const lab = (labelDoc.cases || []).find(l => l.id === c.id);
    const entry = index.get(c.id);
    const probed = probeCache[c.id] || probeBlockStateless(OBOL, {
      command: entry.unit.command,
      stdout: entry.unit.output,
      promptLine: entry.unit.promptLine || '',
      source: entry.unit.command || ''
    });

    const supported = new Set(probed.supported_kinds);
    const expected = lab.expected_kinds || [];
    const misses = [];
    const corrects = [];
    for (const k of expected) {
      totalExpected++;
      krow(k).expected++;
      if (supported.has(k)) {
        totalCorrect++;
        krow(k).correct++;
        corrects.push(k);
      } else {
        totalMiss++;
        krow(k).miss++;
        misses.push(k);
      }
    }

    const forbHit = (lab.forbidden_kinds || []).filter(k => supported.has(k));
    forbiddenHits += forbHit.length;
    const expSet = new Set(expected);
    const extra = probed.supported_kinds.filter(k => !expSet.has(k));
    for (const k of extra) extraKinds[k] = (extraKinds[k] || 0) + 1;

    const lineage = c.errors.filter(e => /lineage/i.test(e));
    lineageIssues += lineage.length;

    const outKind = (probed.outcome && probed.outcome.kind) || 'unknown';
    labeledOutcomeDistribution[outKind] = (labeledOutcomeDistribution[outKind] || 0) + 1;
    if (entry.isShortOrEmpty || probed.facts.length === 0) {
      if (!opts.gradeAllBlocks && isDefaultCorpus) {
        negativeOrEmptyBlocksGraded++;
        corpusNegativeOutcomeDistribution[outKind] = (corpusNegativeOutcomeDistribution[outKind] || 0) + 1;
      }
    }

    labeledTierFacts.tier1 += probed.tier_attribution.counts.tier1 || 0;
    labeledTierFacts.tier2_shape += probed.tier_attribution.counts.tier2_shape || 0;
    labeledTierFacts.tier3_inference += probed.tier_attribution.counts.tier3_inference || 0;
    if (probed.tier_attribution.dominant_tier) {
      labeledDominantTiers[probed.tier_attribution.dominant_tier]++;
    }

    let outcomeOk = true;
    if (lab.outcome_expected) {
      outcomeChecked++;
      outcomeOk = (outKind === lab.outcome_expected);
      if (!outcomeOk) outcomeMismatches++;
    }
    const tierEval = evaluateTierExpectation(lab.tier_attribution, probed.tier_attribution);
    if (tierEval.checked) {
      tierChecked++;
      if (!tierEval.ok) tierMismatches++;
    }

    const row = {
      id: c.id,
      file: entry.file,
      command: (entry.unit.command || '').slice(0, 100),
      expected: expected,
      correct: corrects,
      miss: misses,
      forbidden_hit: forbHit,
      extra_observed: extra,
      outcome_observed: outKind,
      tier_attribution: probed.tier_attribution.dominant_tier,
      tier_by_kind: probed.tier_attribution.by_kind
    };
    if (lab.outcome_expected) {
      row.outcome_expected = lab.outcome_expected;
      row.outcome_ok = outcomeOk;
    }
    if (lab.tier_attribution) {
      row.tier_expected = lab.tier_attribution;
      row.tier_ok = tierEval.ok;
      if (tierEval.mismatches.length) row.tier_mismatches = tierEval.mismatches;
    }
    caseRows.push(row);
  }

  const report = {
    generated_at: new Date().toISOString(),
    corpus_dir: corpusRoot,
    note: 'FACTS axis: fact-kind confusion matrix over human-labeled real corpus blocks. correct = expected kind minted; miss = expected kind not minted; forbidden_hit = a guarded kind minted (false positive). extra = minted-but-unlabeled, informational only.',
    labeled_blocks: (labelDoc.cases || []).length,
    resolved_blocks: cases.length,
    missing_blocks: missingBlocks,
    totals: {
      expected_facts: totalExpected,
      correct: totalCorrect,
      miss: totalMiss,
      forbidden_hits: forbiddenHits,
      recall: totalExpected ? +(totalCorrect / totalExpected).toFixed(3) : null,
      lineage_issues: lineageIssues,
      outcome_checked: outcomeChecked,
      outcome_mismatches: outcomeMismatches,
      tier_checked: tierChecked,
      tier_mismatches: tierMismatches
    },
    tier_attribution: {
      labeled_facts_by_tier: labeledTierFacts,
      labeled_cases_by_dominant_tier: labeledDominantTiers,
      corpus_facts_by_tier: Object.keys(corpusOutcomeDistribution).length ? corpusTierFacts : labeledTierFacts
    },
    outcome_distribution: {
      labeled_cases: labeledOutcomeDistribution,
      corpus_all: Object.keys(corpusOutcomeDistribution).length ? corpusOutcomeDistribution : labeledOutcomeDistribution,
      negative_or_empty_blocks_graded: negativeOrEmptyBlocksGraded,
      negative_or_empty_outcomes: corpusNegativeOutcomeDistribution
    },
    per_kind: perKind,
    extra_observed_kinds: extraKinds,
    cases: caseRows
  };

  if (opts.writeReports !== false) {
    fs.mkdirSync(path.dirname(paths.matrixPath), { recursive: true });
    let skipTrackedWrite = false;
    // When running the default 0xdf smoke check without --out/--corpus-dir, avoid dirtying the
    // git-tracked 0xdf-facts-matrix.json if core confusion-matrix totals and per_kind are unchanged.
    if (isDefaultCorpus && !opts.out && !opts.forceWrite && fs.existsSync(paths.matrixPath)) {
      try {
        const prev = JSON.parse(fs.readFileSync(paths.matrixPath, 'utf8'));
        const prevCore = {
          labeled_blocks: prev.labeled_blocks,
          resolved_blocks: prev.resolved_blocks,
          missing_blocks: prev.missing_blocks,
          totals: prev.totals ? {
            expected_facts: prev.totals.expected_facts,
            correct: prev.totals.correct,
            miss: prev.totals.miss,
            forbidden_hits: prev.totals.forbidden_hits,
            recall: prev.totals.recall
          } : null,
          per_kind: prev.per_kind
        };
        const nextCore = {
          labeled_blocks: report.labeled_blocks,
          resolved_blocks: report.resolved_blocks,
          missing_blocks: report.missing_blocks,
          totals: {
            expected_facts: report.totals.expected_facts,
            correct: report.totals.correct,
            miss: report.totals.miss,
            forbidden_hits: report.totals.forbidden_hits,
            recall: report.totals.recall
          },
          per_kind: report.per_kind
        };
        if (JSON.stringify(prevCore) === JSON.stringify(nextCore)) {
          skipTrackedWrite = true;
        }
      } catch (_e) {}
    }
    if (!skipTrackedWrite) {
      fs.writeFileSync(paths.matrixPath, JSON.stringify(report, null, 2));
    }
  }

  return {
    mode: 'matrix',
    matrixPath: paths.matrixPath,
    forbiddenHits: forbiddenHits,
    outcomeMismatches: outcomeMismatches,
    tierMismatches: tierMismatches,
    report: report
  };
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  function flag(name) { return argv.includes('--' + name); }
  function opt(name, def) { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; }

  const corpusDir = opt('corpus-dir', '');
  const labelsPath = opt('labels', '');
  const outPath = opt('out', '');
  const showId = opt('show', '');
  const worksheet = flag('worksheet');
  const axis = opt('axis', '');
  const tool = opt('tool', '');
  const limit = parseInt(opt('limit', '60'), 10);
  const gradeAll = flag('grade-all');
  const forceWrite = flag('force-write');

  let res;
  try {
    res = runFactsAxis({
      corpusDir: corpusDir || undefined,
      labels: labelsPath || undefined,
      out: outPath || undefined,
      showId: showId || undefined,
      worksheet: worksheet,
      axis: axis || undefined,
      tool: tool || undefined,
      limit: limit,
      gradeAllBlocks: gradeAll,
      forceWrite: forceWrite
    });
  } catch (e) {
    if (e && (e.code === 'CORPUS_NOT_FOUND' || e.code === 'BLOCK_NOT_FOUND')) {
      console.error(e.message);
      process.exit(2);
    }
    throw e;
  }

  if (res.mode === 'show') {
    console.log('id      : ' + res.entry.id);
    console.log('file    : ' + res.entry.file);
    console.log('command : ' + res.entry.unit.command);
    console.log('outcome : ' + ((res.probed.outcome && res.probed.outcome.kind) || 'unknown'));
    console.log('tier    : ' + (res.probed.tier_attribution.dominant_tier || 'none') + ' ' + JSON.stringify(res.probed.tier_attribution.by_kind));
    console.log('observed supported: ' + res.probed.supported_kinds.join(', '));
    console.log('observed refuted  : ' + res.probed.refuted_kinds.join(', '));
    console.log('----- full output -----');
    console.log(res.entry.unit.output);
    console.log('----- end output -----');
    process.exit(0);
  }

  if (res.mode === 'worksheet') {
    const r = res.report;
    console.log(
      'facts-axis worksheet: ' + r.total_unlabeled_matching + ' unlabeled block(s) match' +
      (axis ? ' axis=' + axis : '') + (tool ? ' tool=' + tool : '') +
      ' (negative/empty graded: ' + r.negative_or_empty_blocks_graded + '); wrote ' + r.shown + ' to ' + res.worksheetPath
    );
    console.log('  tier facts: ' + JSON.stringify(r.tier_attribution_facts));
    console.log('  outcomes  : ' + JSON.stringify(r.outcome_distribution));
    process.exit(0);
  }

  const r = res.report;
  console.log('FACTS axis matrix: ' + r.resolved_blocks + ' / ' + r.labeled_blocks + ' labeled blocks resolved against the live corpus.');
  if (r.missing_blocks.length) {
    console.log('  ' + r.missing_blocks.length + ' label(s) did not match any current corpus block (ids: ' + r.missing_blocks.join(', ') + ').');
  }
  console.log(
    '  expected facts ' + r.totals.expected_facts +
    ' | correct ' + r.totals.correct +
    ' | miss ' + r.totals.miss +
    ' | recall ' + (r.totals.expected_facts ? (100 * r.totals.correct / r.totals.expected_facts).toFixed(1) + '%' : 'n/a')
  );
  console.log('  forbidden-kind hits (false positives on labeled set): ' + r.totals.forbidden_hits);
  console.log('  tier attribution (facts): ' + JSON.stringify(r.tier_attribution.corpus_facts_by_tier));
  console.log('  outcomes: ' + JSON.stringify(r.outcome_distribution.corpus_all) + ' (negative/empty graded: ' + r.outcome_distribution.negative_or_empty_blocks_graded + ')');
  if (r.totals.outcome_checked > 0) {
    console.log('  outcome assertions: ' + (r.totals.outcome_checked - r.totals.outcome_mismatches) + '/' + r.totals.outcome_checked + ' matched');
  }
  if (r.totals.tier_checked > 0) {
    console.log('  tier assertions   : ' + (r.totals.tier_checked - r.totals.tier_mismatches) + '/' + r.totals.tier_checked + ' matched');
  }
  const missKinds = Object.keys(r.per_kind)
    .filter(k => r.per_kind[k].miss > 0)
    .sort((a, b) => r.per_kind[k].miss - r.per_kind[a].miss);
  if (missKinds.length) {
    console.log('\n  misses by kind (the facts-axis backlog):');
    for (const k of missKinds) {
      console.log('    ' + k.padEnd(28) + ' miss ' + r.per_kind[k].miss + ' / expected ' + r.per_kind[k].expected);
    }
  }
  console.log('\nReport: ' + res.matrixPath);
  process.exit((res.forbiddenHits > 0 || res.outcomeMismatches > 0 || res.tierMismatches > 0) ? 1 : 0);
}

module.exports = {
  buildCorpusIndex: buildCorpusIndex,
  runFactsAxis: runFactsAxis
};
