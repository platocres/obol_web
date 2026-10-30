/*
 * tools/corpus/harvest-markdown.js - Pass 1 (Stateless Parser, Outcome, and Tier-Attribution
 * Harvester) of OBOL's v13.0 Dual-Pass Corpus Mining program (see docs/CORPUS-MINING.md).
 *
 * Rebased onto tools/corpus/markdown-extractor.js and tools/corpus/sandbox-loader.js so it
 * harvests terminal turns uniformly across:
 *   - 0xdf <div class="language-..."> HTML-wrapped walkthroughs, AND
 *   - Standard CommonMark ``` / ~~~ walkthroughs (OffSec PG Practice, Challenge Labs, alternates),
 *   - Plus optional chronological OCR sidecar files (<corpusDir>/ocr-sidecars/<slug>.json).
 *
 * Every turn (including short, empty, and negative blocks) is run through OBOL's full v13.0
 * sandbox (probeBlockStateless -> parseActionOutput with full OBOL.packs + promptLine +
 * OBOL.outcomes.classify), recording:
 *   - Fact minting and the five signal axes (enumeration, state-change, loot, outcome, none),
 *   - Outcome classification distribution across all turns and negative/empty turns
 *     (completed-negative, authorization-denied, rejected, environment-error, success, partial),
 *   - Tier-1 (primary parsers) vs Tier-2 (shape.js) vs Tier-3 (inference.js) attribution.
 *
 * CLI:
 *   node tools/corpus/harvest-markdown.js
 *   node tools/corpus/harvest-markdown.js --corpus-dir ../corpus/pg-practice-2026-10-29
 *   node tools/corpus/harvest-markdown.js --corpus-dir <dir> --slugs a,b --out report.json
 *
 * House style: no em dashes, no en dashes, no emoji.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { createSandbox, probeBlockStateless } = require('./sandbox-loader.js');
const {
  FACT_BEARING,
  extractWalkthroughTurns,
  discoverAlternates,
  detectTool,
  classifyAxis,
  resolveCorpusWalkthroughsDir
} = require('./markdown-extractor.js');

const ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CORPUS_DIR = fs.existsSync(path.resolve(ROOT, '..', 'corpus', '0xdf-htb'))
  ? path.resolve(ROOT, '..', 'corpus', '0xdf-htb')
  : path.resolve(ROOT, '..', '0xdf-offsec-complete-2026-08-20');

// ---- De-inflation of multi-purpose primitives for the enumeration gap table (Stage 2 cleanup).
const SMB_LAUNCH = /Try "help" to get a list of possible commands|Anonymous login successful|session setup failed|tree connect failed|Impacket v[\d.]|Type help for list of commands|CCache file is not found|Reconnecting with SMB1|Server requested encryption|protocol negotiation failed|NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|Enter\s+\S+\s+password:/i;
const SMB_LISTING = /^\s*\.{1,2}\s+D|\b[DAHNRS]+\s+\d+\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun)|\bblocks of size\b|\bSharename\b|\bDisk\b|\bIPC\b/im;
const SMB_REPL_XFER = /^(?:smbclient\s+)?(put|mput|get|mget|cd|lcd|mkdir|rmdir|rm|del|rename|!|q|quit|exit|recurse|prompt|mask)\b/i;
const CURL_XFER_CMD = /(^|\s)-[oO]\b|--output\b|--remote-name\b|>\s*[^\s|>&]+\s*$/;
const CURL_XFER_OUT = /%\s*Total\s+%\s*Received|\bDload\s+Upload\b|Saving to:/i;
const CURL_PS_FAIL = /\bcurl\s*:\s|CategoryInfo|FullyQualifiedErrorId|Invoke-WebRequest\s*:|is not recognized as|could not be resolved|positional parameter|ParameterBindingException/i;
const WEB_ENUM_SHAPE = /HTTP\/\d|<!DOCTYPE|<html|<head\b|<title|<body|<form|<a\s+href|Server:\s|Content-Type:\s|Set-Cookie:|X-Powered-By:/i;
const WEB_FUZZ_TOOLS = new Set(['ffuf', 'gobuster', 'feroxbuster', 'dirb', 'wfuzz']);
const WEB_FUZZ_HIT = /\[Status:\s*\d{3}|\(Status:\s*\d{3}\)|\bFound:\s|\b\d{3}\s+(?:(?:GET|POST|HEAD)\s+)?\d+l\s+\d+w|\b==>\s+DIRECTORY:|^\s*\+\s+https?:\/\/|^\s*000\d+\s*:\s*\d{3}\b/im;
const DB_TOOLS = new Set(['mysql', 'mssql', 'postgres', 'sqlite']);
const DB_MUTATION_OR_META_CMD = /\b(insert\s+into|update\s+\S+\s+set|delete\s+from|create\s+(?:table|database|user|function)|drop\s+|alter\s+|use\s+\S+|describe\s+|desc\s+|show\s+(?:columns|tables|variables|grants|status)|sp_configure|reconfigure|xp_dirtree|exec\s+master)\b|^\s*\\[dclq]\b/i;
const DB_EMPTY_OR_ACK_OUT = /^(?:\s*(?:Query OK,\s*\d+\s*rows?\s*affected|Database changed|Empty set|0 rows in set|\(\d+\s*rows?\s*affected\)|Records:\s*\d+\s+Duplicates:\s*\d+\s+Warnings:\s*\d+|Table\s+Op\s+Msg_type\s+Msg_text)[^\r\n]*\r?\n?)+\s*$/i;

function rankingLabel(tool, u, didMint) {
  if (didMint) return tool;
  const out = u.output || '';
  const cmd = u.command || '';
  if (tool === 'smbclient') {
    if (u.kind === 'repl') {
      if (SMB_REPL_XFER.test(cmd)) return 'smbclient-xfer';
      const nonDotRows = (out.match(/^\s+(?!\.{1,2}\s+D\b)\S.*?\s+[DAHSRNCETI]+\s+\d+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)/gim) || []);
      if (/\bblocks of size\b/i.test(out) && nonDotRows.length === 0) return 'smbclient-empty';
      return tool;
    }
    if (/-L\b/.test(cmd) || /\s-c\b|--command/.test(cmd)) return tool;
    if (SMB_LAUNCH.test(out) && !SMB_LISTING.test(out)) return 'smbclient-launch';
    return tool;
  }
  if (tool === 'curl') {
    if (CURL_XFER_CMD.test(cmd) || CURL_XFER_OUT.test(out)) return 'curl-xfer';
    if (CURL_PS_FAIL.test(out)) return 'curl-fail';
    if (!WEB_ENUM_SHAPE.test(out)) return 'curl-read';
    return tool;
  }
  if (WEB_FUZZ_TOOLS.has(tool)) {
    if (!WEB_FUZZ_HIT.test(out)) return tool + '-empty';
  }
  if (DB_TOOLS.has(tool)) {
    if (DB_MUTATION_OR_META_CMD.test(cmd) || DB_EMPTY_OR_ACK_OUT.test(out)) return tool + '-ack';
    if (!/\b(?:admin|root|hash|pass|pwd|secret|token|key|flag|version|xp_cmdshell|\$[1256yabPASH]+\$|0x[0-9a-f]{32}|[0-9a-f]{32})\b/i.test(out)) return tool + '-app-rows';
  }
  if (tool === 'GetNPUsers' && /No entries found!|doesn't have UF_DONT_REQUIRE_PREAUTH set/i.test(out) && !/\$krb5asrep\$/i.test(out)) return 'GetNPUsers-none';
  if (tool === 'GetUserSPNs' && /No entries found!/i.test(out) && !/\$krb5tgs\$/i.test(out)) return 'GetUserSPNs-none';
  if (tool === 'certipy' && (/Found no vulnerable certificate templates/i.test(out) || (!/Template Name|Got hash for|Saved credential cache|Successfully|ESC\d/i.test(out)))) return 'certipy-none';
  if (tool === 'ldapsearch' && /# numResponses:\s*1\b/i.test(out) && !/^dn:/im.test(out)) return 'ldapsearch-empty';
  if (tool === 'sudo-l' && /may not run sudo|a password is required|\[sudo\] password for|1 incorrect password attempt/i.test(out) && !/may run the following/i.test(out)) return 'sudo-l-denied';
  if ((tool === 'john' || tool === 'hashcat') && (/0 password hashes cracked|No password hashes loaded|No hashes loaded|Usage:|--help|\bExhausted\b/i.test(out) || /--stdout\b/i.test(cmd))) return tool + '-util';
  if (tool === 'nmap' && /0 hosts up|All \d+ scanned ports on .* are (?:closed|filtered|in ignored states)/i.test(out) && !/^\d+\/(?:tcp|udp)\s+open\b/im.test(out)) return 'nmap-empty';
  return tool;
}

const CUES = {
  loot: /\b(password|passwd|cred(ential)?s?|hash(es)?|id_rsa|private key|ssh key|flag|user\.txt|root\.txt|local\.txt|proof\.txt|secret|api[_ ]?key|token|passphrase)\b|\b(log ?in|logs in|gives us|reveals?|leak)\b/i,
  'state-change': /\b(shell|foothold|reverse shell|meterpreter|logged in|log in as|access as|we are now|we're now|got a shell|as root|as system|as administrator|on the box|on the host|on the target|user on|runs as|execution as)\b/i,
  outcome: /\b(works?|worked|successful|success|fail(s|ed)?|doesn'?t work|does not work|denied|refused|download(ed)?|upload(ed)?|transfer(red)?|timed out|didn'?t work)\b/i
};

function cueFires(axis, prose) {
  const re = CUES[axis];
  return re ? re.test(prose) : false;
}

function defaultReportPaths(corpusRoot, isDefaultCorpus) {
  const reportsDir = path.resolve(__dirname, 'reports');
  if (isDefaultCorpus) {
    return {
      reportPath: path.join(reportsDir, '0xdf-blindspots.json'),
      axisReportPath: path.join(reportsDir, '0xdf-axes.json')
    };
  }
  const tag = path.basename(corpusRoot).replace(/[^a-zA-Z0-9_-]+/g, '-').toLowerCase() || 'corpus';
  return {
    reportPath: path.join(reportsDir, tag + '-blindspots.json'),
    axisReportPath: path.join(reportsDir, tag + '-axes.json')
  };
}

function runHarvest(opts) {
  opts = opts || {};
  const rawCorpusDir = opts.corpusDir
    ? path.resolve(opts.corpusDir)
    : (process.env.OBOL_CORPUS_DIR ? path.resolve(process.env.OBOL_CORPUS_DIR) : DEFAULT_CORPUS_DIR);
  const isDefaultCorpus = path.resolve(rawCorpusDir) === path.resolve(DEFAULT_CORPUS_DIR);
  const { corpusRoot, walkthroughsDir } = resolveCorpusWalkthroughsDir(rawCorpusDir);

  if (!fs.existsSync(walkthroughsDir)) {
    const err = new Error('harvest-markdown: corpus walkthroughs directory not found at ' + walkthroughsDir);
    err.code = 'CORPUS_NOT_FOUND';
    throw err;
  }

  const OBOL = opts.OBOL || createSandbox();
  const slugFilter = Array.isArray(opts.slugs) && opts.slugs.length
    ? new Set(opts.slugs.map(s => String(s).trim().replace(/\.md$/i, '').toLowerCase()).filter(Boolean))
    : null;

  let files = fs.readdirSync(walkthroughsDir)
    .filter(f => f.toLowerCase().endsWith('.md'))
    .sort((a, b) => a.localeCompare(b));

  if (slugFilter) {
    files = files.filter(f => slugFilter.has(f.slice(0, -3).toLowerCase()));
  }
  if (typeof opts.limit === 'number' && opts.limit > 0) {
    files = files.slice(0, opts.limit);
  }

  const walkEntries = files.map(f => ({
    file: f,
    slug: f.slice(0, -3),
    fullPath: path.join(walkthroughsDir, f),
    isAlternate: false
  }));

  if (opts.includeAlternates) {
    for (const f of files) {
      const alts = discoverAlternates(corpusRoot, f.slice(0, -3));
      for (const alt of alts) {
        walkEntries.push({
          file: 'alternates/' + alt.file,
          slug: alt.slug,
          fullPath: alt.path,
          isAlternate: true,
          author: alt.author
        });
      }
    }
  }

  const perTool = Object.create(null);
  function bump(t) {
    if (!perTool[t]) {
      perTool[t] = {
        units: 0,
        withOutput: 0,
        emptyOrShort: 0,
        minted: 0,
        blind: 0,
        kinds: Object.create(null),
        tiers: { tier1: 0, tier2_shape: 0, tier3_inference: 0 },
        outcomes: Object.create(null)
      };
    }
    return perTool[t];
  }

  const axes = {};
  for (const a of ['enumeration', 'state-change', 'loot', 'outcome', 'none', 'other']) {
    axes[a] = {
      units: 0,
      withOutput: 0,
      emptyOrShort: 0,
      minted: 0,
      proseMaterial: 0,
      opportunities: 0,
      outcomes: Object.create(null),
      samples: []
    };
  }

  const outcomeDistribution = Object.create(null);
  const negativeOrEmptyOutcomes = Object.create(null);
  const tierFactsTotal = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  const tierDominantUnits = { tier1: 0, tier2_shape: 0, tier3_inference: 0 };
  let rescuedByTier2OrTier3 = 0;

  let totalBlocks = 0;
  let noPrompt = 0;
  let totalUnits = 0;
  let noOutput = 0;
  let withOutput = 0;
  let minted = 0;
  let blind = 0;
  let parserErrors = 0;
  let ocrSplicedTurns = 0;
  let alternatesAvailable = 0;

  for (const entry of walkEntries) {
    if (!entry.isAlternate) {
      alternatesAvailable += discoverAlternates(corpusRoot, entry.slug).length;
    }
    const md = fs.readFileSync(entry.fullPath, 'utf8');
    const extracted = extractWalkthroughTurns(md, {
      corpusDir: corpusRoot,
      slug: entry.isAlternate ? '' : entry.slug
    });

    totalBlocks += extracted.blocks.length;
    for (const b of extracted.blocks) {
      const hasPromptTurn = extracted.turns.some(t => t.blockIndex === extracted.blocks.indexOf(b) && t.hadPrompt);
      if (!hasPromptTurn) noPrompt++;
    }
    ocrSplicedTurns += extracted.ocrSplicedCount;

    for (const u of extracted.turns) {
      totalUnits++;
      const toolLabel = detectTool(u);
      const axis = classifyAxis(u, toolLabel);
      const A = axes[axis];
      A.units++;

      const nonWsLen = (u.output || '').replace(/\s/g, '').length;
      const hasSubstantialOut = nonWsLen >= 20
        || /^\s*(?:\d{1,3}\.){3}\d{1,3}\s*$/.test(u.output || '')
        || (u.source === 'ocr-sidecar' && nonWsLen > 0);

      let probed = null;
      try {
        probed = probeBlockStateless(OBOL, {
          actionId: '',
          command: u.command,
          stdout: u.output,
          promptLine: u.promptLine || '',
          source: u.command || entry.file,
          domain: ''
        });
      } catch (_e) {
        parserErrors++;
        probed = {
          facts: [],
          diagnostics: [],
          supported_kinds: [],
          refuted_kinds: [],
          tier_attribution: { counts: { tier1: 0, tier2_shape: 0, tier3_inference: 0 }, by_kind: {}, dominant_tier: null },
          outcome: { kind: 'parser-error', conclusive: false }
        };
      }

      const facts = probed.facts || [];
      const didMint = facts.length > 0;
      const outKind = (probed.outcome && probed.outcome.kind) || 'unknown';
      outcomeDistribution[outKind] = (outcomeDistribution[outKind] || 0) + 1;
      A.outcomes[outKind] = (A.outcomes[outKind] || 0) + 1;

      const tCounts = probed.tier_attribution.counts;
      tierFactsTotal.tier1 += tCounts.tier1 || 0;
      tierFactsTotal.tier2_shape += tCounts.tier2_shape || 0;
      tierFactsTotal.tier3_inference += tCounts.tier3_inference || 0;
      if (probed.tier_attribution.dominant_tier) {
        tierDominantUnits[probed.tier_attribution.dominant_tier]++;
      }
      if ((tCounts.tier1 || 0) === 0 && ((tCounts.tier2_shape || 0) + (tCounts.tier3_inference || 0)) > 0) {
        rescuedByTier2OrTier3++;
      }

      // Short / empty / negative turns are graded through outcomes.classify instead of discarded!
      if (!hasSubstantialOut && !didMint) {
        noOutput++;
        A.emptyOrShort++;
        negativeOrEmptyOutcomes[outKind] = (negativeOrEmptyOutcomes[outKind] || 0) + 1;
        const baseRec = bump(toolLabel);
        baseRec.units++;
        baseRec.emptyOrShort++;
        baseRec.outcomes[outKind] = (baseRec.outcomes[outKind] || 0) + 1;
        continue;
      }

      if (!didMint) {
        negativeOrEmptyOutcomes[outKind] = (negativeOrEmptyOutcomes[outKind] || 0) + 1;
      }

      A.withOutput++;
      const rLabel = rankingLabel(toolLabel, u, didMint);
      const rec = bump(rLabel);
      rec.units++;
      rec.withOutput++;
      rec.outcomes[outKind] = (rec.outcomes[outKind] || 0) + 1;
      withOutput++;

      if (didMint) {
        rec.minted++;
        minted++;
        A.minted++;
        rec.tiers.tier1 += tCounts.tier1 || 0;
        rec.tiers.tier2_shape += tCounts.tier2_shape || 0;
        rec.tiers.tier3_inference += tCounts.tier3_inference || 0;
        for (const f of facts) {
          rec.kinds[f.kind] = (rec.kinds[f.kind] || 0) + 1;
        }
      } else {
        rec.blind++;
        blind++;
      }

      const prose = ((u.lead || '') + ' ' + (u.follow || '')).trim();
      if (axis === 'state-change' || axis === 'loot' || axis === 'outcome') {
        const material = cueFires(axis, prose);
        if (material) A.proseMaterial++;
        if (material && !didMint) {
          A.opportunities++;
          if (A.samples.length < 12) {
            A.samples.push({
              file: entry.file,
              command: (u.command || '').slice(0, 90),
              outcome: outKind,
              outputHead: (u.output || '').split('\n').filter(l => l.trim()).slice(0, 4).join(' | ').slice(0, 220),
              prose: prose.slice(0, 240)
            });
          }
        }
      }
    }
  }

  const toolRows = Object.keys(perTool).map(t => {
    const r = perTool[t];
    return {
      tool: t,
      factBearing: FACT_BEARING.has(t),
      units: r.units,
      emptyOrShort: r.emptyOrShort,
      withOutput: r.withOutput,
      minted: r.minted,
      blind: r.blind,
      blindRate: r.withOutput ? +(r.blind / r.withOutput).toFixed(2) : 0,
      tiers: r.tiers,
      outcomes: r.outcomes
    };
  }).sort((a, b) => b.blind - a.blind);

  const actionable = toolRows.filter(r => r.factBearing);
  const act = actionable.reduce(
    (a, r) => { a.withOutput += r.withOutput; a.minted += r.minted; a.blind += r.blind; return a; },
    { withOutput: 0, minted: 0, blind: 0 }
  );

  const defaults = defaultReportPaths(corpusRoot, isDefaultCorpus);
  const reportPath = opts.out ? path.resolve(opts.out) : defaults.reportPath;
  const axisReportPath = opts.axesOut ? path.resolve(opts.axesOut) : defaults.axisReportPath;

  const summaryReport = {
    generated_at: new Date().toISOString(),
    corpus_dir: corpusRoot,
    walkthroughs: files.length,
    walkthroughs_scanned_with_alternates: walkEntries.length,
    alternates_discovered: alternatesAvailable,
    ocr_spliced_turns: ocrSplicedTurns,
    total_blocks: totalBlocks,
    unprompted_blocks: noPrompt,
    total_units: totalUnits,
    empty_or_short_units_graded: noOutput,
    units_with_output: withOutput,
    minted: minted,
    blind: blind,
    parser_errors: parserErrors,
    actionable: { units: act.withOutput, minted: act.minted, blind: act.blind },
    tier_attribution: {
      facts_by_tier: tierFactsTotal,
      units_by_dominant_tier: tierDominantUnits,
      units_rescued_by_tier2_or_tier3: rescuedByTier2OrTier3
    },
    outcome_distribution: outcomeDistribution,
    negative_or_empty_outcomes: negativeOrEmptyOutcomes,
    per_tool: toolRows
  };

  const axisReport = {
    generated_at: summaryReport.generated_at,
    corpus_dir: corpusRoot,
    note: 'opportunities = prose cue fired AND OBOL minted nothing; candidates for human review',
    tier_attribution: summaryReport.tier_attribution,
    outcome_distribution: outcomeDistribution,
    axes: axes
  };

  if (opts.writeReports !== false) {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.mkdirSync(path.dirname(axisReportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(summaryReport, null, 2));
    fs.writeFileSync(axisReportPath, JSON.stringify(axisReport, null, 2));
  }

  return {
    reportPath: reportPath,
    axisReportPath: axisReportPath,
    report: summaryReport,
    axisReport: axisReport
  };
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  function flag(name) { return argv.includes('--' + name); }
  function opt(name, def) { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; }

  const corpusDir = opt('corpus-dir', '');
  const slugsRaw = opt('slugs', '');
  const limitRaw = opt('limit', '');
  const outPath = opt('out', '');
  const axesOutPath = opt('axes-out', '');
  const includeAlternates = flag('include-alternates');

  let res;
  try {
    res = runHarvest({
      corpusDir: corpusDir || undefined,
      slugs: slugsRaw ? slugsRaw.split(',') : undefined,
      limit: limitRaw ? parseInt(limitRaw, 10) : undefined,
      out: outPath || undefined,
      axesOut: axesOutPath || undefined,
      includeAlternates: includeAlternates
    });
  } catch (e) {
    if (e && e.code === 'CORPUS_NOT_FOUND') {
      console.error(e.message);
      process.exit(2);
    }
    throw e;
  }

  const r = res.report;
  const axes = res.axisReport.axes;
  console.log(
    'Walkthroughs ' + r.walkthroughs +
    ' (alternates discovered ' + r.alternates_discovered + ', ocr turns ' + r.ocr_spliced_turns + ')' +
    ' | terminal blocks ' + r.total_blocks + ' (unprompted ' + r.unprompted_blocks + ')' +
    ' | command units ' + r.total_units + ' (empty/short graded ' + r.empty_or_short_units_graded + ')' +
    ' | with output ' + r.units_with_output
  );
  console.log(
    'Overall: minted ' + r.minted + ', blind ' + r.blind +
    ' | Enumeration actionable: ' + r.actionable.minted + ' minted / ' + r.actionable.blind + ' blind of ' + r.actionable.units
  );
  console.log(
    'Tier attribution (facts): tier1=' + r.tier_attribution.facts_by_tier.tier1 +
    ', tier2_shape=' + r.tier_attribution.facts_by_tier.tier2_shape +
    ', tier3_inference=' + r.tier_attribution.facts_by_tier.tier3_inference +
    ' (units rescued by Tier 2/3: ' + r.tier_attribution.units_rescued_by_tier2_or_tier3 + ')'
  );
  console.log('Outcome distribution: ' + JSON.stringify(r.outcome_distribution) + '\n');
  console.log('Per-axis (units / withOutput / OBOL-minted / prose-material / OPPORTUNITIES):');
  for (const a of Object.keys(axes)) {
    const x = axes[a];
    console.log(
      '  ' + a.padEnd(14) +
      String(x.units).padStart(6) +
      String(x.withOutput).padStart(8) +
      String(x.minted).padStart(8) +
      String(x.proseMaterial).padStart(9) +
      String(x.opportunities).padStart(8)
    );
  }
  for (const a of ['state-change', 'loot', 'outcome']) {
    console.log('\n=== ' + a + ' opportunity samples (prose said it mattered, OBOL minted nothing) ===');
    for (const s of axes[a].samples.slice(0, 5)) {
      console.log('  cmd : ' + s.command + ' [outcome=' + s.outcome + ']');
      console.log('  out : ' + s.outputHead);
      console.log('  why : ' + s.prose + '\n');
    }
  }
  console.log('Reports: ' + res.reportPath + '  and  ' + res.axisReportPath);
}

module.exports = {
  rankingLabel: rankingLabel,
  cueFires: cueFires,
  runHarvest: runHarvest
};
