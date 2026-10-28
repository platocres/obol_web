# Corpus Mining: Parser And System Hardening Program

> Canonical reference for OBOL's corpus-driven hardening effort. If you (human or model)
> are asked to improve parsing, fact-minting, fact-handling, failure-doctoring, commands,
> moves, or ordering from real-world data, read this first. Summarized in
> [OPEN_ITEMS.md](../OPEN_ITEMS.md) Pillar 5, which points back here.
>
> **Workspace:** this program lives only in the `qa` web repo (`tools/corpus/`,
> `tests/corpus/` - where `tests/corpus/0xdf-oscp/` is a local offline corpus directory not tracked in git - and this doc). It never ships to `prod` and never runs at runtime.

---

## 1. The Point Of It All

OBOL's entire value rests on one hinge: a user pastes real terminal output and a parser
turns it into the right fact. Everything downstream (ranked moves, blockers, findings, the
report) is only as good as that mint. Today our parsers are hardened against our own
fixtures: outputs we imagined or captured ourselves. The real gap is the distance between
the output we expected and the output the world actually produces: different tool versions,
odd flags, wrapped lines, truncation, partial failures, and the long tail of exceptions we
never thought to write a fixture for.

This program closes that gap by collecting a broad, diverse corpus of real tool output and
real methodology, measuring where OBOL fails to parse or mis-handles what it parsed, and
fixing those gaps. It will never be perfect. The goal is to get much closer to always
catching the nuance and handling it correctly than we are now.

The system is holistic: if one part is weak the whole chain can be weak. The weakest link
is the parsers, so they lead. But missing a command, tool, or move is rarely a deal-killer
in a lab, so move work is deliberately deferred and never allowed to crowd out parser work.

## 2. Scope And Non-Goals

- **Build-time only.** Collection and analysis happen offline, as a dev activity. Using a
  model to read screenshots or triage a corpus at build time does not touch OBOL's
  no-runtime-LLM, exam-legal contract. The shipped output is always deterministic parser
  code plus regression fixtures, human-reviewed.
- **qa only.** Pipelines in `tools/corpus/`, local offline corpus files in `tests/corpus/0xdf-oscp/` (not tracked in git), shipped corpus-free regression suites in `tests/engine/*-smoke.js`, and this doc in
  `qa/docs/`. Nothing here is mirrored to `prod`.
- **Priority order is fixed:** parsers and fact-handling first; commands, moves, and
  ordering are captured but banked, acted on last (they feed Pillar 4.1).
- **This is not a move-adding sprint.** A new move is legitimate only downstream of a
  newly reliable fact (Stage 6), never as the headline.

## 3. Guiding Principles

1. **Mine once, extract everything, analyze many.** The expensive step (reading an asset,
   above all a screenshot) is decoupled from any single purpose. We extract into a rich,
   durable record, then run many cheap analyses over it. We do not repeat the mistake of
   the first 0xdf pass, which took only moves off assets that also held parser and failure
   value.
2. **OBOL's own engine is the oracle.** The engine is pure Node, so we run the real
   `OBOL` parser (`parseActionOutput`) over the corpus and diff against ground truth. We do
   not spend model tokens grading parser correctness; that is deterministic.
3. **Cheapest source that yields the need wins.** Walkthroughs (and their vision tokens)
   are reserved for the two things only they have: real-world output *variance* and
   methodology *flow*. Everything else has a cleaner, structured, often token-free source
   (Section 5).
4. **Full Contextual Value (The Whole-Asset Rule).** For any asset we touch (0xdf, a GitHub
   writeup repo that mixes code blocks and screenshots, a forum thread, anything) we do not
   call it done until we have taken every axis of value it offers. Code blocks are the
   priority axis, but screenshots in the same asset carry context (flow, ordering,
   interpretation, GUI state, the failure the author hit) that we must also capture. We may
   process an asset in stages, but we never abandon it half-mined. Do not miss the forest
   for the trees.
5. **Screenshots are leads and context, not verbatim fixtures.** OCR (via a build-time
   vision model) extracts both the output and the surrounding methodology. When a screenshot
   surfaces a new output shape, we do not commit the noisy OCR text as the fixture. The
   screenshot is the lead; the committed fixture comes from a clean reproduction (re-running
   the tool, or a human-corrected transcription checked against the known format), tagged
   with provenance and tool version. OCR noise never silently enters the test net.
6. **Human gate, and version discipline.** No fixture or parser branch lands without human
   review. Every corpus entry carries a source and, where visible, a tool version. Respect
   the upper-bound version guards (see TASK-03) so modern patched banners do not reintroduce
   legacy exploit promotions.
7. **Copyright boundary.** The corpus is a private oracle for output shapes and functional
   commands, both of which are fair to derive from. We never transplant anyone's prose,
   scenario structure, or lab narrative into field notes or docs. For anything OBOL already
   teaches, the coach is the help and an external link is only a citation.
8. **Log it or it did not happen.** Every mining action is recorded in the provenance ledger,
   [CORPUS-LEDGER.md](CORPUS-LEDGER.md), in the same change that does the work: what was mined,
   how thoroughly (which axes), and what was derived. Updating the ledger is part of the
   definition of done for every stage. Before mining a source, an agent reads the ledger and
   does not re-mine an axis already marked done. This is how we stop redoing work between chats
   and between agents, on any platform. The ledger is pointed to from `AGENTS.md` so agents of
   any platform find it.

## 4. The Extraction Schema (One Pass, Take Everything)

Because re-mining wastes the asset, every asset we read emits one structured record. The
record captures every axis of value even though parsers are the priority consumer. This
schema is the enforcement mechanism for the Whole-Asset Rule.

- `source`: url or repo path, author, retrieval date.
- `asset`: content hash (the dedup key), type (`code_block` | `asciinema` | `screenshot` |
  `tool_fixture` | `source_strings` | `forum_thread`), fidelity (`text` | `ocr`).
- `context`: box or scenario, OS family, phase, tool versions where visible.
- `output_blocks[]`: `{ command_shown, tool, raw_output, truncated, fidelity }`.
- `facts_implied[]`: what the author concluded from an output block. This is the ground
  truth the parser should mint.
- `failures[]`: error or negative-output strings and what they meant (permission denied,
  account lockout, timeout, connection refused, Kerberos clock skew, and so on). Feeds
  `FIELD_DOCTORS` and the blockers parser.
- `flow[]`: the ordered sequence of moves and the command combinations inside each move.
  Banked for the move/ordering audit; not acted on early.
- `notes`: anything else of value, so nothing is lost before the asset is marked done.

This record is locked as a machine-checkable contract in `tools/corpus/extraction-schema.js` (Stage 1):
`validateRecord()` enforces the field set, the `asset.type` / `fidelity` enums, the dedup key
(`contentHash`, sha256 over CRLF-normalized text), the provenance floor (source url + retrieval date), the
output-block shape, and the Whole-Asset Rule (at least one axis present). `validateLabelsFile()` enforces the
facts-axis label sub-contract, and `buildKindVocabulary()` validates every referenced fact kind against the
live engine vocabulary (the union of `PARSER_SIGNATURES` emits, exact or prefix-wildcard, plus environmental
facts, mirroring `assets/engine/decisionmap.js`). `tests/engine/corpus-extraction-schema-smoke.js` ratchets
all of it and validates the real label file (corpus-optional).

## 5. The Source Portfolio (Matched To Need)

0xdf is one entry, not "the corpus." Relying on a single source overfits to that source's
house conventions; confidence to stand up to scrutiny comes from independent sources
agreeing. Route each need to the cheapest source that yields it.

**Decision tree.**
- Need a correct output to fact example? Use structured, ground-truthed sources first.
- Need the full set of error strings a tool emits? Grep the tool's own source code. It is
  authoritative and costs zero model tokens.
- Need command or flag variants, or technique to command? Use structured command repos.
- Need real-world messiness (truncation, odd versions, wrapped lines)? Use writeups, but
  prefer GitHub-hosted markdown (fenced code is text) over blog screenshots.
- Need methodology flow, ordering, or how commands combine into a move? Use walkthroughs
  with vision. This is the one job that justifies the cost.

**Parsers (output to fact): cheap, ground-truthed, no vision.**
- Tool-shipped test fixtures and sample output in their own repos (nmap sample
  XML/grepable/text, projects with a `testdata/` dir).
- Other parser projects' test suites (Metasploit importers, Nessus/OpenVAS importers, SIEM
  grok/Logstash patterns). Their "output to expected parse" fixtures reveal formats we miss.
- Canonical format pages: the hashcat example-hashes wiki (every mode's exact format), tool
  READMEs and wikis (NetExec/CrackMapExec, Impacket examples, ffuf, feroxbuster).
- asciinema casts: raw terminal text, not pixels, searchable.
- Our own lab re-runs: highest fidelity, version-known, fully controlled. Narrow, so used to
  fill specific gaps the corpus flags, not for broad sweeps.

**Failures (for FIELD_DOCTORS and blockers): failure-dense, cheap.**
- Tool source-code error strings: authoritative and greppable.
- Issue trackers, Stack Overflow, r/oscp, r/hackthebox, NetSecFocus, where people paste the
  exact error with the fix in the same thread. Walkthroughs show the happy path; forums are
  concentrated breakage.

**Commands and moves: structured, machine-readable, no OCR.**
- GTFOBins and LOLBAS (YAML: abusable binaries plus exact commands).
- Atomic Red Team (YAML: ATT&CK technique to real executable command lines; maps to a
  taxonomy we already use via `attack-coverage.js`).
- HackTricks (text reference by service: what techniques exist per port).
- PayloadsAllTheThings (markdown payload and command catalog).
- tldr-pages, cheat.sh, man pages (example-command databases per tool).
- MITRE ATT&CK, Exploit-DB, Nuclei templates (service or version to exploit, for findings).

**Flow and ordering (walkthroughs only, vision): the expensive tier.**
- 0xdf (largely mined already), Hacking Articles, Rana Khalil, 0xrick, HTB official
  writeups, IppSec (use the show-notes and search index, not the video frames), and the
  large body of GitHub CTF-writeup repos (many are markdown with code blocks, so they land
  in the cheap text tier, not the vision tier).

## 6. Stages

Ordered so parsers and fact-handling lead and move work is deferred.

- **Stage 0: Salvage, Inventory, And Source Catalog.** Before collecting anything new, find
  what survived the prior 0xdf mine (raw screenshots, extracted text, a manifest, notes).
  Branch on the result: reusable text means re-analyze for near-zero tokens; only screenshots
  means re-run just the extraction step; nothing reusable means re-acquire with the right
  schema so it is the last time. Produce a corpus manifest keyed by content hash with
  provenance, and turn Section 5 into a concrete, checkable source catalog. Read-only, cheap.
- **Stage 1: Lock The Extraction Schema.** Finalize Section 4 as the record contract and the
  dedup/provenance rules.
- **Stage 2: Tier 0 Harvest, Structured And Text Sources.** Exhaust the cheap, ground-truthed
  sources first: tool fixtures, source-code error strings, canonical format pages, structured
  command repos. Builds the initial parser confusion matrix and command/move coverage for
  almost no tokens.
- **Stage 3: Tier 1 Harvest, Walkthrough And Screenshot Extraction.** The vision tier, run
  only to add the variance and flow Tier 0 cannot give. The Whole-Asset Rule governs here:
  every asset yields output, facts, failures, and flow before it is marked done, whether its
  value sits in code blocks, screenshots, or both.
- **Stage 4: Parser Confusion Matrix.** Run `parseActionOutput` over every `output_block` and
  bucket each as correct mint, miss, or wrong mint. **Order the work by leverage:**
  blind-block-count times tool-criticality, so a pull or a parser fix is prioritized by how much
  it helps the exact weak, high-value tools the data names, not by what is easiest. The first
  deterministic sweep already exists: `tools/corpus/harvest-markdown.js` writes
  `tools/corpus/reports/0xdf-blindspots.json` (minted versus blind per tool across the 194
  walkthroughs). That sweep is a BINARY signal (any mint vs none), which overcounts success: a
  block can mint an incidental fact and look not-blind while missing the fact that mattered. The
  fact-kind matrix now exists on top of it: `tools/corpus/facts-axis.js` grades each
  human-labeled block against a floor of expected kinds (and optional forbidden kinds), bucketing
  correct / miss / forbidden-hit. Ground truth is `tools/corpus/labels/0xdf-facts.json` (no
  verbatim output, Principle 7); the matrix is `tools/corpus/reports/0xdf-facts-matrix.json`. The
  first batch (8 blocks) grades at 100.0% recall with 0 forbidden hits: the single miss the first run
  surfaced (admirer's `curl .../credentials.txt` freeform credential block) was closed the same day by
  a Stage 5 parser fix (the websource `labeled_leak` extractor), taking the batch from 97.0% to 100%.
  Expanded the same day to 38 blocks / 101 expected facts across 15 parsers (netexec, smbclient, ftp,
  curl, ssh, feroxbuster, gobuster, mssqlclient, sqlmap, GetNPUsers, GetUserSPNs, ldapsearch, rpcclient,
  secretsdump, hashcat/john, sudo -l, evil-winrm, nmap), still 100.0% recall / 0 forbidden hits: the new
  labels were authored at the floor the parsers already meet, with heavy forbidden-kind guards (no
  foothold from a login banner, no credential from a scan or a failed bind, no admin from a non-Pwn3d
  logon) and several true-negative anchors (banner-only gobuster, pre-auth-required GetNPUsers, bad-bind
  ldapsearch, evil-winrm connect banner). A follow-up batch the same day then OPENED the backlog on
  purpose: it asserted a stricter floor on three ambiguous blocks the parsers did not yet handle (40 blocks
  / 104 expected facts, recall 97.1% / 101-of-104, still 0 forbidden hits), namely an ftp `ls` exposing
  backup.mdb that should mint `loot.files`, a curl HTTP 404 body and a proxychains curl 200 that should
  both mint `http.reachable`, each paired with guards (a DNS-failure curl true-negative anchors the
  reachability fix). Two Stage 5 fixes (2026-10-23) then closed all three: `_parse_http_metadata` mints
  `http.reachable` from a returned response body, and `_parse_ftp_output` mints `loot.files` from an FTP
  directory listing (IIS and Unix row shapes), guarded to the FTP control-channel context. Recall is back
  to 100.0% / 104-of-104, 0 forbidden hits; the backlog is empty. `--worksheet` lists unlabeled blocks
  with observed kinds prefilled so labeling is additive; `tests/engine/facts-axis-smoke.js` ratchets the
  result (forbidden_hits == 0 always; recall >= floor, lowered consciously from 1.0 to 0.97 to admit the
  backlog, raised to 0.99 by the http.reachable fix, then RAISED back to 1.0 by the ftp loot.files fix;
  MIN_LABELS initially 30 and subsequently ratcheted to `MIN_LABELS = 100` as `tools/corpus/labels/0xdf-facts.json` expanded to `102 blocks` and `259 expected facts` across 21 tool families at 100.0% recall and 0 forbidden hits) and is corpus-optional (skips cleanly when the local offline corpus `tests/corpus/0xdf-oscp/` or snapshot is absent, since raw corpus directories are not tracked in git).
- **Stage 5: Parser Hardening And Fixture Reproduction.** For each miss or wrong, reproduce a
  clean fixture (Principle 5), add it to the growing `tests/corpus/`, extend the parser
  branch, register any new fact kind in `data/parser-signatures.js` with a downstream consumer
  in `assets/engine/decisionmap.js`, run the gauntlet. Human-gated.
- **Stage 6: Fact-Handling Pass.** For each newly reliable fact, confirm a success has a
  downstream follow-up move and a failure has a doctor. Driven by `post-parse-audit.js`
  lenses (`missedGain`, `failureGap`, `reOffer`) against real data. Successes get follow-up
  commands or tools; failures get `FIELD_DOCTORS` cards that turn the failure into the next
  move.
- **Stage 7: Move And Ordering Audit.** The banked `flow` data becomes evidence for whether
  the move graph and its ordering are faithful to real practice. Deferred on purpose; feeds
  Pillar 4.1. We take this value during mining but do not spend it until parsers and
  fact-handling are where we want them.

## 7. Artifacts And Layout

- `E:\KaliFiles\obol\obol-site\corpus\`: the centralized local corpus root. Every pulled source
  lives here, one subfolder each, indexed by `CORPUS-LEDGER.md`. The agent performs each pull
  into this root and logs it in the ledger before mining. (Existing pulls predate the
  convention and still sit at their original paths; consolidation is a pending, path-sensitive
  step.)
- `qa/docs/CORPUS-MINING.md`: this doc. `qa/docs/CORPUS-LEDGER.md`: the provenance ledger and
  source backlog (pulled versus planned).
- `qa/tools/corpus/`: the pipeline (inventory, harvesters per source type, the vision
  extractor, the confusion-matrix runner).
- `qa/tests/corpus/` (specifically `tests/corpus/0xdf-oscp/`): local offline corpus directory not tracked in git; shipped corpus-free regression fixtures live in `qa/tests/engine/*-smoke.js`.
- The corpus manifest: content-hash dedup key, provenance, tool version, extraction record
  per asset.

## 8. Verification And Gates

Every change rejoins the existing gauntlet (see CLAUDE.md Section 2). A new parser branch
registers its fact kind in `data/parser-signatures.js`, has a consumer in
`assets/engine/decisionmap.js`, and keeps `gap-report.js` and `post-parse-audit.js` at zero.
House style holds in this doc and all outputs: no em or en dashes, Title Case for labels and
headings, no decorative emoji.

## 9. Stage 0 Findings (2026-10-22)

The prior 0xdf mine survived in full, and the result shapes everything that follows.

- **Raw corpus is complete and local: no re-fetch, no scraping, zero acquisition cost.**
  `E:\KaliFiles\obol\obol-site\0xdf-offsec-complete-2026-08-20\` (about 352 MB). 194
  walkthroughs, each saved as both HTML and Markdown in `walkthroughs/` (the Markdown
  preserves fenced code blocks, so it is Tier A text already on disk), plus per-box
  screenshots in `assets/<slug>/` with SHA-256 checksums and original URLs.
  `corpus-manifest.json` inventories all 194 (completed 194, failed 0). This is the fetched
  snapshot of `https://0xdf.gitlab.io/cheatsheets/offsec`.
- **Prior extraction took only the move/technique axis.** `ranked-walkthroughs.json`
  (refreshed 2026-10-11) classifies each box by `techniques[]`, OS, `isAD`, OSCP tier, score,
  and word count. That pass drove the current move set. No output-block or fact-level
  extraction was ever captured: exactly the single-axis mistake Principle 1 names.
- **Screenshot content: deep-audited and extracted (Stage 3, 2026-10-23).** `qa/Testing/batch*-images.json` are per-box
  screenshot filename *queues* (lists) with a stale `Testing\` path prefix; the images live at
  `../0xdf-offsec-complete-<date>/assets/<box>/`. A full 194-walkthrough structural context sweep (2396 content captures)
  and 75-image visual inspection across 63 boxes proved that while ~75% of captures are web GUI, 25.3% of inspected
  screenshots (38.0% of high-suspicion captures lacking an adjacent code block) carry unique terminal output, Jenkins
  Groovy/Pipeline scripts, webshell execution, or Burp Repeater payloads; 19 validated `fidelity: 'ocr'` records are
  locked in `qa/tools/corpus/labels/0xdf-screenshots-ocr.json` and `harvest-screenshots.js --candidates` isolates the
  382 high-signal no-adjacent-code captures.
- **The Stage 4 engine already exists, fed by hand-authored fixtures, not this corpus.**
  `qa/tools/verify-parser-corpus.js` runs the real parser over a manifest of cases and diffs
  observed facts against expected (supported/refuted/forbidden kinds, fact lineage): this is
  the confusion-matrix machinery, already built. `qa/tests/engine/legacy/corpus-smoke.js` is a
  golden-path ranking corpus; `qa/tools/verify-all-20-mined.js` asserts specific mined moves
  landed in packs. None of them reference the 0xdf corpus directory.

**What this means for the plan.** Acquisition (Stage 0) is done and local. All 194 Markdown
copies are Tier 0 text ready to harvest now (Stage 2) at near-zero token cost. Stage 4 does
not need building: we extend `verify-parser-corpus.js`'s manifest with cases derived from the
corpus instead of starting from scratch. The only expensive step is the vision pass over the
local screenshots (Stage 3), and because the Markdown already carries most output, that step
is second, not first, though the Whole-Asset Rule still requires each box's screenshots be
read before that box is marked done. The move/technique axis is already banked in
`ranked-walkthroughs.json`, giving Stage 7 a head start while it stays deferred.

## 10. Status

- **Stage 0: inventory complete** (2026-10-22). Prior corpus salvaged, source portfolio
  cataloged (Section 5). Findings above.
- **Stage 2: complete** (started 2026-10-22, completed 2026-10-23; Stages 0-7 complete). Output-axis sweep of the 194 local Markdown
  walkthroughs done and sharpened via `tools/corpus/harvest-markdown.js`: console blocks are
  segmented into command units on real prompts, each parsed on its own output, and blind is
  counted only over fact-bearing tools (command-only units, no-prompt dumps, and navigational
  or file-read output are excluded from THIS enumeration ranking, not from scope: see the axis
  correction below). Trustworthy result: 2153 fact-bearing units with output,
  70% mint, 30% blind (642 units); report in `tools/corpus/reports/0xdf-blindspots.json`.
  Method validated by mature parsers (nmap 1% blind, netexec 2%, secretsdump 5%). Confirmed real
  gaps: gobuster v2.0.1 old format (FIXED 2026-10-23, Stage 5 dispatch sniff; see below), dig
  A-records (FIXED 2026-10-23, Stage 5 dns.a_record; see below). Smbclient/curl classification
  inflation CORRECTED in the sweep (2026-10-23): `harvest-markdown.js` now de-inflates the two
  multi-purpose primitives with a `rankingLabel` step that keeps a minted unit as real coverage
  and moves only the BLIND launch/transfer/content residue into explicit non-fact-bearing buckets
  (`smbclient-launch`, `smbclient-xfer`, `curl-xfer`, `curl-fail`, `curl-read`), gated on content
  signatures not on mint status so a web-shaped curl miss or an `smbclient -L` share-list still
  counts. Effect: smbclient blind 110 -> 31, curl blind 105 -> 0 (both mint counts unchanged),
  actionable blind 537 -> 314, and the honest top gaps (mysql, feroxbuster, certipy, smbmap, mssql)
  surface. qa-only tooling (no engine edit, no stamp-assets); axis report untouched. Next: derive
  fixtures for the top actionable gaps.
- **Stage 4: fact-kind confusion matrix complete** (2026-10-23; expanded to 102 blocks, 259 expected facts, MIN_LABELS = 100). The binary blind-vs-mint sweep
  is now backed by a fact-kind matrix graded against human ground truth. `tools/corpus/facts-axis.js`
  loads the real engine, re-reads each labeled block's live output by stable id, and buckets minted
  kinds as correct / miss / forbidden-hit against a floor in `tools/corpus/labels/0xdf-facts.json`
  (no verbatim output, Principle 7). First batch: 8 blocks, 33 expected facts, 100.0% recall, 0
  forbidden hits. The one miss the first run surfaced (admirer's `curl .../credentials.txt` freeform
  credential block) was closed the same day in Stage 5: websource `_parse_labeled_creds` now mints a
  `labeled_leak` credential.candidate for a bracket-header + bare-user + bare-pass leak, guarded
  against non-credential sections, prose, and placeholder/boolean values
  (`tests/engine/labeled-leak-cred-smoke.js`). Expanded the same day to 38 blocks / 101 expected facts
  across 15 parsers, still 100.0% recall / 0 forbidden hits: authored at the floor the parsers already
  meet, carrying heavy forbidden-kind guards and true-negative anchors to widen false-positive coverage.
  A follow-up batch the same day then opened the backlog on purpose, asserting a stricter floor on three
  ambiguous blocks the parsers did not yet handle (40 blocks / 104 expected facts, recall 97.1% / 101-of-104,
  0 forbidden hits): ftp `ls` exposing backup.mdb should mint `loot.files` (`100754e619b9`), and a curl
  404 body (`23708bbeb1b8`) and a proxychains curl 200 (`e0c783a21aa5`) should both mint `http.reachable`,
  each with a guard (a DNS-failure curl true-negative, `f87b247fe3a8`). Two Stage 5 fixes then CLOSED all
  three: services.js `_parse_http_metadata` mints `http.reachable` from a returned response body (HTML or
  an "HTTP Error <code>" wrapper, guarded so a no-body transport failure stays unreachable;
  `tests/engine/http-reachable-body-smoke.js`), and services.js `_parse_ftp_output` mints `loot.files`
  from an FTP directory listing (Windows IIS and Unix `ls -l` row shapes, reached on an ftp command or FTP
  control codes and minting only inside that context; `tests/engine/ftp-listing-loot-smoke.js`). Recall is
  back to 100.0% / 104-of-104, 0 forbidden hits; the backlog is empty. Report:
  `tools/corpus/reports/0xdf-facts-matrix.json`. Labeling is additive via `--worksheet`; the matrix is
  held green by the corpus-optional `tests/engine/facts-axis-smoke.js` (forbidden_hits == 0 always;
  recall >= floor, lowered consciously 1.0 -> 0.97 to admit the backlog, raised to 0.99 by the
  http.reachable fix, then RAISED back to 1.0 by the ftp loot.files fix; MIN_LABELS initially 30, then ratcheted to `MIN_LABELS = 100` across `102 blocks` and `259 expected facts`). The parser fixes
  are shipped engine changes (qa re-stamped); the labels, matrix, and grader stay qa only.
- **Stage 6: first outcome-axis fix shipped** (2026-10-22). Failure-doctoring derived from the
  corpus: a certutil usage/arg error mints `blocker.certutil_usage` and surfaces
  `certutil-usage-doctor` (the correct -urlcache/-split/-f download and -encode/-decode transfer
  forms). Wired through `blockers.js`, `parser-signatures.js`, the shells pack, and `field-notes.js`,
  with a regression in `tests/engine/outcome-parsers-smoke.js`. Full gauntlet green and gating
  verified (surfaces only when the blocker is present). qa only, not synced to prod. Logged in
  CORPUS-LEDGER.md.
- **Signal axes (2026-10-22 correction).** "Blind" must be measured per axis, not with one
  fact-bearing flag. A command's output can carry: (1) enumeration facts (what the ranking above
  measures); (2) state-change facts (a shell obtained, a pivot, being on host X as user Y, which
  should change on-host suggestions); (3) loot-in-content (a cat or ls that reveals a key, flag,
  or config secret; low base rate, so a curated high-value pattern catalog, prose-confirmed, not
  arbitrary file parsing); (4) outcome (a suggested transfer or auth succeeded or failed, feeding
  success-advance and failure-doctoring); (5) none (cd, pwd, clear). The surrounding walkthrough
  prose is the ground-truth oracle for whether an output mattered, so axes 2 through 4 are
  measured against the prose before any scope decision. Guardrail: curated patterns, prose-
  confirmed materiality, and a human gate, so we never mint false facts from arbitrary content.
  MEASURED (2026-10-22): the harvester now tags each unit by axis and pulls the surrounding prose.
  state-change, loot, and outcome hold about 1200 prose-confirmed opportunities (539 / 601 / 70),
  rivaling the 598 enumeration blind spots. Clearest wins: flag-file reads, credential-file reads,
  and command-failure doctoring. Report: `tools/corpus/reports/0xdf-axes.json` (opportunity =
  prose cue fired and OBOL minted nothing; candidates for human review, since some state-change
  hits may already be covered by a move's own proof and the cues are broad).
- Stage 5: parser-hardening fixes shipped (2026-10-23). (a) The Stage 4 matrix surfaced a miss
  (admirer's freeform credential leak); reproduced corpus-free as a fixture
  (`tests/engine/labeled-leak-cred-smoke.js`), the websource parser gained `_parse_labeled_creds`
  (a `labeled_leak` credential.candidate). (b) The deliberate stricter-floor batch then opened two
  `http.reachable` misses (a PowerShell-wrapped curl 404 and a proxychains curl 200); services.js
  `_parse_http_metadata` gained a response-body reachability branch (HTML document or "HTTP Error
  <code>" wrapper), DNS/connection-failure guarded, reproduced corpus-free in
  `tests/engine/http-reachable-body-smoke.js`, closing both. (c) The last backlog miss (an ftp `ls`
  IIS listing exposing backup.mdb that should mint loot.files) was closed by a `_parse_ftp_output`
  directory-listing branch (Windows IIS and Unix `ls -l` rows, reached on an ftp command or FTP control
  codes, minting only inside that context), reproduced corpus-free in
  `tests/engine/ftp-listing-loot-smoke.js`. Recall is back to 100.0% and the floor raised to 1.0; the
  facts-axis backlog is empty. All are the intended Stage 4 -> Stage 5 loop (matrix finds a miss, a
  guarded parser branch closes it, recall ratchets up).
- Stage 5: gobuster dispatch fix shipped (2026-10-23). The highest-leverage named output-axis gap
  (gobuster, 42 blind units, blindRate 0.58) was a DISPATCH miss, not a regex miss: `_WEB_GOBUSTER_RE`
  already parsed `/path (Status: NNN)`, but when a found-path block was pasted WITHOUT the command
  line, the shape sniff in `assets/engine/parsers/index.js` required the modern `[Size: N]` suffix, so
  old gobuster v2.0.1 `(Status)`-only blocks fell through unparsed. Broadened the sniff to
  `[Found: ][http://host]/path (Status: NNN)` with zero or more trailing bracket groups, anchored to
  end-of-line (old, 3.x `[Size]`, and redirect `[--> url]` forms covered; mid-sentence prose excluded).
  No new fact kind (reuses `web.content_map`), so no parser-signatures or decisionmap change; gap-report
  stays at 0 orphans. Reproduced and locked corpus-free in `tests/engine/web-content-paths-smoke.js`
  (7 assertions). `dig` A-records remain the one open named output-axis gap.
- Stage 5: dig A-record fix shipped (2026-10-23). The other named output-axis gap (`dig` A-records):
  a plain forward lookup (dig/host/nslookup resolving one name to an address) is not a zone transfer,
  so `_parse_dns` never met the `dns.zone` >=2-record floor and minted nothing. Folding it into
  `dns.zone` would raise a false "Zone Transfer Permitted" medium finding, so this is a distinct output
  shape: added a new terminal kind `dns.a_record` {name, ip} minted for a single forward resolution
  (scoped to the resolved host), skipped when `dns.zone` fires or the name is already an
  `ad.dc_candidate` (no double receipt). Registered in `data/parser-signatures.js` (internal-dns emits)
  and the recon-dns move's `produces`; terminal via decisionmap's `dns.` class, so gap-report stays at
  0 orphans. Locked by `tests/engine/dns-a-record-smoke.js` (11 assertions, corpus-free). Remaining
  sub-gap: `dig +short` bare-IP output carries no name (it is only on the command line), so it still
  mints nothing; it is now the one tracked output sub-gap, and no named output-axis gap remains open.
- Stage 5: interactive db schema-enumeration fix shipped (2026-10-23). The next honest actionable gap
  after the de-inflation was mysql (39 blind, rate 0.74) and rpcclient (16 blind, rate 0.76). Measuring
  first showed most of the mysql/mssql/rpcclient blinds were a harvester-vs-product mismatch, not an engine
  gap: the product's `assets/ui/ingest.js` prepends the sub-shell tool token to a REPL command (`mysql>
  show tables;` -> command string `mysql show tables;`), which `parsers/index.js` dispatches on, but the
  harvester passed the bare REPL command so the sub-parser was never reached and real listings read as
  FALSE blinds. Fixed the harvester first (qa-only, no stamp): `tools/corpus/harvest-markdown.js` now mirrors
  the product via a `prefix` per REPL prompt and an idempotent `_applyPrefix` in `matchPrompt` (and loosened
  `SMB_REPL_XFER` to tolerate the prepended token), recovering about 10 false blinds. The real engine fix:
  the database parser's signature already DECLARED `db.databases`/`db.tables` (with a FRIENDLY label and the
  live `crack-identify` consumer) but the interactive path never produced them. `_parse_database_output` now
  mints them from a `show databases/schemas`/`show tables` run, reading both printed shapes (boxed ASCII grid
  and bare `mysql -e` newline list) via a new `_db_listing_names` helper, dropping header labels (`Database`,
  `Tables_in_<db>`) and status lines, and gated on an inventory verb AND a single-column shape so a
  describe/select grid, an empty set, and a `Query OK` acknowledgement mint nothing. No new fact kind, so no
  parser-signatures or decisionmap change. Locked corpus-free by `tests/engine/db-listing-parser-smoke.js`
  (15 assertions). Corpus effect (post harvester fix): mysql minted 22 -> 28, blind 31 -> 25; actionable
  aggregate blind 304 -> 298. database.js ships, so qa assets were re-stamped last; prod sync is by hand.
  Open follow-ups (honest, not built here): rpcclient's patterned residue is AD user/group/SID enumeration
  (`querygroup`/`querygroupmem`/`queryuser`, `lookupnames`/`lookupsids`) that could mint `ad.user`/`ad.group`
  facts (its `setuserinfo2 -> NT_STATUS_PASSWORD_RESTRICTION` units are failure-axis), and a mysql/mssql
  users-table `select` returning hash columns could widen into a `credential.candidate` dump.
- Stage 5: rpcclient AD SID/name resolution fix shipped (2026-10-23). The next honest actionable gap after
  the db-listing fix was rpcclient (15 blind, rate 0.71). Triage showed the residue is the raw interactive
  `rpcclient $>` resolution and detail shapes that nxc/enum4linux-ng never relabel into the `(SidTypeUser)` /
  `user:[x] rid:[y]` forms `_rid_usernames` already catches. Dispatch was NOT the gap: `parsers/index.js`
  already routes every `rpcclient` sub-command (and `lookupsid`) to `_parse_rid_user_list`; the function just
  never read these shapes. Added `_rpc_resolution(text)` in `directory.js`, which reads the four raw shapes:
  `lookupsids` (`<SID> DOMAIN\name (type)`, classified by SID_NAME_USE type: 1 = user, 2/4/5 = group),
  `lookupnames` (`<name> <SID> (Label: type)`, classified by the explicit label), `queryuser`
  (`User Name : <name>`), and `querygroup` (`Group Name : <name>`). Resolved users merge into the existing
  `ad.user_list` (the sprayable/roastable pivot, 5 live consumers: asrep-roast, password-spray,
  online-brute-ssh/ftp/rdp) and resolved groups into `ad.group_list`. `*unknown*` resolutions, non-user/-group
  SID classes, machine accounts (trailing `$`, dropped by `_valid_username(name, false)`), and
  `NT_STATUS_NONE_MAPPED` failures mint nothing. No new fact kind (both facts already declared at
  `data/parser-signatures.js`), so no parser-signatures or decisionmap change, and `gap-report` stays at
  `orphanParserFacts: 0`. Locked corpus-free by `tests/engine/rpc-resolution-parser-smoke.js` (14 assertions,
  incl. the machine-account / *unknown* / NONE_MAPPED guards and a no-regression merge of enumdomusers rows
  plus a lookupsids resolution). Corpus effect (fact-bearing rows): rpcclient minted 6 -> 12, blind 15 -> 9
  (blindRate 0.71 -> 0.43); actionable aggregate blind 298 -> 292. directory.js ships, so qa assets were
  re-stamped last; prod sync is by hand. Remaining rpcclient residue (honest, not built here): `querygroupmem`
  prints member RIDs with no names in the same unit (resolving them needs cross-unit correlation with a
  `queryuser`/`lookupsids` pass), the `setuserinfo2 -> NT_STATUS_PASSWORD_RESTRICTION` units are failure-axis,
  and the `enumprinters` comment password leak is rare loot.
- Stage 5: feroxbuster no-method content-discovery fix shipped (2026-10-23). The next honest actionable gap
  after the rpcclient fix was feroxbuster (36 blind, rate 0.41, the single largest fact-bearing blind pool).
  Triage showed neither dispatch nor the fact was the gap: `parsers/index.js` already routes `feroxbuster`
  commands to `_parse_web_content`, which mints the established `web.content_map`, and `_WEB_FEROX_RE` already
  existed. The miss was purely the regex shape: it required a method column (`\w+`) between the status code
  and the line count. Newer feroxbuster builds print one (`200  GET  6l  77w  3351c  URL`), but older/default
  output omits it (`301  9l  28w  313c  URL`), so result-bearing walkthroughs on the no-method format
  (fingerprint 36 rows, sense 34, writer 20, pikaboo 18, love 13, dynstr 11, and more) read as blind while the
  paths sat in plain view. The parsing walkthroughs (absolute, acute, aero) all happened to use the
  method-column format, which hid the gap. Fix: make the method optional and match it with `[A-Za-z]+` (not
  `\w+`) so, when absent, the optional group matches empty instead of swallowing the leading `9l` line count:
  `_WEB_FEROX_RE` in `common.js`, plus the same widening in the `index.js` text-shape dispatch fallback (so a
  bare result paste with no command line still routes). No new fact kind (`web.content_map`, 8 live downstream
  consumers), so no parser-signatures or decisionmap change, and `gap-report` stays at `orphanParserFacts: 0`.
  404 rows, the `[####] ... found:11 errors:0` scan progress bars, and a banner/config-only paste with no
  result rows all mint nothing (verified). Locked corpus-free by
  `tests/engine/feroxbuster-nomethod-parser-smoke.js` (9 assertions, incl. the 404-drop, 301-redirect-source,
  progress-bar-junk, and banner-only-mints-nothing guards, plus a no-regression GET-method merge). Corpus
  effect: feroxbuster minted 51 -> 80, blind 36 -> 7 (blindRate 0.41 -> 0.08, now level with gobuster);
  actionable aggregate blind 292 -> 263. common.js and index.js ship, so qa assets were re-stamped last; prod
  sync is by hand. The remaining 7 feroxbuster blinds are honest: all banner-only or 0xdf-snipped blocks
  (jail, jeeves, luanne, object, monitors, fulcrum's empty `-x asp,aspx` run) with no result rows to mint.
- Stage 6: fact-handling pass over the two Stage 5 facts (2026-10-23). Both were made reliable from
  NEW output shapes, so this pass confirms a success drives a downstream follow-up. `http.reachable`
  from a response body: 65 pack consumers, and the real ranker (`OBOL.pack.rankActions`) leads with
  `recon-web-triage` / `content-discovery`, the same web-enumeration chain the clean-nmap mint already
  drives (`tests/engine/linux-web-e2e-replay.js` Stage 1). `loot.files` from the ftp listing: 9 pack
  consumers, and for the listed `backup.mdb` the ranker leads with `access-db-export` and
  `ole-macro-analysis`, the correct Access-DB follow-up. `post-parse-audit.js --check` is green across
  all five lenses (`missedGain`, `probeRetire`, `reOffer`, `failureGap`, `leadOrder` all 0), and the
  non-reachable curl shapes (DNS failure, connection refused, timeout) correctly mint nothing, so there
  is no spurious lead and no failure-doctor gap. No fix was required; the downstream half is now locked
  by `tests/engine/stage6-fact-followup-smoke.js` (corpus-free). The mint half stays locked by
  `http-reachable-body-smoke.js` and `ftp-listing-loot-smoke.js`.
- Stage 7: move and ordering audit (2026-10-23). The banked `flow` data (194 ranked walkthroughs)
  gives an empirical precedence over the 11 coarse technique tags: every co-occurring pair is 100%
  consistent in direction, with the strong chains recon/web -> foothold -> privesc/pivot and, for AD,
  domain creds -> roasting -> DCSync. Coverage: all 11 tags map to shipped moves (no graph gap). Ordering:
  faithful, but enforced by eligibility GATES (`requires_all` / `requires_any`), not by phase labels. A
  coarse min-phase proxy flagged 8 "inversions" (pivoting tagged recon/enum but gated on `foothold.*` /
  `scan.local.*`; the cred-producing SQLi variant reading creds phase; potato/token reading enum), all
  false positives: the gates hold each move until its prerequisite fact exists. Proven dynamically through
  the real ranker (`OBOL.pack.rankActions`): a pre-foothold web state offers no pivoting / linux-privesc /
  potato move; a linux foothold unlocks linux-privesc and pivoting; a windows privilege token unlocks the
  potato path; domain creds offer roasting and BloodHound but NOT `dcsync` (which waits on `access.admin` /
  `ad.control_paths`), matching the empirical roast -> DCSync chain. No pack change required; locked by
  `tests/engine/stage7-flow-ordering-smoke.js` (corpus-free, hand-built fact states). Feeds Pillar 4.1.
- Stage 1: extraction-schema lock (2026-10-23). Section 4 (the one-record-per-asset contract) is now
  machine-checkable in `tools/corpus/extraction-schema.js`: the asset-record shape (type / fidelity enums,
  the sha256 dedup key, the provenance floor, the Whole-Asset Rule), the facts-axis label sub-contract, and
  a fact-kind vocabulary built from the live `PARSER_SIGNATURES` emits (exact / prefix / environmental,
  mirroring `decisionmap.js`). Locked by `tests/engine/corpus-extraction-schema-smoke.js` (corpus-free, plus
  a corpus-optional pass over the real label file). The vocabulary check immediately found drift: two
  `anubis.md` label cases guarded against `web.authenticated`, a kind no parser can mint (before Stage 1 a
  typo'd or dead kind silently read as a facts-axis miss instead of an error). The dead guard was removed
  from both cases; `credential.available` still carries the real "a GET / 404 is not a credential" guard, so
  facts-axis recall stays 1.0 / 0 forbidden hits (40/40 at Stage 1 lock, subsequently expanded to 102 blocks / 259 expected facts with `MIN_LABELS = 100`). Future Stage 2/3 harvest records must pass
  `validateRecord()` before an asset is marked done.
- Stage 3: vision tier built, deep-sampled across 63 boxes, and OCR-extracted (2026-10-23).
  `tools/corpus/harvest-screenshots.js` resolves the real image root, classifies every asset into a CONTENT
  CAPTURE or DECORATION, collapses png/webp pairs, scans all 194 Markdown walkthroughs via
  `scanWalkthroughImageContexts()` to attach structural adjacency metadata (`has_adjacent_code`,
  `section_code_blocks`, `surrounding_prose`) to each capture, and supports `--candidates` to filter the 382
  high-signal captures that have no adjacent code block. Visual inspection of 75 real `.png` screenshots across
  63 boxes (50 high-suspicion + 25 stratified random) found 19 captures (25.3% overall; 38.0% of high-suspicion)
  carrying unique terminal output, Jenkins Groovy/Pipeline RCE scripts, ASPX webshell commands, Burp Repeater
  requests/responses, or `neofetch` system info absent from the Markdown text. All 19 are captured as validated
  Stage 1 `fidelity: 'ocr'` records in `tools/corpus/labels/0xdf-screenshots-ocr.json` (plus `neofetch` /
  `hostnamectl` OS & kernel support in `assets/engine/parsers/host.js`), locked by
  `tests/engine/stage3-screenshot-harvest-smoke.js`.
- Stage 4, Stage 5, and Stage 6 completion sweep (2026-10-23):
  - Stage 4 `facts`-axis ground truth (`tools/corpus/labels/0xdf-facts.json`) expanded from 40 to 102 labeled
    blocks (259 expected facts across 21 tool families) at 100.0% recall (259/259) and 0 forbidden-kind hits,
    with `MIN_LABELS = 100` ratcheted in `tests/engine/facts-axis-smoke.js`.
  - Stage 5 & 6 triaged all 263 remaining actionable blind units and closed the recurring parser and blocker
    gaps across `dns.js` (`dig +short`), `directory.js` (`certipy req`/`ESC7`/`account read`, SMB compressed
    `Dc`/`Ac` + ADS + piped `-L` + `putting file`, `rpcclient` password reset + `querygroupmem` + piped `nxc`
    users, `bloodhound-python` completion without `--zip`), `database.js` (`$S$`, `pbkdf2_sha256$`,
    `master.sys.databases`, `db.admin`), `creds.js` (`$ansible$`, `$PEM$`, `.psafe3`, 96-hex NTLM, IPMI RAKP),
    `web.js` (`sqlmap` ASCII `[N tables]` grid and `FILE` privilege), `host.js` (`neofetch`/`hostnamectl`,
    Spanish `whoami /priv`), and `blockers.js` (`blocker.password_restriction` + 11 widened blocker patterns).
    Actionable enumeration coverage across the 194 walkthroughs reached 97.5% (1796 minted / 46 blind of 1842
    units), locked corpus-free by `tests/engine/stage5-corpus-remining-smoke.js`.
- All stages (Stage 0 through Stage 7) on the 0xdf OffSec snapshot are now complete.
