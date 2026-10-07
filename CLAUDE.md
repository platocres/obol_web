# Obol web

Read and follow [AGENTS.md](AGENTS.md), then [README.md](README.md) and
[docs/LOCAL-INHERITANCE-OVERHAUL.md](docs/LOCAL-INHERITANCE-OVERHAUL.md).

Obol web is the static-site edition of obol-local. The same contract applies to Claude and
any other coding agent. There are no separate, model-specific build instructions.

**House style:** no em dashes or en dashes anywhere (use commas, colons, or periods). Use proper
capitalization, and Title Case for UI labels, tabs, and section headings.

---

## Active build: Workbench and fact-driven utilities (in progress, PR #302)

**Plan of record.** If this chat is lost, resume from this section. Work on branch
`claude/obol-web-overhaul-local-59ttbx`. Commit frequently.

### Intention

Turn the Next Steps field notes from "one command plus a link" into a system that *answers* the
student's situation. obol already parses pasted tool output into facts; use those facts to hand the
exact, pre-filled next thing: the GTFOBins escape for the SUID binary they found, the hashcat mode
for the hash they hold, the reverse shell for their own lhost and lport, with the canonical source
one tap away. Add a global **Workbench** of client-side "borrowed back ends" (hash identifier,
reverse-shell builder, encoders or a mini CyberChef, GTFOBins browser, wordlist picker, JWT decoder)
that fill from the active engagement's credentials and parameters and also work standalone. The
audience is neurodivergent and disabled learners: clarity, continuity, and it-actually-works are
acceptance criteria, not polish.

### Non-negotiable boundaries (do not break)

- Static, browser-local, no backend, no execution, no telemetry (AGENTS.md). Everything is
  client-side JavaScript plus bundled data.
- **Pack commands stay the source of truth** (parity with obol-local; the decision map and the
  coach ranker derive from them). The Workbench and the resolver *enrich presentation* only. They
  never rewrite the move graph or change which move or command the coach ranks.
- **One store, one filler.** The Workbench is a view over `OBOL.store`, the fact ledger, and
  `OBOL.command.fillCommand`. No forked state.
- **Stay exam-legal.** OSCP is open-book (internet and notes allowed); it bans AI chatbots and
  LLMs, automated mass scanners, and sqlmap. obol is a deterministic reference and notes tool with
  no LLM, so it is on the right side of this. Keep it that way. The manual-SQLi builder is manual by
  design (the human runs every query).
- **Accessibility is acceptance.** Verify every surface with screenshots for readability and
  continuity; colour is never the sole signal; keyboard reachable; 11px font floor;
  `prefers-reduced-motion` honoured; works from 4K down to about 320px.
- **House style.** No em or en dashes. Title Case for tabs, labels, and headings.

### Owner caveats

- The reverse-shell builder must offer quick base64 encoding the way OffSec teaches for the OSCP,
  especially PowerShell `-EncodedCommand` (UTF-16LE, then base64). One click.
- Screenshot-verify everything for comprehension and continuity for this audience, and it must
  actually work: drive the real app headless and test it.
- Frequent commits so no work is lost.

### Verify each phase

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` ·
`node tools/gap-report.js --check` · `for t in tests/engine/*.js; do node "$t"; done` ·
`NODE_PATH=/opt/node-tools/node_modules node tests/browser-smoke.js` ·
`node tools/stamp-assets.js` (after any asset edit) · drive the app headless (0 console errors) ·
screenshot the changed surface and read it for sense.

### Phases (check off as completed)

- [x] **P0.** This plan in CLAUDE.md plus task tracking.
- [x] **P1.** Reference resolver engine (`fact -> exact, pre-filled knowledge`) plus the GTFOBins
  closed loop surfaced in Next Steps. Bundle GTFOBins data (GPL-3.0, attributed) as compact JSON.
- [x] **P2.** Add `lport` (and a shell-type preference) to engagement params, the context and
  parameter bar, and the command filler.
- [x] **P3.** **Workbench**: a new global section (neon glass, sub-tabs), credential and parameter
  aware, working standalone with no engagement. Tools: hash identifier, reverse-shell builder
  (including base64 and PowerShell `-EncodedCommand`), encoder or mini CyberChef (base64, url, hex,
  rot, IFS evasion), JWT decoder, wordlist picker, GTFOBins browser.
- [x] **P4.** Stack-aware wordlist picker wired to content discovery; "run all" for *independent*
  checks and "Build in Workbench" affordances on cards (presentation only; pack commands untouched).
- [x] **P5.** Manual-SQLi guided builder (manual, exam-legal; the parser reads each pasted result to
  fill the next query).
- [x] **P6.** "Explain This Output" (parser annotate mode: highlight the lines that mint facts, say
  what each proves in plain language, and what it does not prove).
- [x] **P7.** Finish the remaining field-note lanes: ad, windows, web_exploit_checks, database,
  pivot (and obol_local_pivot), creds (and credential_access), shells, cracking, findings_checks.
  Author with the new capabilities baked in. **Field-note coverage is now 100%: all 278 moves and
  all 848 commands across every lane are authored.**
- [x] **P8.** Refine pass over recon, linux, and web; stretch sparks (lockout-aware spray planner,
  report-snippet generator, proof-screenshot helper, "what changed" fact diff). Delivered: the
  Lockout-Aware Spray Planner and the "What Changed" fact diff (the two the owner prioritized), plus a
  refine that wires the web lane to the new tools (Build In Workbench chips for Manual SQLi and the
  Encoder, and note pointers on the SQLi, command-injection and JWT moves). The report-snippet
  generator and proof-screenshot helper are left as future sparks: the report route already generates
  OSCP report content, and the flag-capture field notes already drill the proof-screenshot discipline
  (id and IP in the same frame as the flag).

Naming: the new global section is **Workbench** (distinct from Tools, the command builders, and
Loadout, your installed tools). Easy to rename.

### Status log (update per commit)

- 2026-10-07: P0, plan documented in CLAUDE.md.
- 2026-10-07: P1, GTFOBins resolver. Bundled 477 binaries (data/gtfobins.js, GPL-3.0),
  OBOL.resolve engine, exact sudo/SUID escape surfaced in Next Steps for the parsed binary, plus a
  live lookup box. tools/build-gtfobins.js, tests/engine/resolve-smoke.js. All guardrails green.
- 2026-10-07: P2, lport is now a persistent param (sidebar field, default 4444, overridable) and the
  command filler pins it, so reverse-shell and listener commands are complete out of the box.
- 2026-10-07: P3, the Workbench shipped (global route, neon-glass panel, six sub-tabs, lazy-loaded,
  in the primary nav and the mobile More sheet). Pure engine in assets/engine/workbench.js
  (tests/engine/workbench-smoke.js). Built across four sub-commits:
  - P3a: Reverse Shell Builder. Curated OSCP catalogue as {{lhost}}/{{lport}} templates with notes and
    matching listeners. Base64 runner (Linux) and PowerShell -EncodedCommand (UTF-16LE then base64,
    byte-exact vs node Buffer). LHOST/LPORT seed from the engagement and save back to the one store.
  - P3b: Hash Identifier. Deterministic, rule-based. Structured prefixes resolve exactly; bare hex is
    ranked by OSCP-likelihood (NTLM-first) with alternatives; pwdump lines parse the NT and flag a set
    LM. Hashcat -m mode + john format + ready crack command per candidate. Auto-fills from captured
    hash facts (NTLM, krbtgt, AS-REP, TGS). Links to the hashcat wiki and CrackStation.
  - P3c: Encoder (mini CyberChef) and JWT decoder. Encoder shows every encoding at once plus a gated
    decode when the input looks encoded. JWT decodes header/payload, flags alg:none, HMAC weak-secret
    (hashcat -m 16500), RS256->HS256 confusion, and states plainly it is a decode, not a verification.
  - P3d: GTFOBins browser (reuses OBOL.resolve; gtfoFunctions + gtfoSuggest added) and a stack-aware
    Wordlist picker (task catalogue, tech-tag ranking, sample commands filled from the target).
  All guardrails green throughout; every surface driven headless (0 console errors) and
  screenshot-verified for readability, continuity, and full mobile stacking.
- 2026-10-07: P4, the Workbench is now wired into the coach. Next Steps cards carry "Build In
  Workbench" deep links, classified by what the move produces and the tools it uses (a hash ->
  Identify/Crack, sudo/SUID -> GTFOBins browser, gobuster/ffuf or a content/vhost move -> the
  wordlist picker with the right task preselected, a foothold/listener move -> reverse-shell builder,
  a JWT move -> the decoder). The wordlist picker reads the engagement's fact ledger to float the
  detected stack's list to the top, and the deep link can target a specific task
  (#/workbench/wordlists/subdomains). "Run all": the Set Up First block gains a "Copy All N Steps"
  bundle when a note has two or more authored setup one-liners (lights up as P7 authors multi-step
  setups; the orientation block already ships a run-together bundle). Presentation only, no pack
  command or coach ranking changed. Verified headless on a seeded SUID move (0 console errors).
- 2026-10-07: P5, Manual SQLi builder (seventh Workbench tab). A guided, strictly manual walkthrough:
  the student runs every query and fills in what each step reveals (column count, visible column,
  table), and obol writes the next payload. No automation, no sqlmap, so it stays exam-legal (stated
  in the panel). Seven phases unfold progressively: confirm injection (boolean/error/time), count
  columns, find a visible column, read version/user/db, list tables, list a table's columns, dump.
  DBMS-correct for MySQL/MariaDB, MSSQL, PostgreSQL and SQLite (comment style, concat, time-based,
  information_schema vs sqlite_master, CAST for MSSQL UNION). Engine in OBOL.workbench.sqliBuild,
  tested in workbench-smoke.js; links to PortSwigger. All guardrails green; screenshot-verified with
  0 console errors.
- 2026-10-07: P6, Explain This Output (eighth Workbench tab). Paste tool output; obol runs the REAL
  parser bundle (OBOL.parsers.analyzeTerminal, lazy-loaded on demand), then annotates: it highlights
  the lines that minted each fact and, per fact, says what it proves and what it does not prove in
  plain language (green / orange). Honest by construction: it annotates the facts the engine actually
  minted, never an invented one, and says so when nothing minted. The parsers carry no line numbers,
  so facts map to lines by matching their distinctive values, with whole-token matching for numbers
  so a port like 22 does not light up 2.4.41. Per-kind explanation table (OBOL.workbench.explainKind)
  with a safe fallback; annotateOutput + factNeedles tested in workbench-smoke.js. Verified headless
  on a real nmap paste (15 facts, correct line attribution, 0 console errors). The Workbench now has
  all eight tools.
- 2026-10-07: P7 COMPLETE. Authored every remaining field-note lane in committed sub-batches: shells,
  cracking, credential access, pivoting and local pivot, database, web exploit checks, findings
  checks, windows privesc, then the 68-move AD lane in five parts (recon/enum/roasting; pathfinding/
  dumping/lateral; ADCS/delegation/tickets/ACLs; foothold enum and Kerberos troubleshooters;
  trusts/coercion/relay and the CVE and advanced escalations). Field-note coverage is now 100%: all
  278 moves and all 848 commands across all 14 lanes carry an authored When / How To Land It / What
  To Look For / win / Common Mistakes note, in the learner-first voice, with the AD throughline
  (userlist handoffs, roast-then-crack, coerce-and-relay, the mandatory Zerologon restore) and
  pointers into the Workbench (Hash ID, reverse-shell builder, encoder, wordlist picker, GTFOBins).
  No payloads authored in the notes; the pack commands own those. tests/engine/field-notes-smoke.js
  updated: with full coverage there is no real un-authored move, so the fallback test now synthesizes
  one. All guardrails green throughout, lint clean, no em or en dashes.
- 2026-10-07: P8 COMPLETE, and with it the whole build. Two stretch sparks shipped as Workbench tabs:
  the Lockout-Aware Spray Planner (turns a lockout policy into a safe spray schedule) and What Changed
  (the fact diff since you last checked, reusing the Explain Output "Proves" lines). The Workbench now
  carries ten tools. Refine pass: the Build In Workbench classifier now surfaces Manual SQLi on SQLi
  moves and the Encoder on LFI/command-injection/XSS moves, and the manual-sqli, command-injection and
  jwt-attacks notes point at the matching tools. Field notes stay 100% (278 moves, 848 commands). All
  guardrails green end to end; every new surface screenshot-verified with 0 console errors.

  Build summary (PR #302): P0 plan, P1 GTFOBins resolver, P2 lport param, P3 the Workbench (reverse
  shell with base64 and PowerShell -EncodedCommand, hash identifier, encoder, JWT decoder, GTFOBins
  browser, wordlist picker), P4 coach-to-Workbench wiring, P5 manual SQLi builder, P6 Explain This
  Output, P7 field notes to 100% coverage across all fourteen lanes, P8 the spray planner, the fact
  diff and the web refine. House style held throughout (no em or en dashes, Title Case), every asset
  stamped, all tests/lint/gap/browser-smoke green.

### Post-build follow-ups (real-box testing on Forest)

- 2026-10-07: House toolkit (NetExec) preference + switchless probe, and What Changed folded into Explain
  Output. (1) Ranking: added a single global tool-class rule in pack.js (PREFERRED_TOOLKIT = nxc family),
  expressed as data like LOCUS_REMOTE, never per-move weights. It drives the within-move default command
  (preferredCommandIndex: prefer nxc, then a switchless probe, then pack order) and an across-move
  tie-break in nextActionsV2, placed below hand-tuned priority and above the remote-first locus tiebreak so
  it only decides genuine twins. (2) Switchless probe: the Anonymous SMB move now leads with
  `nxc smb {{target}} -u '' -p ''` to confirm a null session is even accepted before enumerating shares.
  It carries a new per-command `settled_by: [smb.null_session, smb.guest_session]`, so once anonymous
  access is proven the probe drops out of the card (never nag a question you answered); the render also
  re-points a stale selection off a settled command. Investigation note: the switchless variant never
  existed in obol_web's pack (git history confirms `--shares` was always command [0]); the owner
  sanctioned deviating from obol-local, so it was added to the source JSON and the bundle regenerated.
  (3) What Changed tab removed; its only durable value (the plain-language "what this newly proves /
  unlocks" narrative) already lives in Explain Output via the findings engine. Tests: locus-scope-smoke.js
  extended (toolkit rank, switchless-probe detection, settled skipping, across-move tiebreak). All
  guardrails green; headless-verified on a seeded Forest-like state with 0 console errors.
- 2026-10-07: Orient before exploit + progressive command disclosure + switchless LDAP. (1) Ranking:
  after a port scan the coach leads with the thorough service scan, then the orient steps, then
  enumeration. Mechanism: a fresh-tier recon-first rule in nextActionsV2 scoped to the opening (scanned
  but no scan.nmap.version, no foothold/credential), so it fixes the port-scan->service-scan transition
  and never buries the AS-REP roast. (2) Hide-gated-commands: a command still needing an EARNED token
  (basedn, domain, a credential, the scanned ports) is hidden behind a "more unlocks once you have ..."
  line, never the default; a move whose every command is gated drops to Coming Up. (3) Switchless LDAP
  probe on ad-anon-ldap-enum. ranker-smoke restructured; mssql corpus reframed post-service-scan.
- 2026-10-07: Credential tier, "validate a found credential before you use it". New fact
  credential.validated, minted when a credential becomes trustworthy (john/hashcat crack, online-brute,
  a successful nxc/evil-winrm/kerbrute login); a dumped/found plaintext is NOT auto-validated. New move
  validate-credential (switchless nxc over SMB/LDAP/WinRM, -H for a found hash) settles on
  credential.validated, so it only ever shows for a FOUND credential and leads via a bounded
  "validate before use" ranker tie-break. Full field-note + study-fixtures coverage.
- 2026-10-07: Two real-box parser fixes. (a) hostname/domain from an nmap -oX scan: the domain/hostname
  regexes required nmap's text "| " pipe, but the browser's DOMParser decodes the <script output> to
  un-piped lines, so smb-os-discovery never matched; made the pipe optional, so FOREST / htb.local now
  mint and the target card flips its name to the hostname (hostDomain also fixed to read the domain's
  `name` key). (b) WinRM's "Microsoft-HTTPAPI/2.0" server header on 5985/47001 no longer mints
  web.server, so a vuln scan on an AD box stops ranking the web-exploit lane above the real LDAP move.
- 2026-10-07: Smart Decoder (eleventh Workbench tab) plus an Encoder expansion. The Encoder now shows every
  common encoding at once (base64, base64url, hex, URL percent and every-byte, base32, ascii85, binary,
  decimal, HTML entities, gzip and zlib base64-wrapped, ROT13, ROT47, reverse, and ${IFS} evasion); it went
  async so the native compression streams can run. The new Smart Decoder is the opposite of the Encoder:
  paste anything and it (1) peels multi-layer encodings to completion via a bounded, scored BFS over the
  codecs that pass each layer's applies() guard (base64 of a gzip of hex, and so on), honestly reporting the
  chain and "nothing decoded cleaner than the input" when that is the truth, (2) shows every single-layer
  decode at once, flagging the ones whose shape matches, and (3) offers a Manual section with one field per
  codec so a power user can run a single step either direction by hand. All byte-oriented so compression
  chains stay binary-safe; all browser-native (atob/btoa, DecompressionStream). Engine in OBOL.workbench
  (CODECS, codecList, smartDecode, decodeAllOnce, runCodec, encodeAll), tested in workbench-smoke.js. All
  guardrails green; both surfaces driven headless (0 console errors), screenshot-verified desktop and mobile.
  The Workbench now carries eleven tools.

---

## Open item to revisit: make ranker tuning measurable before re-architecting it (NOT STARTED)

**Status: agreed, deferred by the owner. Do not start until the owner asks. This section is the full
brief: a future chat should be able to execute it from here alone.**

### The problem (why this exists)

Coach next-move tuning never converges and never feels satisfactory. Worse than it looks from any
single chat: the owner has attempted ranker tuning across several separate chats, and we keep
re-refining things already tuned in earlier chats, because no chat can see what a previous one
decided or measure whether a change helped or quietly regressed other boxes. It is Groundhog Day
tuning. The dissatisfaction is a MEASUREMENT problem (no scoreboard, no cross-chat memory of what was
tuned and why) at least as much as an architecture problem.

### The key diagnostic insight (do not skip this)

Before assuming the ranker is the problem, decompose where the tuning pain actually comes from. When
we decomposed this session's own Forest-driven patch history, four of five "tuning" patches were NOT
ranking-math problems:

- Web lane outranked AD (Microsoft-HTTPAPI minted web.server): a PARSER bug. The ranker did the right
  thing with a wrong fact. A probabilistic ranker would not have prevented it.
- nmap hostname/domain not captured (un-piped XML): a PARSER bug.
- Gated commands (hide a command whose fill-tokens are not earned yet): a CORRECTNESS FILTER,
  orthogonal to ranking weights.
- Prefer nxc (toolkit rank): a genuine PREFERENCE, already expressed cleanly as data.
- Recon-first before exploit: SEQUENCING / goal-distance. This is the ONLY one that is genuinely a
  ranking-math gap a planner could absorb structurally.

Conclusion: most churn is fact/parser correctness, correctness filters, and data preferences, not
ranker weights. The biggest lever on "useful next move" is fact/parser correctness and move-graph
completeness, which NO ranking architecture touches. Honest odds that a probabilistic rewrite is
"much more useful" than today's ranker: low (roughly 20 to 30 percent transformative; roughly 50
percent modestly better on sequencing cases while staying safe elsewhere). Adding moves/commands
costs about the same under any engine (the cost is authoring requires/produces + field note +
fixtures, identical in all worlds); a planner may cut the spiky "new move floated to the wrong place,
add a tiebreak" patches but introduces NON-LOCAL failure modes (a bad edge cost misroutes globally,
harder to debug than an additive score's local failure). A Bayesian archetype prior strictly ADDS a
maintenance surface (new facts need authored likelihoods).

### The plan, in strict order

1. **Build a ranking regression corpus + scoreboard FIRST (the actual fix for "never satisfactory").**
   This is the only step to start with. It is cheap, pure upside, and touches nothing in the live
   ranker. For each box archetype (Forest-style AD DC, Linux web box, Windows standalone, a few HTB
   classics), capture the fact-state at each decision point and the expert's expected top-1-to-3
   moves. Run `nextActionsV2` against every decision point and score "was the expert move in the top
   N." Make it a guardrail test. Now:
   - tuning stops being vibes: every weight change shows exactly what improved and what regressed,
     and you can tell when you are DONE;
   - it becomes the cross-chat memory: the fixtures ARE the record of what "correct" means, so a new
     chat cannot silently re-litigate settled orderings (this directly fixes the Groundhog Day
     problem the owner reported);
   - it tells you EMPIRICALLY whether the ranker is even the problem or whether the misses are
     facts/moves.
   Reuse existing machinery: `tests/engine/corpus-smoke.js` and its fixtures, `ranker-smoke.js`,
   `locus-scope-smoke.js`, and the seeded-state drivers in the scratchpad (drive-forest.js etc.).
   Estimate: about a day. No risk to the live ranker.

2. **Only if the corpus shows SYSTEMATIC sequencing failures a greedy 1-step score cannot fix**, try a
   bounded expected-path-to-goal planner: replace the greedy `enable` score with expected
   steps-times-reliability to the objective, via weighted Dijkstra / a Viterbi-style trellis over the
   AUTHORED move graph (requires/produces), never over learned transitions. Add it BEHIND the existing
   deterministic ordering as a soft tiebreak first (exactly how toolkit-rank went in), prove zero
   regressions on the corpus, and only then consider giving it more weight. Revert on ANY regression.

3. **Later follow-ons, only if step 2 proves out:** expected-value ranking (score = P(lands) x
   value-toward-goal - cost, formalizing the reliability weighting we already have) and a Bayesian
   box-archetype prior (a tiny belief over archetypes, updated by observed facts via naive Bayes with
   HAND-AUTHORED likelihoods, used only as a low-weight soft prior on lane ordering, surfaced with a
   visible reason like "obol thinks this is an AD DC, so AD moves lead"). These relocate tuning to a
   more interpretable place; they do not eliminate it.

### Hard constraints (these kill the tempting shortcuts)

- **No telemetry (AGENTS.md).** This rules out any LEARNED Markov chain / HMM from real playthroughs.
  Collecting what users do is forbidden and is part of staying exam-legal and trustworthy. Any
  transition probabilities must be hand-authored from the pack, not learned.
- **No Pyodide / heavy Python in the browser.** The math that helps (EV, Bayesian update, shortest
  path over the graph) is light and runs in microseconds in plain JS. Pyodide costs ~10MB+ download
  and multi-second cold start, spending the one budget we cannot (instant load + "it just works") for
  this neurodivergent/disabled audience, with no payoff. Hard no.
- **Deterministic and EXPLAINABLE always.** A "73% confidence" with no reason is worse for this
  audience than a clear "do this next, because X," and it reads like the AI-chatbot behavior OSCP
  bans. Probabilities may only shape ordering and reasons, never become an opaque predictor.
- **Pack commands stay the source of truth.** Any new mechanism enriches ranking/presentation only;
  it never rewrites the move graph or which command the coach ranks. One store, one filler.
- Add any ranking change as a soft tiebreak below the hand-tuned priority first, measure on the
  corpus, and revert on any regression. The ranker is the core of the tool; a clever idea is exactly
  how ten currently-green boxes break quietly.

### Where the code lives (so a future chat can orient fast)

- Ranker: `OBOL.pack.nextActionsV2` / `rankActions` in `assets/engine/pack.js`. Current sort: tier
  (recency) -> score (goalProgress + 0.6*enable + V2_KEYSTONE_W*keystone, reliability-weighted) ->
  priority -> house-toolkit (nxc, PREFERRED_TOOLKIT) -> locus (remote-first R<F<I) -> id. Constants:
  V2_KEYSTONE_W=0.15, V2_OBJECTIVE_W=3, FOCUS_BONUS=8. The Forest follow-up rules (earlyRecon
  recon-first tier, validateFirst, toolkit tiebreak) are all here.
- Command gating / "more unlocks once you have X": `assets/ui/routes/path.js` (GATE_TOKENS,
  cmdGated, nsCommandRows).
- Existing ranker/corpus tests to extend: `tests/engine/corpus-smoke.js`, `ranker-smoke.js`,
  `ranker-*-smoke.js`, `locus-scope-smoke.js`, `decisionmap-smoke.js`, `workflow-preference-smoke.js`.
- Architecture overview: `ARCHITECTURE.md` (ranker section).

### Kill criterion

Once the corpus/scoreboard exists: if the current ranker already scores well on it (expert move in
top-3 at the decision points), DROP the probabilistic-ranker idea entirely and redirect the saved
energy to parser correctness and move-graph coverage, which the evidence says are the real levers.
