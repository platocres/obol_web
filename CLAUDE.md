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

## Open item to revisit: make ranker tuning measurable before re-architecting it (SCOREBOARD BUILT)

**Status: the scoreboard now EXISTS: `tools/ranker-sim.js` (42 states = 7 archetypes x 6 stages,
judged against a methodology rubric). The first measured tuning has landed (see the 2026-10-07 A/B
entry in the Stuck status log): it confirmed the thesis empirically, two of three real issues were
move-data, only one was a ranking rule, and the fix took the sim from 3 violations to 0 with zero
test regressions. The probabilistic-rewrite steps below remain deferred and, per the kill criterion,
look UNNECESSARY so far (the current ranker scores clean on the rubric once move-data is right). Keep
using ranker-sim.js as the scoreboard for any future tuning. The brief below stays for reference.**

### How to run the scoreboard (procedure for a future chat, follow this)

This is the exact loop this session used to find and fix ranking / move-data problems. Reproduce it
whenever a move seems to rank wrong, or before and after ANY ranker or move-data change.

1. **Two tools, both read-only (they never touch the ranker):**
   - `node tools/ranker-sim.js` (add `--verbose` for every violation). The curated scoreboard: 42
     states (7 archetypes x 6 stages). This is the gate. It must print `0 / 42`.
   - `node tools/ranker-sweep.js [--n 4000] [--seed 1] [--show 3]`. The broad fuzzer: thousands of
     sampled port-sets x stages x injected findings, judged by ranker-sim's SAME rubric (exported, one
     source of truth) and CLUSTERED by (principle + leading move), so the output is "N issue patterns,"
     not a wall. Use it to catch what the 42 curated states miss.
2. **Read the board.** Each violation names a rubric PRINCIPLE (ad_lane_leads, no_brute_in_lead,
   no_unguarded_cve_lead, no_premature_loot, no_privesc_before_foothold, validate_first,
   command_sanity) and an example state (its archetype, stage, ports, and the top moves). A clean run
   is `0` violations.
3. **Triage each pattern BEFORE touching the ranker.** The thesis this project proved repeatedly: most
   "ranking" problems are NOT ranking-math. Sort every violation into one of:
   - **move-data** (a move's requires/produces is wrong, so it is eligible when it should not be, or
     its command keys on a token it should not): fix the pack JSON, regenerate the bundle.
   - **parser / fact correctness** (the ranker did the right thing with a wrong fact): fix the parser.
   - **a correctness filter** (a command should be hidden until a token is earned): that is path.js
     gating, not a weight.
   - **a genuine ranking rule** (sequencing / a real preference): only THIS is a ranker change, and it
     goes in as a soft tiebreak BELOW the hand-tuned priority (see nextActionsV2), measured on the sim,
     reverted on any regression.
   Expect ~2 of every 3 real issues to be move-data, not ranking.
4. **Two gotchas that cost this session real time, do not repeat them:**
   - **Load the FULL engine, including `assets/engine/loot.js`, in any harness.** ranker-sim.js now
     requires it (ranker-sweep.js inherits it). Without loot.js, output-path and discovery tokens
     ({{hashfile}}, a discovery {{userlist}}) never resolve, so command_sanity flags violations the
     LIVE app never shows. A sim that does not mirror the real filler cries wolf.
   - **Fix only what a user would actually SEE and be confused by.** A command hidden by path.js
     gating until a token is earned is fine (the user never sees it). A move that can only ever render
     as a dead or backwards card is not. Confirm which by driving the real app headless (below), not by
     reading raw ranker output.
5. **Verify every change against ALL of:** `node tools/ranker-sim.js` (must stay `0 / 42`), the broad
   sweep (must not regress), the full engine suite (`for t in tests/engine/*.js; do node "$t"; done`,
   especially ranker-smoke, corpus-smoke, ad-killchain-e2e, locus-scope-smoke), the guardrails
   (field-notes-coverage, lint-study, gap-report, browser-smoke), then stamp assets. Finally, drive the
   app headless on the relevant seeded state and read the card for sense (0 console errors): a scratchpad
   driver that serves the repo and parses evidence into facts is the pattern (see the drive-*.js helpers
   this session wrote; they seed via OBOL.store.setParam + the Evidence paste box).
6. **To extend coverage:** add an archetype or stage to ARCHETYPES / STAGES in ranker-sim.js (the
   curated gate), or widen the sampler in ranker-sweep.js. The rubric lives ONCE in ranker-sim.js and is
   exported to the sweep, so change a principle in one place only.

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
- Scoreboard tools (the measured-tuning loop, see "How to run the scoreboard" above):
  `tools/ranker-sim.js` (curated 42-state gate) and `tools/ranker-sweep.js` (broad fuzzer, reuses the
  sim's rubric). Both read-only; both carry a usage header.
- Architecture overview: `ARCHITECTURE.md` (ranker section).

### Kill criterion

Once the corpus/scoreboard exists: if the current ranker already scores well on it (expert move in
top-3 at the decision points), DROP the probabilistic-ranker idea entirely and redirect the saved
energy to parser correctness and move-graph coverage, which the evidence says are the real levers.

---

## Active build: the Stuck? tab (in progress, PR #302 branch)

**Plan of record. If this chat is lost, resume from this section. Work on branch
`claude/obol-web-overhaul-local-59ttbx`. Commit frequently.**

### Intention

A global **Stuck?** tab for exam-takers (OSCP lab, not neophytes) who are stuck in a box and want to
see their options FAST without pasting terminal output. They assert attributes about their target by
clicking human-phrased binary buttons (neon glass, multicolor), and obol shows ranked move cards,
the SAME ranker as Next Steps, that expand to commands with field notes. Progressive disclosure: the
more facts they give, the more relevant fact options and moves appear, never everything at once. It
is NOT meant to run a whole engagement, just to hand a stuck student a path forward. Advisory by
construction: everything is framed as "based on what you told me," deterministic and explainable,
same as the coach.

### Decisions locked (owner-approved)

- **Full curated fact catalog across ALL lanes up front** (not a vertical slice). The catalog is the
  real cost; the UI is quick.
- **Global primary nav** item (alongside Workbench and Playbooks, plus the mobile More sheet),
  standalone, works with no engagement.
- **Sandbox by default.** Stuck? runs in its own ephemeral in-memory FactSet and NEVER writes to the
  active engagement. Two opt-ins only: "Start from my active engagement" (seed from real facts) and
  "Save these to an engagement."
- **Triage first.** One opening question ("What do you have right now?": nothing yet / open ports /
  services known / a foothold shell / a working credential / local admin) sets the phase, then the
  relevant binary facts reveal.
- **"I tried it / ruled out" toggles in v1** (see mechanism below, this is load-bearing for
  un-sticking: stuck means the obvious thing already failed).
- **Single target in v1.** Multi-target (pivot/AD-wide) is a later iteration (needs relationships
  between targets that buttons model poorly).
- **Typing is contextual, never upfront.** Binary buttons mint presence facts (enough to rank);
  typed fields appear only when a selected command needs a token to fill (lhost, domain), tied to a
  concrete payoff.

### The REFUTED finding and the "I tried it" mechanism (critical)

The coach ranker (`nextActionsV2`) is **SUPPORTED-facts-only**. `FactSet.has/.values/.kinds` all hard
-filter to `ProofState.SUPPORTED`, so a `REFUTED` fact is INERT: it cannot prune or demote a move.
Therefore "I tried it, didn't work" must NOT be modeled as a REFUTED fact. Instead:

- **"I tried this MOVE, it failed"** (per move card) maps to the ranker's existing `opts.doneIds`
  (`{id:true}`), a local, per-call exclusion that removes that move and floats up the next option.
  No ranker change, no store write.
- **"This CONDITION is ruled out"** (signing on, no anon access, filtered port) maps to the POSITIVE
  SUPPORTED fact the pack already uses in a move's `obsoleted_by` (drops the move) or
  `deprioritize_when` (-40 priority), where that edge exists. Where the pack does not yet model a
  condition negatively, v1 falls back to the per-move "didn't work" doneIds exclusion. Enriching pack
  edges later is a pack-data change, never a ranker fork.

### Engine APIs to build on (confirmed)

- `OBOL.pack.rankActions(facts, pack, opts)` is PURE over its args (no `OBOL.store` reads). Default
  dispatches to `nextActionsV2`. Returns a sorted `Action[]` (best first); fields per Action: id,
  title, tool(s), command(s) `[{tool,run,note,settled_by?}]`, priority, phase, requires_all,
  requires_any, produces, obsoleted_by, deprioritize_when, proves, does_not_prove, locus, scope,
  refs. `opts = { doneIds, focusPrefixes }`.
- `pack = OBOL.packs.actions()` (cached shared `Action[]`, read-only, do not mutate).
- Sandbox: `new OBOL.facts.FactSet()`, then `fs.add(OBOL.facts.makeFact({kind,scope,value,state}))`.
  `makeFact` defaults state to SUPPORTED. `add` dedups on (kind,scope,value); same key, new state
  supersedes in place.
- Companion planners: `OBOL.pack.lockedActions(facts,pack)` -> `[{action, reason}]` (OS-ok but not
  yet eligible, with the unmet-prereq reason), `blockedActions`, both pure.
- Frontier/phase: `OBOL.phases.targetPhase(fs)`, `frontierIndex(fs)`, `phaseOfKind(kind)`,
  `phaseOfAction(action)`. Phases: recon, enum, creds, access, escalate, loot.
- Labels for the catalog (reuse, author the gaps): `OBOL.pack.friendly(kind)` (broadest short
  kind->noun-phrase map), `OBOL.workbench.explainKind(kind)` -> `{proves,caveat}`,
  `OBOL.workbench.explainFact(fact)` (value-aware echo). Kind universe:
  `OBOL.PARSER_SIGNATURES` emits (+ pack produces). Only ~40 kinds have hand-written explain text;
  author the rest.

### Reveal-from-graph (the core algorithm, derive, do not hand-maintain a menu tree)

The facts worth asking about next = the facts the near-frontier moves REQUIRE or PRODUCE. For each
non-settled, non-obsolete move: if it is eligible, its `produces` are mild candidates (asserting them
advances); if it is NOT eligible, its unmet `requires_all` / unmet `requires_any` are candidates,
weighted higher the closer the move is to eligible (gap of 1 unmet strongest). Exclude kinds already
SUPPORTED. Rank candidates by information gain (how many moves each would help unlock), group by
phase, show a bounded batch. This keeps the catalog in lockstep with the move graph and self-prunes
to only the questions that would change the suggestions.

### Acceptance criteria (hard, not polish)

- **Responsive and fills the width at EVERY size: 4K, 1920x1080, tablet, phone to ~320px.** No wasted
  gutters: the fact-button grid reflows to MORE columns as width grows (so 1080p and 4K pack with
  buttons, not empty margin), and the move-cards region uses the real available width beside the
  sidebar, never a fixed skinny center column. Screenshot-verify 4K, 1080p, tablet, mobile; confirm
  1080p specifically is packed, not guttered.
- **House style: no em or en dashes anywhere** (commas, colons, periods). Proper capitalization,
  Title Case for the tab, every label, heading, and binary-button phrase, and any field notes.
- **Aesthetic:** neon glass, multicolor, glowing, rainbow shimmer that intensifies as more facts
  light up, BUT the shimmer is gated behind `prefers-reduced-motion` (off cleanly for that audience),
  and colour is NEVER the sole signal (a "ruled out" fact carries a shape/label, not just a red glow).
  11px font floor.
- **Advisory framing:** every suggestion labeled "based on what you told me." Deterministic and
  explainable; no opaque prediction.
- **Boundaries unchanged:** sandbox never writes the active engagement unless the user opts to save;
  pack commands stay the source of truth; the ranker is not forked.

### Phases (check off as completed)

- [x] **ST0.** This plan in CLAUDE.md + task tracking.
- [x] **ST1.** Engine foundation `assets/engine/stuck.js` (pure, headless-tested): sandbox helpers,
  `suggestFacts` (reveal-from-graph), `rankedMoves` (rankActions + doneIds), triage seeds, the
  ruled-out -> doneIds/positive-fact mapping. Smoke test `tests/engine/stuck-smoke.js`.
- [x] **ST2.** The FULL curated fact catalog across all lanes (`data/stuck-catalog.js`, 107 kinds):
  human-phrased binary label per user-assertable kind, grouped by lane, reusing friendly()/explainKind()
  and authoring the gaps. Voice sanctioned by the owner on the Recon + Web sample first.
- [x] **ST3.** UI route `assets/ui/routes/stuck.js` + global nav (index.html desktop + mobile More
  sheet) + lazy group (assets/ui/lazy.js). Triage-first flow, progressive neon-glass fact picker
  (bounded to 18, "Show All N"), per-move "I Tried This" (doneIds), move cards (reuse ranker, expand
  to filled commands, Build In Workbench deep links, field notes), optional Target/LHOST/LPORT fill,
  sandbox with seed-from-engagement and save-to-engagement opt-ins.
- [x] **ST4.** Aesthetic + responsive pass. Two-column grid that fills the width; fact grid reflows
  to more columns as the viewport grows; `main#view:has(.stuck)` raised to 2600px so 4K is not
  guttered (1080p already fills); lane hues, rainbow shimmer gated behind prefers-reduced-motion;
  colour never the sole signal. Screenshot-verified 4K, 1080p, tablet, mobile; 0 console errors.
- [ ] **ST5.** Final guardrails + owner review on the live site.

### Synergy with the deferred ranker-corpus open item

The curated catalog + the manual state-builder in Stuck? are nearly the exact tooling the ranking
regression corpus would need (construct a fact-state, see the ranked moves). Building Stuck? gets us
most of that fixture-authoring surface for free, and is a natural place to notice when the ranker
gives a weird answer on a hand-built mid-game state.

### Verify each phase (same as the project)

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` ·
`node tools/gap-report.js --check` · `for t in tests/engine/*.js; do node "$t"; done` ·
`NODE_PATH=/opt/node-tools/node_modules node tests/browser-smoke.js` ·
`node tools/stamp-assets.js` (after any asset edit) · drive the app headless (0 console errors) ·
screenshot the changed surface at 4K, 1080p, tablet, and mobile and read it for sense and width use.

### Status log (update per commit)

- 2026-10-07: ST0, plan documented. Engine APIs mapped (rankActions pure over FactSet; REFUTED inert
  so "I tried it" uses doneIds / positive-fact edges; labels from friendly()/explainKind(); kind
  universe from PARSER_SIGNATURES).
- 2026-10-07: ST1 engine foundation (assets/engine/stuck.js): sandbox/assert/retract, suggestFacts
  (reveal-from-graph, frontier-weighted, catalog-gated), suggestByPhase, rankedMoves (rankActions +
  doneIds for "I tried it"), TRIAGE + triageSeed guarded against the kind universe. tests/engine/
  stuck-smoke.js. All guardrails green.
- 2026-10-07: ST2 catalog. data/stuck-catalog.js, 107 user-assertable binary facts across Recon, Web,
  Windows And AD, Credentials, Access, Linux Privesc, Windows Privesc, Loot, Pivoting. Owner sanctioned
  the voice on the Recon + Web sample first. The smoke test verifies every cataloged kind is a live
  pack/parser kind (dropped 8 that loadPacks canonicalizes away, e.g. access.root -> access.admin).
- 2026-10-07: ST3 + ST4. Shipped the Stuck? tab: global nav (desktop + mobile More sheet), lazy group,
  the route (triage-first, progressive fact picker bounded to 18 with Show All, per-move I-Tried-This,
  move cards reusing the ranker with filled commands + field notes + Build In Workbench links, optional
  Target/LHOST/LPORT fill, sandbox with seed/save opt-ins). Responsive: two-column grid fills the width,
  fact grid reflows to more columns on wide screens, main#view:has(.stuck) raised to 2600px so 4K is not
  guttered. Neon glass, lane hues, shimmer gated by prefers-reduced-motion. Driven headless at 4K, 1080p,
  tablet, mobile with 0 console errors; all guardrails (engine, browser-smoke, lint, gap) green. ST5 is
  owner review on the live site.
- 2026-10-07: STUCK? REDESIGN (the Ferryman), owner-directed, built A-E. The dense button board became
  a guided experience. (A) Port palette + lane gating: OBOL.STUCK_PORTS (37 curated ports, grouped),
  picking a port asserts the service/reachable fact; laneActive() hides a lane until a port/foothold
  implies it; isFinding() keeps ports out of the findings refiner. (B) Interview state machine (Act 1):
  one question at a time, host -> pick ports -> credential? -> shell?(+OS) -> admin?, each seeds the
  sandbox, fully skippable, with "not sure? run this" command hints. (C) Ferryman persona + cyberpunk
  skin: a warm cyberpunk Charon (an obol pays the ferryman to cross), glowing eye orb, typewriter
  prompts, neon-glass answer buttons, all motion gated by prefers-reduced-motion, colour never the sole
  signal. (D) Act 2 board: ranked move TILES reusing the Next Steps mechanic (.ns-card/.ns-grid: select
  to expand with the --fam glow, is-glow, and the ns-bloom rainbow prism sweep, grow-and-reflow), plus a
  calm port-gated refiner (Open Doors visible, Findings collapsed). Engine (SX-A) committed with tests;
  route+CSS driven headless through the full interview to the board at 4K, 1080p, tablet, mobile with 0
  console errors; all guardrails green. The old flat-picker route was replaced.
- 2026-10-07: RANKING SIMULATOR + first measured A/B tuning. Built tools/ranker-sim.js (the scoreboard
  from the deferred open item, realized on the Stuck? state-builder): 42 states (7 archetypes incl. a
  noisy AD box x 6 stages), ranker run over each, top moves judged against a rubric (AD lane leads on an
  AD box, no brute in the lead, no unguarded version-CVE lead, no premature loot, no privesc before
  foothold, validate-first, command sanity). Baseline flagged 3 states and reproduced the real-box
  SSH-over-AD bug. Owner-sanctioned A/B tuning, measured on the sim AND the full ranker test suite:
  (Fix 1, ranking rule) the earlyRecon recon-first tiebreak in pack.js now lifts ONLY the thorough
  service scan (produces scan.nmap.version), not every recon-phase move, so per-service recon
  (ftp/ssh/dns/udp) stops burying the higher-priority AD orient line on multi-service boxes; the noisy
  AD box now leads ad-dc-identify > ad-anon-ldap-enum > ... and ssh-user-enum fell to #5 on its own.
  (Fix 2, SSH priority) proven UNNECESSARY by the sim once Fix 1 landed, dropped (no over-tuning).
  (Fix 3, move-data) gpp-passwords now requires read access to SYSVOL (credential.available OR a proven
  null/guest SMB session) instead of just smb.reachable, so it stops surfacing as premature loot at
  recon. Result: sim 3 -> 0 violations, gap-report clean (gpp still reachable), and every engine test,
  lint, move-lint, coverage, and browser-smoke green (zero regressions). Bundle regenerated, assets
  stamped. Validates the open-item thesis: 2 of 3 real issues were move-data, 1 was a ranking rule; no
  ranker rewrite needed.
- 2026-10-07: BROAD RANKING SWEEP (tools/ranker-sweep.js) + triage. A fuzzer over ~4,678 states
  (realistic archetypes x stages, pairwise port coverage, and ~4,000 randomly-sampled port-sets x
  stages x injected findings), reusing ranker-sim's rubric (exported from ranker-sim.js; one source of
  truth). First run flagged 7.5% of states, but most were FUZZER ARTIFACTS: unconstrained fact
  injection (privesc.* with no foothold, smb.* with no SMB port, hash.ntlm on a pure-DB box) invented
  impossible states. Hardened the generator (canInject preconditions: a finding only lands if the state
  could produce it) and sharpened the rubric (anonymous-session loot and confirmed-vuln exploitation
  are NOT premature; a database/web login ahead of AD is a legitimate lead, not noise burying AD). That
  took the sweep from 7.5% to 1.4%, isolating the one clear real bug: ticket-forge moves
  (golden-ticket, silver-ticket, ticket-reuse) need the domain to forge but did not require it, so they
  ranked with an unfillable {{domain}} command. Fix: requires_all += ad.domain_known on those three.
  Result: sweep 65 -> 45 states (1.0%), curated sim still 0/42, full engine suite + browser-smoke +
  lint + move-lint + coverage + gap all green, ad-killchain still completes (domain is captured long
  before any hash). Remaining residual (~45 states) is minor/judgment-call: blind SSH/FTP brute at #3
  on 2-port boxes, and a couple more domain-gated commands, surfaced to the owner, not auto-fixed.
  Subagents were considered but not used: the compute is one fast Node process, and the triage
  collapsed to ~4 patterns, so parallel investigation was not warranted.
- 2026-10-07: Brute moves, spray-vs-blind split (owner-directed). The owner caught that online-brute-ssh
  was authored as a spray (its command is `hydra -L users.txt`, hypothesis says "enumerated user
  list") but gated only on ssh.reachable, so it surfaced before you had any users. (A) Gated
  online-brute-ssh/ftp/rdp on a userlist: requires_all [service.reachable] + requires_any
  [ad.user_list, web.users], and the command now fills {{userlist}}. (B) Added blind-brute-ssh, the
  genuine last resort (priority 10, requires only ssh.reachable, a SHORT common-users wordlist, not an
  enumerated one) for the case where you have no userlist, with field note, study evidence seed, label,
  and noise annotation. Second-order effect the sim caught: gating the brutes on ad.user_list made
  ssh-user-enum (which PRODUCES ad.user_list) more valuable (it now enables the brutes), so it jumped to
  #1 on Linux boxes. Fixed at the root: ssh-user-enum (a version-specific CVE) now requires
  scan.nmap.version, so you must do the service scan before a version-CVE, which also permanently
  satisfies no_unguarded_cve_lead (it can only be eligible once the version is known). The rubric learned
  the distinction: a userlist spray in the lead without a userlist is a bug; a dedicated blind brute
  (id "blind") is an exempt last resort. Result: sim 0/42, sweep 43 states (0.9%), full engine suite +
  browser-smoke + lint + move-lint + coverage + gap all green, ad-killchain intact. Pending: the owner's
  "check AD first to get oriented, then the SQL" call on DB-vs-AD ordering (realistic single-DB DC already
  keeps AD in top 3; still queued).
- 2026-10-07: "Rule out AD first", AD-orient holds a top-3 slot (owner-directed). The owner's DB-vs-AD
  call: on an AD box you want to get oriented and rule AD out before diving into service exploitation
  (a database or web login), even when several high-value services are open. Added a surgical post-sort
  promotion in nextActionsV2 (assets/engine/pack.js): on an AD box where the DC/domain is not yet
  confirmed (no ad.dc_candidate + ad.domain_known) and you have NOT landed a foothold or credential, the
  top eligible AD-orient move (one that produces ad.dc_candidate / ad.domain_known / ad.base_dn /
  ad.anonymous_bind you do not yet have) is spliced to position 3 if it is not already top-3; everything
  else keeps its order. It self-disables the moment you are oriented (the orient move settles) or you are
  on the box, and it only fires when such a move is actually eligible, so pure-Linux and post-foothold
  states are untouched. The rubric (ranker-sim.js ad_lane_leads) was made strict-but-precise to match:
  it flags ONLY when an eligible orient move is not in the top 3 (if no orient move is eligible there is
  nothing to pin, so it is not a failure), the same condition the rule enforces. Verified: DC + all DBs
  now shows mssql-login > mysql-login > ad-dc-identify > ... (AD pinned at #3); a plain DC keeps AD at #2
  naturally; pure-Linux is unaffected. sim 0/42, broad sweep 32 states (0.7%, all pre-existing
  command_sanity residuals: recon-smtp needs a userlist, asrep-roast needs a hashfile, zero ad_lane_leads
  violations), full engine suite + ranker-smoke + corpus-smoke + ad-killchain-e2e + locus-scope-smoke +
  guardrails + browser-smoke all green. Engine-only change (no pack-data edit, no bundle rebuild); assets
  stamped.
- 2026-10-07: Residual triage, discovery-vs-spray user list + scoreboard accuracy (owner rule: fix only
  what a user would see and be confused by; never-seen gated tokens are fine). Ran the full gated-command
  picture, not just the two flagged moves. Findings and decisions, all at once: (1) asrep-roast / hashfile
  was a SCOREBOARD ARTIFACT, not a user-facing bug: ranker-sim.js and ranker-sweep.js never require loot.js,
  so {{hashfile}} (an OUTPUT path) never resolved in the sim; in the live app loot.js resolves it to
  loot/asrep.hashes, the Rubeus and the three crack commands are runnable, and the move is Ready Now. No
  fix to the move; instead loaded loot.js in ranker-sim.js (ranker-sweep.js inherits it) so command_sanity
  now sees the loot-resolved commands the user actually sees. (2) recon-smtp was a GENUINE dead card:
  SMTP VRFY enumeration DISCOVERS users, but its command keyed on {{userlist}}, which loot deliberately
  leaves unfilled until a list is proven (the right signal for a SPRAY), so every command was gated and the
  move could only ever show as a backwards "unlocks once you have a user list" card on a move whose job is
  to FIND users. Fixed as a GENERAL rule in the one filler (assets/engine/loot.js, tokensFor): a command
  that uses {{userlist}} but is NOT gated on a proven list (ad.user_list / web.users) is a discovery move,
  so it seeds a default names list (seclists top-usernames-shortlist, matching the blind brute) and is
  runnable at once; a spray move keeps pointing at the materialized list and stays an honest dependency
  signal. Verified: recon-smtp is now Ready Now with a runnable VRFY command (the swaks command still
  hides, correctly, until the domain is known); the brute sprays are unchanged (gated until users are
  enumerated, then resolve to loot/users.txt). loot-smoke.js updated to lock in the discovery-vs-spray
  distinction. Result: sim 0/42, broad sweep now 0.0% (clean), full engine suite + guardrails + browser-smoke
  all green, 0 console errors driving the live recon-smtp card. Engine + test + sim change; no pack-data
  edit, no bundle rebuild; assets stamped.
- 2026-10-08: Real-box parser fix (Forest), anonymous LDAP bind now mints ad.anonymous_bind, so the spent
  probe drops. The owner noticed on a live Forest run that after pasting `nxc ldap <ip> -u '' -p ''`
  output (a successful anonymous bind), the ad-anon-ldap-enum card did not change: the bare probe command
  stayed instead of settling. Root cause was a PARSER backslash-count bug (the "ranker did the right thing
  with a wrong fact" class, which our scoreboard procedure calls out): the anon-bind regex in
  parsers/directory.js required TWO backslashes (`\\\\:` in the literal) before the colon, but real nxc
  prints the empty-user signature with ONE (`[+] htb.local\:`), so ad.anonymous_bind never minted and
  command [0]'s settled_by:[ad.anonymous_bind, ldap.authenticated] never fired. Fix: match a single
  backslash (`\\:`); verified it mints on the anon line and does NOT misfire on an authenticated bind
  `DOMAIN\user:pass` (no backslash-then-colon there). Now the probe settles and drops, and the card
  advances to lead with the `--users` dump (the move itself stays, correctly, until ad.user_list is
  proven). Regression test added to nxc-switch-parsers.js (anon mints, auth does not). Noted but NOT
  fixed (separate, only matters for the authenticated case which already settles via ad.anonymous_bind):
  ldap.authenticated is produced by a move and mapped in phases/labels but minted by no parser. Full
  engine suite + guardrails + browser-smoke green, sim 0/42; parser asset stamped.
- 2026-10-08: Three real-box fixes from a live Forest run (owner testing on a fresh Kali VM). (1) Set Up
  First prep steps did not fall away after being run, eating the card with the loot/users.txt and
  loot/asrep.hashes heredocs. obol can't see the operator's disk, so there is no honest auto-detect
  (commandWasRun needs 3+ distinctive tool tokens and will not match a cat-heredoc); instead each prep
  step now carries a "Got It" control that collapses it to a single "done, <file> written [Show]" line,
  persisted per engagement in eng.ui.prepDone and keyed by a content hash of the exact bytes it writes,
  so a dismissed step RE-APPEARS if the file obol would write changes (you proved more users). path.js
  prepStep/prepBlock + two click handlers (mirrors the ws-done pattern), CSS for the collapsed line.
  (2) hashcat failed on the fresh VM with clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR: a GPU-less Kali
  has no OpenCL/CUDA backend, so hashcat exits before cracking. The Loadout arsenal (assets/engine/
  arsenal.js, buildScript) now installs PoCL (pocl-opencl-icd + ocl-icd-libopencl1) when hashcat is
  present but `hashcat -I` shows no backend, so cracking works out of the box in a VM; it skips when a
  real GPU backend exists, so GPU boxes are not bloated. bash -n clean. (3) Field-note hints added to
  crack-asrep and crack-kerberoast: the CL_PLATFORM error means a GPU-less VM, fix with pocl-opencl-icd
  or the john line (no GPU needed). All guardrails + full engine suite + browser-smoke green; prep-step
  collapse driven headless (Got It collapses the heredoc, persists, 0 console errors); assets stamped.
- 2026-10-08: Field-note polish (owner feedback on the above). (1) Authored note lines now support inline
  `backtick` code: a new fmtNote() helper in path.js renders each backtick span as a monospace, click-to-copy
  <code class="ns-ic"> chip (reusing U.copy), applied to How To Land It / What To Look For / Common Mistakes
  / the win line. General capability, not a one-off. The two hashcat notes now read the error as a code chip
  (`CL_PLATFORM_NOT_FOUND`) and offer the fix as a one-click-copy chip (`sudo apt install -y pocl-opencl-icd`).
  (2) House-style Title Case on the Set Up First prep step: the chip is "Write" / "Done", the copy button is
  "Copy". Verified headless: both chips render with correct copy text, prep labels Title Case, 0 console
  errors. Guardrails + engine + browser-smoke green; assets stamped.
- 2026-10-08: Forest post-credential ranking (owner real-box run) + BloodHound ingest verified + a new
  structural task. (1) usermin-rce was eligible on ANY credential (a Usermin-specific RCE); gated it on
  its fingerprint (port:20000 / vuln.usermin) so it stops cluttering every credentialed box. (2) After
  cracking svc-alfresco (validated domain cred, no shell), the coach led with ADCS abuse at #2 and buried
  BloodHound at #6 and the foothold. Two measured fixes: bloodhound-collect now produces ad.control_paths
  (it undervalued itself by omitting the keystone, score 0.14 vs the manual path-finder's 0.96); and a new
  nextActionsV2 rule (specializeHold) demotes named-misconfiguration abuse (ADCS/Trust/SCCM) below the
  map/foothold/roast moves while you hold a credential but have NOT mapped and have NO foothold, self-
  disabling once you map or land a foothold. Owner chose "map first, keep manual-first": manual path-finder
  stays #1, BloodHound rises to #2 (not ahead), foothold to #3, kerberoast #5. Scoreboard gap closed: added
  a cred_remote stage (credential, no foothold) to ranker-sim.js (49 states) + a specialize_after_map
  principle, teeth-checked (rule off -> 3 flagged incl ad_dc/cred_remote; on -> 0/49). sim 0/49, sweep 0.0%,
  full suite + ad-killchain-e2e + guardrails + browser-smoke green. (3) Verified the BloodHound ingester
  end to end on the owner's real Forest zip: ownedPaths from SVC-ALFRESCO finds 16 owned->DA paths, the
  shortest being the exact Forest chain (... -> EXCHANGE WINDOWS PERMISSIONS -> HTB.LOCAL), mints
  ad.attack_paths, and the coach then leads with ACL Abuse (bloodyAD) / Object ACL Abuse, the real win.
  It surfaces AND recommends correctly; the only dependency is that the engagement has the owned principal
  (svc-alfresco) set, which drives the owned->DA path computation. (4) NEW OPEN TASK (#30): an end-to-end
  command -> real output -> fact -> advance/retire round-trip audit. Every audit so far tests ranking given
  facts; none test the loop the human actually runs, so parser/retire gaps (e.g. certipy find erroring on
  a box with no CA and the ADCS move not retiring or acknowledging it) only surface on the real box. This
  is the structural fix for the recurring "I ran it, pasted it, nothing changed" class.
- 2026-10-08: Domain (BloodHound) tab, major upgrade (owner-directed, general to any collection). The tab
  computed a rich analysis but rendered only the graph + census; made it answer "so what do I do". (1)
  Bridge banner: after ingest, names the coach's top queued move and links to Next Steps, closing the seam
  where users did not know the graph fed the coach. (2) Route To Domain Admin: the derived shortest
  owned->DA path as numbered steps, each hop's edge with a bloodyAD command (group -> add member, domain
  control -> grant DCSync, user -> reset), ending in the DCSync dump. (3) Closest To Domain Admin board:
  new engine nearestToGoal (one reverse BFS) ranks every principal by hops to DA; click a row to explore.
  (4) Explore An Account: new engine controls() (forward reachability) + ownedPaths for ANY principal, so
  users theorize from accounts they do not own. (5) Smarter census: matched cards first, empties collapsed,
  owned principals marked, AS-REP / password-not-required flagged "costs nothing". (6) Graph: BloodHound-
  style round nodes with the name underneath (owned green, goal red); edges stop at the circle so arrows
  stay visible. Fixed a latent bug: domain.js mounted() used `mount` without defining it, so copy/report
  wiring silently threw (now ctx.mount); and the "UNDEFINED USERS" header (users is a count, not an array)
  plus three missing-space hint glitches. Engine additions covered in bloodhound-smoke.js. Driven headless
  on the owner's real Forest zip: bridge + route (exact ...->Exchange Windows Permissions->HTB.LOCAL chain)
  + 12-row board + 13 round labelled nodes + 19 matched cards + "32 users"; explore loads on click; 0
  console errors. Full engine suite + browser-smoke + gap green; assets stamped. (Tasks #31-#35.)
- 2026-10-08: Domain (BloodHound) tab, "explore + own + diff" slice (owner-directed, general to any
  collection, built after an alignment pass). The tab stops being read-only and becomes a BloodHound
  replacement you steer. Five pieces, one pass (Tasks #36-#39):
  (1) Engine (assets/engine/bloodhound.js), five pure additions with smoke coverage: principalProfile
  (the weaknesses the data carries on one account, SPN/DONT_REQ_PREAUTH/PASSWD_NOTREQD + census roles),
  acquisitionLines (data-INDICATED ways to acquire a non-owned account, from its own attributes only,
  no generic host-enum noise), principalList (every principal ranked by closeness to DA, for the
  dropdown), graphFingerprint + diffCollections (a compact snapshot + a temporal diff: new/removed
  principals, new/removed abusable+MemberOf edges, census-flag deltas).
  (2) Inspect dropdown at the top (where the owned principal was): select any account, owned or not, and
  see its tags, path(s) to DA, and what it controls. Board rows, census buttons, diff names,
  controlled-object links and graph nodes all drive the one inspect slot; _inspecting survives a re-render.
  (3) Ownership as ONE set behind THREE doors (owner's refinement): a stored credential, a pasted login
  (mints a credential, same set), or ticking "I Own This Account Now" (eng.bloodhound.ownedExtra, carried
  across re-uploads). Runnable abuse commands (walk the path, bloodyAD per hop, DCSync cash-in) stay hidden
  until you own the account; a non-owned account shows theory (path + controls) + how to acquire it + the
  gate. Ticking re-derives the whole tab and restores the card.
  (4) What Changed Since Last Collection: the diff vs the prior upload, new leverage, flag deltas,
  new/removed principals, each name clickable to inspect. Native BloodHound-CE has no such temporal view.
  (5) Expandable "+ N more" on the targeting board and the controls list, so nothing is hidden for good.
  Ingest stores summary.diff + carries ownedExtra. Presentation only: no ranker fork, one store, one filler.
  Driven headless on the owner's real Forest zip through the full gate -> unlock flow (inspect SVC-ALFRESCO
  non-owned: AS-REP tag + acquisition + gate, no walk commands; tick "I own this": card restored with the
  walk commands, gate gone, top route + 13-node graph appear) and the diff panel, desktop + mobile, 0
  console errors. Full engine suite + browser-smoke + lint + gap all green; assets stamped. House style held
  (no em or en dashes, Title Case). Still open from the same discussion thread for a later pass: feeding the
  diff's new-leverage edges into the coach as "a faster route opened", and the bigger "exceed BloodHound"
  ideas (progress-aware overlay, marginal-value who-to-hunt, what-if owned set).
- 2026-10-08: Domain tab follow-through (owner-directed: the ownedPaths accuracy fix, then the two deferred
  items). Three commits (Tasks #40-#43):
  (1) ownedPaths is now BREADTH-first over simple paths (was DFS). A DFS can fill its maxPaths budget with
  long routes before reaching the short one, so its reported "shortest" could be longer than the true
  distance (the tab showed "shortest 6 hops" while the dropdown's nearestToGoal, a BFS, said 5). FIFO BFS
  makes the first goal hit a globally shortest route, so the path length now equals nearestToGoal's hops
  (confirmed on real Forest: SVC-ALFRESCO is 5, not 6). Node-expansion budget guards a dense graph. Test
  added; ad-killchain unaffected (domain captured long before any path derivation).
  (2) Faster-route cue (diff -> coach): at ingest, the shortest owned->DA length is compared against the
  prior collection's for the same owned set; if it shrank (or a route appeared), summary.diff.route =
  {now, prev} and the bridge banner leads with "A faster route to Domain Admin opened" plus a bolt-headline
  in What Changed. The coach already re-ranks on the fresh ad.attack_paths fact; this is the visible cue,
  not a ranker change. Verified headless across two Forest collections (5 hops -> 1 after a direct edge).
  (3) "Best Accounts To Hunt Next" (the marginal-value board, the standout "exceed BloodHound" view): new
  engine bestNextTargets(summary, owned) ranks the accounts you can GO GET right now (their own flags say
  how: SPN/DONT_REQ_PREAUTH/PASSWD_NOTREQD) by how many hops owning them SAVES off your current route, with
  a one-line acquisition command each. Restricted to data-indicated weaknesses so it never becomes generic
  noise; krbtgt excluded (never a real target); self-hides once nothing acquirable is left. Plus owned
  overlay (an "N owned" head badge, owned markers on the Closest board), and a "ticking is a what-if you
  can undo" note on the gate. Engine tested; UI driven headless on Forest (hunt board leads with
  SVC-ALFRESCO "opens a 5-hop route", AS-REP + Shortcut chips, acquisition command; board owned-marks once
  taken), 0 console errors. Full engine suite + browser-smoke + lint + gap all green; assets stamped; house
  style held. Remaining from this thread (not built, lower value): a full progress-aware graph overlay and a
  dedicated what-if sandbox beyond the undoable ownership toggle.
- 2026-10-08: Domain tab, the last two "exceed BloodHound" items the owner asked to finish (Tasks #44-#46).
  (1) Progress-aware graph overlay: bhgraph.renderInto now takes opts.owned + opts.reached (maps of UPPER
  short name) and colours EVERY node on the canvas by status, not just the path source: owned green, reached
  (a node an owned account already controls, computed from controls() over the owned set) a dashed accent
  ring, Domain Admin red, with a legend under the graph and a "reached" tag on the hover card. So the graph
  shows how far you have actually gotten, at a glance. (2) What-If sandbox: an EPHEMERAL hypothetical-owned
  set (_whatIf, module scope, never written to the engagement), layered on the real owned set by a new
  effectiveOwned() that now drives every derivation on the tab (route, graph, hunt, census, dropdown, inspect
  gating). "Try As What-If" on a non-owned inspect card adds it; a banner says "showing the picture as if you
  also owned X" with Commit To Engagement (moves them into the real ownedExtra) and Clear; a what-if account
  shows its walk commands under a "What-If" tag with Remove; the head carries an "N what-if" badge and the
  dropdown marks "(what-if)". Distinct from real ownership (the three doors), so a hypothesis never silently
  becomes a claim. Driven headless on Forest: Try As What-If flips the card to the walk commands + banner +
  "What-If" tag, the graph shows 1 owned + 4 reached with the legend, Commit persists SVC-ALFRESCO to
  ownedExtra and clears the banner, 0 console errors. Full engine suite + browser-smoke + lint + gap green;
  assets stamped; house style held. Presentation only: no ranker fork, one store, the what-if touches the
  engagement only on an explicit Commit.

---

## Active build: Frameworks view (ATT&CK / D3FEND / compliance / CVEs) in Findings (PR #302)

**Plan of record. If this chat is lost, resume here. Branch `claude/obol-web-overhaul-local-59ttbx`.
Commit frequently.**

### Intention

The owner saw Splunk ES map every detection across MITRE ATT&CK + Kill Chain + NIST + CIS + PCI, with
the ATT&CK matrix as the hero view (tactics columns x technique cells, coloured by coverage). Mirror
that in obol, flipped to the OFFENSIVE side: your recorded moves and minted findings light up the
exact matrix cells a blue team's Splunk would try to cover, and D3FEND / the ATT&CK detection notes
say how a defender catches each one. Dual-use and educational, deterministic, no LLM, exam-legal.

Fold into the **Findings tab** as sub-views (same sub-tab pattern as Workbench), not a new nav item.

### What already exists (do not rebuild)

- `data/findings-catalog.js` (552 findings) already carries per entry: `attack` (ATT&CK Txxxx, 55
  populated), `nist` (800-53, 87), `cwe` (286), `cve`, `remediation` (all 552), `severity`,
  `confidence`, `refs`, `match`. Schema add needed: `killchain`, `cis`, `pci` (the coverage pass).
- `OBOL.findings.assess(factSet)` -> matched findings with all those fields + `trigger_kinds` + `kev`.
  NOTE: `kev` is STUBBED (`kev = {}`) in the web edition. Un-stub it against `data/packs/cisa_kev_*`.
- Recorded moves live in `eng.activities` (the Run Log, routes/history.js). A move's produced facts
  trigger findings, so a recorded move inherits its findings' ATT&CK techniques (+ a lane default for
  pure-recon moves that mint none). That is the "recorded moves -> ATT&CK" trail, for free.
- `data/packs/cisa_kev_2026_09.json`, `known_exploits_2026_09.json` (CVE -> exploit).
- ATT&CK STIX is fetchable (raw.githubusercontent.com/mitre-attack/attack-stix-data, 53MB, 200).
  D3FEND's inference mapping is NOT cleanly extractable from its static sources (the API is GitHub
  Pages; the TTL encodes ATT&CK<->D3FEND via reified artifacts, not direct triples), so D3FEND is a
  curated compact bundle (same pattern as GTFOBins), attributed.

### Decisions locked (owner-approved)

- **Hero view first from existing data** (ATT&CK matrix + kill chain + CVE/KEV), THEN a coverage pass
  to fill attack/nist/cis/pci across the 552 findings. (Owner: "Agreed.")
- **D3FEND in v1** (not just ATT&CK's built-in detection guidance). (Owner: "D3FEND in v1.")
- Frameworks to map: MITRE ATT&CK (hero, offensive matrix), Lockheed Kill Chain, MITRE D3FEND +
  ATT&CK detection (defensive), NIST 800-53 + NIST CSF + CIS Controls v8 + PCI DSS + CWE + OWASP
  (compliance/report), CISA KEV + CVSS (vuln prioritization). PCI rendered dim/collapsed unless the
  engagement touches cardholder-data scope.
- Boundaries unchanged: presentation only, no ranker fork, one store, pack commands the source of
  truth. Reference data bundled + attributed (ATT&CK/D3FEND are MITRE; CIS; PCI SSC).

### Phases (check off as completed)

- [x] **MF0.** This plan in CLAUDE.md + tasks.
- [x] **MF1.** Reference data + engine. tools/build-attack.js -> data/attack-catalog.js (14 tactics in
  matrix order; techniques: name, tactics, detection, data_sources, mitigations, url; sub-technique
  name lookup). data/d3fend-map.js (curated ATT&CK -> D3FEND countermeasures + names, obol's technique
  set). Small fixed tables: kill-chain stages + obol-phase mapping, NIST CSF functions, CIS v8 titles,
  PCI v4 requirement titles. Un-stub KEV against the cisa_kev pack. Engine `assets/engine/frameworks.js`
  (OBOL.frameworks): from assess()+activities -> {attack matrix model, d3fend countermeasures, compliance
  rollup, cve/kev list}. Smoke test tests/engine/frameworks-smoke.js.
- [x] **MF2.** ATT&CK Matrix hero sub-view in the Findings route (tactics columns, technique cells lit
  by the engagement, Splunk-style; hover/click = technique detail: what you did, detection, mitigations).
  Sub-view nav in routes/findings.js.
- [x] **MF3.** Defensive sub-view: per technique used, the D3FEND countermeasure + ATT&CK detection and
  data sources ("how a defender catches this").
- [x] **MF4.** Compliance sub-view (NIST 800-53/CSF, CIS, PCI dim-unless-scoped, CWE, OWASP rollup) +
  CVEs & KEV sub-view (detected CVEs, KEV "actively exploited" flag, exploit availability, remediation).
- [x] **MF5.** Coverage pass: add attack/nist/cis/pci across the 552 findings + a move/lane ATT&CK map;
  verify guardrails, stamp. Screenshot-verify every sub-view desktop + mobile, 0 console errors.

### Verify each phase (same as the project)

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` ·
`node tools/gap-report.js --check` · `node tools/attack-coverage.js` (ATT&CK map integrity + gap list) ·
`for t in tests/engine/*.js; do node "$t"; done` ·
`NODE_PATH=/opt/node-tools/node_modules node tests/browser-smoke.js` ·
`node tools/stamp-assets.js` (after any asset edit) · drive the app headless (0 console errors) ·
screenshot the changed surface at desktop + mobile and read it for sense. House style: no em/en dashes.

### Status log (update per commit)

- 2026-10-08: MF0, plan documented. Confirmed: findings-catalog already carries attack/nist/cwe/cve/
  remediation; OBOL.findings.assess exposes them; KEV is stubbed (to un-stub); recorded moves are
  eng.activities; ATT&CK STIX fetchable, D3FEND to be curated.
- 2026-10-08: MF1-MF5 shipped the Frameworks view in the Findings tab (Splunk-ES style, flipped
  offensive). MF1 reference data + engine: tools/build-attack.js -> data/attack-catalog.js (ATT&CK
  Enterprise v19.2 from the STIX, 15 tactics in matrix order, 697 techniques with detection, data
  sources, mitigations, 133 KB); data/d3fend-map.js (curated ATT&CK -> D3FEND, 42 techniques/26
  countermeasures, names from the authoritative D3FEND catalog); data/frameworks-tables.js (Kill Chain
  + ATT&CK-tactic/obol-phase maps, NIST CSF + 800-53 families + family->CSF, CIS v8, PCI v4, and the
  NIST->CIS/PCI crosswalk); tools/build-kev.js -> data/kev-catalog.js (CISA KEV, 1711 CVEs, 360
  ransomware); un-stubbed the KEV overlay in findings.js; assets/engine/frameworks.js (OBOL.frameworks
  .compute: ATT&CK matrix model, kill-chain, defensive lens, compliance rollup, CVE/KEV list), smoke
  test. MF2-MF4 the UI: five sub-tabs in routes/findings.js (Findings / ATT&CK / Defensive / Compliance
  / CVEs), all driven by compute(). The ATT&CK matrix is the hero (tactics x techniques, lit by what you
  did, click a cell for detail); Defensive = D3FEND + ATT&CK detection/mitigations per used technique;
  Compliance = NIST/CIS/PCI(dim)/CWE/OWASP; CVEs = KEV-flagged, actively-exploited first. MF5 coverage,
  done DERIVATIONALLY (accurate, no mass catalog edit): data/attack-move-map.js (fact-kind -> technique)
  lights the matrix from recorded Run Log moves AND gap-fills a finding's technique from the fact that
  triggered it; the NIST->CIS/PCI crosswalk fills CIS/PCI from an authored NIST control. So coverage is
  far beyond the 55 explicitly-authored attack codes without guessing. Driven headless on a seeded
  engagement: matrix lit across 15 columns + kill-chain + cell detail with D3FEND chips; Defensive 5
  cards; Compliance CIS/PCI populated via crosswalk; CVEs 3, all KEV (PHP-CGI + two Apache), 0 console
  errors. Full engine suite + browser-smoke + lint + gap green; assets stamped; house style held.
  Remaining (future, accuracy-first): hand-author explicit attack/nist on more of the 552 catalogue
  findings to raise the authored (non-derived) coverage; the derivational layer already carries the view.
- 2026-10-08: ATT&CK matrix hover cards + detection backfill (owner-directed). (1) Cursor-following
  hover card on every matrix cell in BOTH densities (Labeled and Compact, where the squares carry no
  label): a lit cell flips what-you-did to engagement insight (the findings that mint it with severity
  + CVE/KEV, the commands you ran, its used sub-techniques, then the blue-team view: how it is detected
  and the D3FEND countermeasures that answer it); an unlit cell teaches (what it is + how a defender
  spots it). The engine's techniqueUse now returns contribution objects ({k:'f',t:title,sev,cve,kev} /
  {k:'m',t:command}); the matrix cells + defensive lens keep label arrays via a useLabels() view. Card
  lives on <body>, follows the pointer, flips to stay on-screen, fade honours prefers-reduced-motion;
  the verbose native title is dropped for an aria-label. (2) Detection backfill: ATT&CK v19.2 ships NO
  x_mitre_detection text at all (0/697, the field was dropped for detection analytics), so the hover's
  "Blue Team Detects" line and the Defensive cards were blank. Added DET_OVERRIDES in tools/build-attack.js
  (48 obol-authored blue-team detection blurbs, one per technique the Frameworks view surfaces), applied
  ONLY where ATT&CK carries none (|| fallback, so a future ATT&CK restore wins), attributed as obol's own
  content (not MITRE's) in the generated-file header. Catalog regenerated (133 -> 143 KB). All 48
  surfaceable techniques now carry detection text; 0 en/em dashes. Full engine suite + frameworks-smoke +
  browser-smoke + lint + coverage + gap green; assets stamped; driven headless at 1080p in both modes
  (0 console errors), the Detect line now renders. House style held.
- 2026-10-08: Example obol commands on grayed cells + D3FEND "what this blocks" + the coverage auditor
  (owner-directed, the whole "show students what a technique looks like, and surface lineup gaps" idea).
  Built as five commits. (1) BY_MOVE (move-id -> technique) map in attack-move-map.js: the fact-kind map
  is produce-side and cannot tell a hash dump from a hash pass or label a privesc move that produces only
  access.*, so BY_MOVE names the ACT each move performs and wins over BY_KIND. Fixed real mislabels the
  auditor surfaced (password-spray was Valid Accounts, now Password Spraying; PtH, Golden/Silver Ticket,
  crack-*, the privesc acts, web-shell plants, cloud-metadata SSRF were unmapped). techniqueUse consults
  it by the activity's action_id. (2) OBOL.frameworks.exampleCommands(technique, pack): the obol move(s)
  that perform a technique, command filled for teaching (exampleFill: known tokens substituted, unknown
  left visible, never invented), ordered earliest-phase-first (kerberoast before golden ticket). Returns
  nothing for a technique obol does not perform, so the UI stays honest. (3) UI: a grayed cell obol can
  perform carries an accent dot (shape, not just colour; aria-label says so; coverage line counts them);
  hovering it adds "In obol This Looks Like" with the filled command; clicking opens a detail panel with
  copyable commands and a "values are placeholders, pack is the source of truth" note. The hover was
  refactored into a reusable attachHover() serving both matrices. (4) D3FEND Defensive view: hovering a
  countermeasure shows the ATT&CK techniques it counters and the offensive obol command(s) it would BLOCK
  (the honest dual-use framing, obol has no defensive lineup), via the same resolver. (5) tools/attack-
  coverage.js: read-only auditor (ranker-sim pattern). Integrity gate (every BY_MOVE id, technique and
  findings attack code is real, currently clean) + the gap signal (referenced-technique example coverage,
  and the inverse: moves that produce a win but map to nothing). It flagged 51 unmapped acts; acted on 44
  unambiguous ones (the CVE RCEs -> T1210/T1190, kernel LPEs -> T1068, DB RCEs, UAC bypass -> T1548.002,
  remote logins -> T1021.x, delegation -> T1558, SID history -> T1134.005, WSUS -> T1072, COM hijack ->
  T1546.015, service DACL -> T1543.003), leaving 7 genuinely ambiguous (writable-passwd, the persistence
  moves, wildcard-injection, cred-reuse-sweep, tftp/rsync write-to-shell). Referenced techniques 59 -> 69
  (66 with an example); dotted cells on a modest engagement 31 -> 38. Detection backfill extended to every
  newly-surfaceable technique (21 added across the two map passes); 0 surfaceable techniques without
  detection, 0 em/en dashes. attack-coverage added to the verify list. frameworks-smoke extended; full
  engine suite + browser-smoke + lint + coverage + gap all green; catalog regenerated; assets stamped;
  driven headless at 1080p (grayed example hover + copyable detail panel + D3FEND "what this blocks", 0
  console errors). Presentation only: no ranker fork, one store, pack commands the source of truth.

---

## Active build: Help tab (global nav) (in progress, PR #302 branch)

**Plan of record. If this chat is lost, resume here. Branch `claude/obol-web-overhaul-local-59ttbx`.
Commit frequently.**

### Intention

obol now has 35+ surfaces (7 global nav sections, 12 engagement sub-surfaces grouped Work the Box /
Analyze / Track & Report, 11 Workbench tools, 5 Findings sub-views, the Domain tab's panels). For a
neurodivergent and disabled audience that is too much to be intuitive, and a landing-page blurb will
not carry it. Add a global **Help** tab that breaks obol down by section then sub-section, with an
index, an obol-vocabulary glossary, search, and a calm Charon quick-start, plus a context-aware "?"
on-ramp from any screen. Help answers "how do I use obol," never "how do I pentest" (that is Learn and
the field notes); Help is the MAP, Learn is the curriculum. This boundary keeps Help from becoming a
second firehose.

### Decisions locked (owner-approved)

- **Help home: triage first, index below.** Three intent cards on top (I'm new -> Charon quick-start;
  I'm working a box -> the Paste -> Next Steps -> Workbench -> Stuck? workflow; I'm looking for
  something -> index/search), then the collapsible by-section index. Same triage pattern as Stuck?.
- **Index: by section then sub-section, accordion, collapsed by default** (progressive disclosure, so
  the first screen is seven calm cards, not a wall). Each sub-section: a one-line "What it's for" + a
  "When to use it" + a Go There deep link.
- **Glossary: obol vocabulary only** (fact, move, the ledger, settled, locus, prematurity, proof-gated,
  the coach, Next Steps, Workbench, Stuck?, Loadout). Pentest jargon stays in Learn / field notes. Keeps
  the Help-vs-Learn boundary and limits authoring.
- **Charon quick-start: a calm, self-paced card path** (NOT a screen-hijacking spotlight tour). Charon
  introduces the 3-4 first things as clickable cards, at your own pace, skippable and resumable
  (progress saved per browser). Charon briefly introduces himself in character: in the old job he rowed
  the dead across the Styx for an obol a head; off the clock he moonlights here rowing the living to
  root, same fee, better company. Warm and brief; house style (no em or en dashes).
- **Context-aware "?" on-ramp: yes.** A "?" affordance that, from any screen, opens Help at that
  screen's section ("What is this?"). The Help tab is home; the "?" is the on-ramp from wherever you
  stand. The biggest discoverability win.

### Boundaries (unchanged)

- Static, browser-local, no backend, no execution, no telemetry. Presentation only: Help documents the
  app, it never changes the ranker, the move graph, the one store, or the one filler.
- Accessibility is acceptance: accordions keyboard-operable, colour never the sole signal, 11px font
  floor, `prefers-reduced-motion` honoured (the Charon orb and any shimmer), works 4K down to ~320px.
- House style: no em or en dashes; Title Case for the tab, labels, headings.

### Derive-don't-duplicate (the honesty lever)

The index SKELETON is already data: the global nav list and the ctxbar `SUBNAV` groups and the
Workbench tool list. Author the Help tree in `data/help-content.js`, then a coverage smoke test
(`tests/engine/help-coverage.js`, the guardrail) asserts every real route and nav surface has a Help
entry, so Help cannot silently drift from the app (the field-notes-coverage pattern). Half the glossary
can reuse `OBOL.pack.friendly(kind)` / `OBOL.workbench.explainKind()`; the rest is a hand-authored
supplement.

### Phases (check off as completed)

- [ ] **H1.** Help route + global nav item (desktop + mobile More sheet) + lazy group. Derived index
  accordion (sections -> subs, each a one-line What + Go There deep link), deep-linkable
  (#/help, #/help/<section>, #/help/glossary, #/help/start). Coverage smoke test. Triage cards on top.
- [ ] **H2.** Authored What / When prose per surface (field-note voice), the full Workbench and Findings
  sub-trees.
- [ ] **H3.** Glossary (obol vocabulary), reusing friendly()/explainKind() + a hand-authored supplement,
  cross-linked to the sections that use each term.
- [ ] **H4.** Search across Help (section names, sub-sections, glossary) that jumps you there; unify
  with or complement the existing nav-search.
- [ ] **H5.** Charon quick-start card path (reuse the Ferryman persona + reduced-motion gating),
  skippable and resumable, with the in-character intro.
- [ ] **H6.** Context-aware "?" on-ramp in the header that opens Help at the current screen's section.

### Verify each phase (same as the project)

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` · `node tools/gap-report.js
--check` · `node tools/attack-coverage.js` · `node tools/help-coverage.js` (once H1 lands) ·
`for t in tests/engine/*.js; do node "$t"; done` · `NODE_PATH=/opt/node-tools/node_modules node
tests/browser-smoke.js` · `node tools/stamp-assets.js` (after any asset edit) · drive the app headless
(0 console errors) · screenshot the Help surface at desktop + mobile and read it for sense. House
style: no em/en dashes.

### Status log (update per commit)

- 2026-10-08: H0, plan documented. Nav inventory confirmed (7 global; SUBNAV groups Work the box /
  Analyze / Track & report in ctxbar.js; 10-11 Workbench tools; 5 Findings sub-views). Owner locked:
  triage+index home, obol-vocabulary glossary, calm Charon card-path quick-start with an in-character
  moonlighting intro, context-aware "?" on-ramp.
- 2026-10-08: H1 shipped the Help tab skeleton. New global route assets/ui/routes/help.js + content in
  data/help-content.js (OBOL.HELP: triage, sections, glossary, quickstart, Charon intro), lazy `help`
  group, Help in the primary nav and the mobile More sheet. Three sub-views (Index / Quick Start /
  Glossary), deep-linkable: #/help, #/help/<sectionId> (Index with that section open + scrolled),
  #/help/start, #/help/glossary. Index = three triage cards (I Am New / Working A Box / Looking For
  Something) over a collapsible <details> accordion of all 9 top sections (Engagements with its Work
  the Box / Analyze / Track & Report groups, Learn, Loadout, Tools, Workbench with its 10 tools, Stuck?,
  Playbooks, Paste, Search), each row a one-line What + a Go There deep link (Findings sub-views carry a
  `set` that flips eng.ui.findingsView before navigating). Quick Start = Charon's glowing orb + his
  in-character moonlighting intro + the four first-things cards. Glossary = 10 obol-vocabulary terms
  (H3 expands). Coverage guardrail tests/engine/help-coverage.js asserts every real nav surface + every
  Workbench tool + every Findings sub-view has an entry, and no em/en dashes (added to the verify list).
  Fixed a self-caught bug: the triage cards reused the .help-go class whose white-space:nowrap made the
  body text overflow and overlap; decoupled behavior (bind [data-goto]) from styling. Driven headless at
  1920 and 390 wide: 3 triage, 9 sections, 27 sub-rows, deep-link opens Workbench's 10 tool rows, Quick
  Start 4 cards + orb, Glossary 10 terms, 0 console errors both sizes. Full engine suite + help-coverage
  + browser-smoke + lint + gap green; assets stamped; house style held.
- 2026-10-08: H6, the context-aware "?" on-ramp. A new "?" button in the header (visible desktop and
  mobile, beside Paste and Search) opens Help at the section explaining the CURRENT screen: every
  engagement surface (Hub, Next Steps, Evidence, Map, Domain, Creds, Checklist, Findings, Run Log,
  Scoreboard, Report, and the graph/target routes) maps to the one Engagements Help section; a global
  surface (Workbench, Tools, Stuck?, Playbooks, Learn, Loadout) maps to its own. Wired in mobile.js
  (helpTargetForRoute reads the route and returns the #/help/<section> deep link, which H1 made open and
  scroll that section). The Help tab browses; the "?" explains where you stand. Driven headless: from
  /path it opens #/help/engagements (section open), from /workbench #/help/workbench (section open),
  visible on desktop and mobile, 0 console errors; mobile header not crowded. browser-smoke + help-
  coverage green; assets stamped; house style held. Remaining: H2 (deepen per-surface prose), H3
  (expand glossary), H4 (Help search), H5 (make the Charon quick-start a resumable stepped path).

---

## Active build: Cruise (was Playbooks) global tab (in progress, PR #302 branch)

**Plan of record. If this chat is lost, resume here. Branch `claude/obol-web-overhaul-local-59ttbx`.
Commit frequently.** Marked **Experimental** in the UI (fine print under the nav label).

### Intention

Bring obol-local's **cruise control** concept to obol_web, exam-legally and without execution. In
obol-local, cruise is a supervised auto-advance loop: drain async facts, re-rank the move frontier,
run the single top SAFE move through the real runner, re-rank, and STOP at the first move that needs
approval / is manual / is objective-complete, emitting a resumable "pause briefing." obol_web cannot
and must not execute. So obol_web's Cruise is the same loop with the HUMAN as the execution channel:
obol hands you a phase-scoped batch script, you run it on your Kali box, you paste the output back,
facts update, and the next batch generates, round after round, until flags. The Playbooks tab (static
pre-authored runbooks) is reworked into Cruise; the curated runbooks live on inside it as "Recipes."

### The ONE reframe (why cruise here is a BATCH, not one-move-at-a-time)

obol-local runs exactly one move per iteration because command execution is free and instant there,
so re-ranking after every command is optimal. In obol_web the expensive operation is the PASTE
round-trip (run, copy, switch windows, paste). One-move-at-a-time would be unusable. So obol_web
cruise batches the moves that are INDEPENDENT of each other's output and checkpoints where output
genuinely changes what comes next. That batch is a **frontier cut** over the move graph, derivable
from data we already have (`requires_*` / `produces`): the batch = eligible, mode-permitted moves
whose required inputs are already satisfied, MINUS any move that requires a fact-kind another
EARLIER-ranked batched move produces (those dependents defer to the next round, after the paste).
This is the reconciliation of the owner's "phase-oriented script that does several steps at once"
with obol-local's "re-rank between steps": independent steps now, dependent steps next.

### Exam-legal by construction (the load-bearing rule)

OSCP bans automated exploitation and mass scanners. Cruise stays legal because it only ever BATCHES
SAFE ENUMERATION and ALWAYS checkpoints before anything that lands a shell, sprays/brutes creds, or
fires an exploit. The human reviews and runs every command; obol never executes. Batches are scoped
to KNOWN hosts/facts, never a /24 sweep. This mirrors obol-local's `exam` mode (autopwn impossible,
stop at manual). Two modes (owner-approved, lab explicitly wanted):

- **Exam (default):** batch only `safe`-tier moves (explicit `autonomy:auto`, or phase recon/enum
  that does not produce a foothold and is not a spray/brute). Everything else is a checkpoint.
- **Lab (opt-in, labeled "not exam-legal"):** also batch `active`-tier moves (explicit
  `autonomy:approve`, foothold/safe-exploit setup), pushing past a foothold. Still stops at
  `manual`-tier and at anything a batched move's output is a prerequisite for.

Tier classifier `cruise.tierOf(action)`: explicit `action.autonomy` wins (auto->safe, approve->
active, manual->manual); else derive from phase + produces (foothold-producer or phase
access/escalate/loot or a spray/brute id -> active or manual; recon/enum -> safe). ~143/312 pack
actions carry explicit autonomy; the derivation covers the rest.

### Self-delimiting script (the highest-leverage detail)

The generated cruise script emits an `echo "===== OBOL STEP n: <id> ====="` marker before each
command, so the pasted-back blob is self-segmenting and each output chunk attributes to the move that
produced it, with no dependence on the Loadout prompt-stamp. Plus the usual parameterized `$VAR`
header, `set -o pipefail`, and `tee` logging (reuse `OBOL.playbook` variabilization). The script is a
copy/download artifact the human runs; obol never runs it.

### Pivot auto-setup (later phase, highest value + risk)

Feasible because `arsenal.js` gives the checksum-verified cached agent binary + path, the machine
profile says what's installed, and facts give target/creds/lhost. Port obol-local's TRANSPORT_HALVES
as data (which half runs locally vs on the target per transport: ligolo = proxy local + agent staged
on target; chisel = server local + client on target; sshuttle/ssh-forward = all local; netsh = all
on target). Emit a script that does both halves + a liveness check + fallback egress ports; on
failure the operator pastes output and obol regenerates. Best-effort + checkpoint. Deferred to CR3.

### Boundaries (unchanged)

Static, browser-local, no backend, no execution, no telemetry. Presentation only: Cruise is a view
over the ONE store, the fact ledger, `OBOL.pack.rankActions`, and `OBOL.command` filler. It never
forks the ranker or rewrites the move graph. Pack commands stay the source of truth. Accessibility is
acceptance (neon glass, colour never the sole signal, 11px floor, prefers-reduced-motion, 4K to
~320px). House style: no em or en dashes; Title Case.

### Aesthetic

Colourful neon glass like Learn / Hub / Creds / Checklist (the `.cv-shead`/`--sh` hue pattern): the
mode toggle, the phase-batch header band (per-phase hue via the phase colour tokens), the batch
command rows, the checkpoint card, and the briefing. Multicolor, glowing, not monochrome green.

### Engine API (assets/engine/cruise.js, pure, Node-safe, tested)

- `OBOL.cruise.MODES` = ['exam','lab']; `tierOf(action)` -> 'safe'|'active'|'manual';
  `allowsTier(mode, tier)`.
- `OBOL.cruise.plan(facts, pack, opts)` where opts = {mode, doneIds, cap} ->
  `{ mode, phase, frontier, batch:[{action, cmdIndex}], deferred:[{action, waitsOn}], checkpoint:
  {action, reason, tier} | null, counts }`. batch = frontier cut (above). checkpoint = the top ranked
  move NOT permitted by the mode (what you stop before), with a plain-language reason.
- `OBOL.cruise.buildScript(batch, ctx)` -> the self-delimiting bash (markers + vars + tee log).
- Smoke test tests/engine/cruise-smoke.js: exam batch is enum-only, a foothold-producer is never in
  an exam batch (is the checkpoint), lab batches further, a dependent move defers, script has the
  shebang + step markers + no `{{token}}` leaks.

### Phases (check off as completed)

- [x] **CR0.** This plan in CLAUDE.md.
- [x] **CR1.** Engine assets/engine/cruise.js (plan/tierOf/buildScript) + cruise-smoke.js.
- [x] **CR2.** Route assets/ui/routes/cruise.js: nav rename Playbooks -> Cruise (+ Experimental fine
  print), lazy group, neon-glass UI (mode toggle, phase-batch header, reviewable batch commands with
  copy/download/copy-all, paste-back that ingests + regenerates, checkpoint card, briefing), curated
  runbooks folded in as a "Recipes" section. Help entry + coverage updated. Deep-link #/cruise
  (#/playbooks kept as an alias).
- [ ] **CR3.** Pivot auto-setup scripts (arsenal + profile + TRANSPORT_HALVES). Later.

### Verify each phase (same as the project)

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` · `node tools/gap-report.js
--check` · `node tools/attack-coverage.js` · `node tests/engine/help-coverage.js` ·
`for t in tests/engine/*.js; do node "$t"; done` · `NODE_PATH=/opt/node-tools/node_modules node
tests/browser-smoke.js` · `node tools/stamp-assets.js` (after any asset edit) · drive the app headless
(0 console errors) · screenshot Cruise at desktop + mobile and read it for sense. House style: no
em/en dashes.

### Status log (update per commit)

- 2026-10-09: CR0, plan documented. Grounded in a full read of obol-local cruise.py/moves.py/
  autonomy.py/phases.py/dispatch.py and obol_web's existing primitives (rankActions pure; arsenal
  cache + machine profile; playbook.js variabilizer; quickpaste ingest loop). Confirmed the reframe
  (batch = frontier cut, not one-at-a-time, because the paste round-trip is the expensive op) and the
  exam-legal rule (batch safe enumeration only, checkpoint before shell/spray/exploit).
- 2026-10-09: CR1 + CR2 shipped. Engine assets/engine/cruise.js (tierOf classifier: explicit pack
  autonomy wins, else derive from phase + produces, foothold-producers and spray/brute ids are never
  safe; plan() = mode-gated batch of eligible moves + the top not-permitted move as the checkpoint +
  a forward-looking "unlocks" preview from lockedActions whose unmet prereq a batched move produces;
  buildScript() = self-delimiting bash with ===== OBOL STEP markers, $VAR header, tee log, mode
  caveat). cruise-smoke.js green (tier classifier, exam-is-enum-only, foothold-is-the-checkpoint, lab
  batches further, unlocks preview, script markers + no token leaks). Route assets/ui/routes/cruise.js:
  neon-glass UI (gold Experimental pill, Exam/Lab mode toggle persisted in eng.ui.cruiseMode, the
  1-2-3-4 loop strip, per-phase-hue batch band with Copy All + Download .sh, safe/active/manual tier
  chips, teal unlocks strip, gold checkpoint card with a Switch-To-Lab shortcut, inline paste-back that
  ingests + re-renders, curated runbooks folded in as a collapsed Recipes section reusing
  OBOL.cruise.buildScript). Nav: Playbooks -> Cruise with an Experimental sub-label (data-nav-match
  keeps #/playbooks highlighting Cruise); mobile More sheet updated; lazy `cruise` group added and the
  route registered (#/playbooks kept registered as an alias). Help entry + help-coverage updated
  (playbooks -> cruise). Driven headless at 1500 and 390: nav shows Cruise + Experimental, exam batch
  5 steps enum-only with the SMB-share checkpoint, lab 9 steps, unlocks + paste + recipes present, 0
  console errors both sizes. Full engine suite + cruise-smoke + help-coverage + browser-smoke + lint +
  gap all green; assets stamped; house style held. CR3 (pivot auto-setup) deferred.
