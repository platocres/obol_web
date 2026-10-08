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
