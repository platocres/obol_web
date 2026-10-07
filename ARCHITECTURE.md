# Obol Web Architecture

This document explains how Obol web is put together and why. It is for anyone who wants to
understand, audit, or extend the technical side of the project. For the move/ranking contract
specifically, read [docs/MOVE-ENGINE.md](docs/MOVE-ENGINE.md); for the operator-facing tour, read
[README.md](README.md); for the agent working rules, read [AGENTS.md](AGENTS.md).

Obol web is the static-site edition of `obol-local`. The engine is ported faithfully from the
Python source and kept at behavior parity; the test suites encode that parity.

---

## 1. What It Is, And The Non-Negotiable Contract

Obol is a browser-local OSCP/pentest-prep companion. The operator hacks in their own terminal;
Obol watches what they have proven about a box, ranks the next commands worth running, remembers
everything, draws the attack path, and assembles the report.

Five hard constraints shape every design decision:

- **No backend.** There is no server, no API, no account. The whole app is static files served as
  is. The live site is GitHub Pages serving `main` verbatim.
- **No build step to run.** Opening `index.html` from disk (`file://`) runs the full app. Build
  tooling exists only to generate bundled data and cache-bust stamps, never to produce a runtime
  artifact the browser could not run without it.
- **No command execution.** Obol generates commands for a human to run externally. It never runs
  anything against a target. "A run is not a win."
- **No telemetry.** Nothing the operator types leaves the browser. All state lives in the
  operator's own IndexedDB.
- **Conservative evidence boundaries.** Parsers never invent a fact. An open port is not a shell;
  a crackable hash is not a login. The engine only asserts what the pasted tool output actually
  proves.

Accessibility is an acceptance criterion, not polish: the audience includes neurodivergent and
disabled learners. Colour is never the sole signal, surfaces are keyboard reachable, the font floor
is 11px, `prefers-reduced-motion` is honoured, and layouts work from 4K down to roughly 320px.

House style: no em or en dashes anywhere; Title Case for UI labels, tabs, and headings.

---

## 2. The Core Idea: Facts, Moves, Goals

Everything in Obol is a projection of one small graph.

```
          requires_all / requires_any                 produces
   FACTS  ───────────────────────────►   MOVES   ───────────────────►  FACTS
 (what you          (eligibility, the           (the facts a move          (new facts feed
  have proven)       move's in-edges)            mints when it lands,        the next moves)
                                                 its out-edges, honest)
```

- A **Fact** is one thing the operator has proven about a target (a port is open, a credential
  works, a hostname). Facts are the single source of truth.
- A **Move** is a methodology branch expressed as data: it declares the facts that make it eligible
  (`requires_all` / `requires_any`), the facts it mints when it lands (`produces`), and metadata
  (phase, locus, priority, commands, report finding). Moves live in `data/packs/*.json`.
- **Goals** are the terminal facts worth reaching (a flag, SYSTEM/root/admin, NTDS secrets).

From this one graph the engine computes: the ranked next moves (the coach), the lowest-cost route
to a goal (the planner), the attack-path graph, the compromise chain, and the report. Adding a move
is adding a node with honest edges; the engine figures out where it belongs. That rule (a move must
be rankable from its own honest declaration) is what keeps ranking correct as the pack grows, and
it is enforced mechanically by the lints and the golden-path corpus (see Section 9).

---

## 3. Layered Architecture At A Glance

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  UI layer  (assets/ui/*, DOM + IndexedDB, browser only)                   │
  │  shell · router · lazy loader · routes · evidence ingest · store          │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  Pure engine  (assets/engine/*, runs in window / Web Worker / Node)       │
  │  facts · phases · pack+planner · command · parsers · findings · resolve   │
  │  graph · chain · engmap · bloodhound · report · study · toolbuilder …     │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  Data  (data/*, bundled JSON generated from source)                       │
  │  packs (moves) · field-notes · findings-catalog · narratives · gtfobins   │
  │  study-fixtures · toolset · decision-forks · parser-signatures …          │
  └─────────────────────────────────────────────────────────────────────────┘
```

The sharp line is between the **pure engine** and the **UI**. Everything under `assets/engine/*`
is dependency-free JavaScript that runs identically in the window, in a Web Worker, and in Node
(the test suites import it directly). It touches no DOM, no `window`-only API, no network. The UI
layer under `assets/ui/*` is the only code that touches the DOM, IndexedDB, and the hash router.

### Boot order (the critical path)

`index.html` loads the engine core and a few home surfaces up front, then everything else lazily.
The up-front order (from `index.html`) is:

```
engine:  facts → phases → pack → profile → command → workspace → vfs → loot → chain
data:    findings-catalog → narratives → packs-bundle → tools-install → tunnels →
         pivot-troubleshooter → field-notes → tool-staging → gtfobins
engine:  findings → pivotdoctor → packs → resolve
ui:      util → icons → mobile → factpick → store → credbar → ctxbar → quickpaste →
         chainview → graphview → graphtip → ingest → router → lazy → palette
routes:  home → targets → evidence → path            (only the first surfaces up front)
ui:      boot → backdrop → coin → settings
```

Every other route (Workbench, Report, Domain/BloodHound, Study, Tools, Graph, Map, Findings,
Checklist, History, Scoreboard, per-target view) is lazy-loaded on first navigation by
`assets/ui/lazy.js`, which injects `<script>` tags on demand (this works over `file://`, unlike
`fetch`). A group that fails to load degrades to a "coming online" placeholder and is retried on
the next navigation.

---

## 4. The Pure Engine (`assets/engine/`)

### 4.1 The fact ledger: `facts.js`

The foundation. A `Fact` has:

- `kind`: a dotted type, e.g. `smb.reachable`, `credential.available`, `host.hostname`.
- `scope`: `host:10.10.10.10` or `domain:corp.local`.
- `value`: an arbitrary payload (the port, the username, the hash, the headers).
- `state`: a `ProofState`: `supported` (evidence established it), `refuted` (evidence establishes
  it is not so), or `inconclusive` (attempted, ambiguous, no claim earned).
- `source`, `created_at`: provenance and a timestamp (the ranker's recency signal reads this).

`FactSet` is the queryable collection: `has(kind)` ("is this proven?"), `values(kind)` (the
payloads of every supported fact of that kind), `kinds()` (the set of proven kinds). The whole
engine asks the ledger these two questions. Facts dedupe on `(kind, scope, claim)`; the UI collapses
repeat observations into one row with an `xN` count.

### 4.2 The phase model: `phases.js`

One projection shared by the planner and the graph. Phases order an engagement:
`recon → enum → creds → access → escalate → loot`. Each move resolves to a phase (explicit, or
derived from the maximum phase of its `produces`). `targetPhase(facts)` is the furthest phase any
proven fact reaches; `frontierIndex` is that plus one (capped). The v1 ranker and the graph use this;
the live v2 ranker uses it as a sort input but tiers primarily by recency (Section 4.3).

### 4.3 Moves and the planner: `pack.js` (+ `packs.js`)

`pack.js` is the heart. It defines the `Action` class (a loaded move) and the two consumers of the
fact/move graph.

**The `Action`** carries everything a move declares plus derived fields:

- Eligibility: `requires_all`, `requires_any`; `eligible(facts)`, `settled(facts)` (every produced
  kind already proven), `obsolete(facts)` (a later achievement makes it moot).
- `locus`: **R** (remote, run from Kali), **F** (on-host one-shot), **I** (interactive on-host).
  Derived from the tool/gates if omitted. Remote is preferred, always.
- `scope`: `oscp` / `oscp+` / `beyond`, a newcomer-safe syllabus lens, derived from id/tool/gates.
- `priority`: a hand-tuned tiebreak, deliberately kept weak; `effectivePriority` subtracts a
  penalty when a `deprioritize_when` fact makes the move a side-quest.
- `commands[]`: the copy-ready command templates (with `{{token}}` placeholders), plus per-command
  metadata such as `tool`, `note`, `web` variant, `settled_by`, `sequence`.

**`rankActions` / `nextActionsV2`**, the coach's ranker. It orders eligible, non-settled,
non-obsolete moves by, in order:

1. **tier** (recency): a move that *just* became possible from the latest ingest batch leads;
   speculative "try-if-vulnerable" moves are capped below evidenced ones.
2. two bounded "prep before use" tie-breaks inside the fresh tier: **recon-first** at the opening
   (finish the service scan before enumerating) and **validate-first** (confirm a found credential
   before spending it).
3. **score**: goal-distance progress + 1-step enablement + a **keystone** term (breadth of doors a
   move's facts unblock, goal-tempered and capped), all weighted by reliability.
4. **priority** (hand-tuned tiebreak), then a **house-toolkit** tiebreak (prefer NetExec), then
   **locus** (remote-first), then id (stable).

The design intent is to move structural value into the wiring (enablement, keystone) and shrink the
hand-tuned priority over time. `docs/MOVE-ENGINE.md` is the authoritative description.

**`planPath`**, an A* search for the lowest-cost dependable route from the current facts to any
goal. Costs encode preference: an evidenced step is 1, an ordinary step 1.5, a privilege shortcut 8,
a speculative move 12, plus a small locus surcharge so the route prefers Kali-side steps. Returns a
path or an honest "not reachable from here".

`packs.js` loads the deduped `Action` list from the generated `OBOL.packData` global and caches it;
`OBOL.packs.actions()` is the one accessor the rest of the app uses.

### 4.4 Command templating: `command.js`

Builds a `{{token}}` context from proven facts plus engagement params (`fillAll`, `fillCommand`),
then renders a template into a ready-to-run command. It is identity-coherent: it never pairs one
credential's username with another's secret, and it prefers a cracked/validated credential, the
discovered ports (`nmap_ports`), the located loot file, and so on. The UI reads which tokens remain
unfilled to decide whether a command is runnable yet (see the gating in Section 6).

### 4.5 Filesystem modeling: `workspace.js`, `vfs.js`, `loot.js`

Obol cannot read the operator's Kali disk, but it models it. `workspace.js` represents the working
directory the operator runs from (the scaffold `mkdir -p <root>/{scans,loot,...} && cd <root>`, and
relative output tokens like `scandir`/`lootdir` so a generated command writes into it correctly).
`vfs.js` is the virtual workspace that knows what files should exist where. `loot.js` is the
fact-to-file glue for command tokens (the AD-chain seam, e.g. the userlist handed between moves).

### 4.6 The parser pipeline: `parsers/`

The only way facts enter the ledger from tool output. `parsers/index.js` is a command-keyed
dispatcher: `OBOL.parsers.parseActionOutput({command, stdout, scope, ...})` routes one paste to
every parser its command/content warrants, non-destructively (it returns minted facts; it never
writes to the store). `parsers/common.js` holds the shared compiled regexes, scoping helpers, and
fact-construction utilities. The per-protocol parsers are conservative by construction:

- `nmap.js` (XML-first via DOMParser when available, else text regexes), `host.js`, `services.js`,
  `shape.js` (generic response-shape), `dns.js`.
- `directory.js` (nxc/LDAP/SMB enumeration and auth validation), `nxc-catalog.js` (the NetExec
  capability map), `creds.js` (cracked/dumped/brute credentials), `database.js`, `web.js`,
  `websource.js`, `pivot.js`, `findings.js`.
- `blockers.js`: the "cryptic wall" detectors: a pasted failure (host-seems-down, CRLF, AMSI,
  clock skew, lockout, SMB signing required, rate limit) mints a `blocker.*` fact so the matching
  fix surfaces reactively.

The guiding rule: a parser mints a fact only when the output affirmatively shows it. Which kinds
each parser is allowed to emit is declared in `data/parser-signatures.js` and checked by the
gap-report (Section 9), so a new mint cannot drift from its signature.

### 4.7 Findings and narratives: `findings.js` (+ `data/findings-catalog.js`, `data/narratives.js`)

A fact-driven projection that matches the findings catalog against the current fact set and produces
report-ready findings (title, severity, category, remediation). `narratives.js` supplies the
plain-language "what this proves / why it matters" lines the coach and Explain Output reuse.

### 4.8 The reference resolver: `resolve.js` (+ `data/gtfobins.js`)

Turns a fact into the exact, pre-filled answer rather than a generic link: the GTFOBins sudo/SUID
escape for the binary the operator actually found, the hashcat mode for the hash they hold. GTFOBins
data (GPL-3.0, attributed) is bundled as compact JSON.

### 4.9 Projections: `graph.js`, `chain.js`, `engmap.js`

All read-only views of the same facts+pack. `graph.js` projects the attack path as a self-contained
inline SVG (phase columns left to right, proven vs. unlocked nodes). `chain.js` reconstructs the
ordered compromise chain for a host ("this led to that, all the way to the flags"). `engmap.js` is
the whole-engagement map (targets, scope, credentials, subnets, pivots).

### 4.10 BloodHound: `bloodhound.js` (+ `workers/bloodhound-worker.js`)

Ingests a SharpHound/BloodHound-CE export into an engagement-wide domain overlay and attack-path
intel. The heavy parse runs in a Web Worker (the same pure engine code), which is why the engine
must stay DOM-free.

### 4.11 Report, Study, Tools, Workbench

- `report.js` assembles the OSCP-style report (ported from the Python `report.py` and the report
  profiles) and exports Markdown/HTML/PDF/Word with the required proof discipline and redaction.
- `study.js` is Study mode's engine half: pure functions over the loaded packs plus `ARSENAL` and
  the embedded sample outputs, with an evidence index that must cover every move (a CI-gated guard).
- `toolbuilder.js` is the command compiler behind the Tools builders.
- `workbench.js` is the engine behind the Workbench: the reverse-shell catalogue and base64 /
  PowerShell `-EncodedCommand` runner, the hash identifier, the encoder, the JWT decoder, the
  GTFOBins browser, the wordlist picker, the manual-SQLi builder, Explain Output, the spray planner.
  It is a view over `OBOL.store`, the fact ledger, and the command filler. It enriches presentation
  only; it never rewrites the move graph.

---

## 5. The Data Layer (`data/`)

Data is split into hand-authored source and generated bundles.

### 5.1 Methodology packs (the move set)

- **Source of truth:** `data/packs/*.json` (one file per lane: recon, ad, web, linux_privesc,
  windows_privesc, credential_access, cracking, database, pivoting, shells, findings_checks,
  web_exploit_checks, known_exploits, obol_flag_hunt, and more). These are vendored at parity with
  obol-local; the owner has sanctioned selective deviation where obol_web needs it.
- **Generated bundle:** `data/packs-bundle.js` (the `OBOL.packData` global), produced by
  `node tools/build-packs.js`. Do not edit it by hand; regenerate after editing the source JSON. CI
  checks it is in sync.

### 5.2 Other data

- `field-notes.js`: the per-command When / How To Land It / What To Look For / win / Common
  Mistakes notes (learner-first voice). 100% authored coverage across every move is a tracked goal.
- `findings-catalog.js`, `narratives.js`, the findings projection data.
- `study-fixtures.js`: hand-written, coherence-vetted teaching content and sample outputs for
  Study mode; every move must appear under an evidence entry.
- `gtfobins.js`: the bundled GTFOBins corpus.
- `toolset.js`, `tools-install.js`, `tool-staging.js`, the Tool Builder / Loadout data.
- `decision-forks.js`, `parser-signatures.js`, `coverage-expected.js`, `flag-reach.js`, the
  decision-map and gap-report ground truth (what parsers emit, which moves hand off to which,
  reachability of the flag from every port).
- `playbooks-bundle.js` (from `data/playbooks/`), `reportmeta.js`, `tunnels.js`,
  `pivot-troubleshooter.js`, `narratives.js`.

---

## 6. The UI Layer (`assets/ui/`)

### 6.1 Store: `store.js`

The browser database. IndexedDB is the primary store (async, structured, roomy), fronted by an
in-memory cache so synchronous reads stay fast. It holds engagements, each with its target list,
fact ledger, params, profile, workspace, and activity log. `addFacts` is the single write path for
facts; it dedupes, reflects a proven hostname onto the matching target record, persists, and emits a
change event that re-renders the active route. There is one store and one filler; the Workbench and
every surface are views over it, never forked state.

### 6.2 Router and lazy loader: `router.js`, `lazy.js`

A tiny deterministic hash router. Each navigation renders the target route into `#view` exactly
once (no timed double-paints, ever). `lazy.js` registers placeholder routes that load their script
group on first navigation then delegate to the real route.

### 6.3 Evidence ingest: `ingest.js` + the Evidence route

`ingest.js` is the shared, DOM-free ingest core: it derives the command from a raw terminal paste,
runs the conservative parsers, mints only proven facts, and stores them (via `store.addFacts`), which
re-ranks the coach. The Evidence route and the per-card "Paste Output" boxes both call it. A
full-terminal paste routes on its own prompt/command line, so any tool's output mints its facts from
any box.

### 6.4 Routes and the shell: `routes/`, `boot.js`

`boot.js` inits the store, wires the shell (the engagement picker, the params/credential bars, the
facts panel), registers routes, and starts the router. The routes are the surfaces:

- `path.js`: Next Steps (the coach): the ranked card grid plus the field-notes canvas. It is the
  main consumer of the ranker and owns the within-move command presentation: the default command
  pick (house-toolkit and switchless-probe aware), the settled-command drop-out, and the
  progressive **gating** that hides a command whose earned tokens (base DN, domain, a credential,
  the scanned ports) are not yet proven, behind a single "more unlocks once you have ..." line.
- `home.js` (the Hub), `targets.js` / `target.js`, `evidence.js`, `report.js`, `domain.js`
  (BloodHound), `map.js`, `graph.js`, `study.js`, `tools.js`, `loadout.js`, `workbench.js`,
  `findings.js`, `creds.js`, `checklist.js`, `scoreboard.js`, `history.js`, `playbooks.js`.

All "what's my next move?" surfaces rank through the one shared `OBOL.coach.rankFor(facts)` in
`path.js`. No surface re-implements ranking.

---

## 7. The Evidence Loop (how a paste becomes guidance)

```
 operator pastes tool output
        │
        ▼
 ingest.deriveCommand ─► parsers.parseActionOutput ─► minted facts (conservative)
        │                                                     │
        │                                                     ▼
        │                                           store.addFacts (dedupe, sync, persist)
        │                                                     │
        ▼                                                     ▼
   activity log                                       emit('facts') ─► active route re-renders
                                                              │
                                                              ▼
                                       rankActions / rankFor re-orders the coach, the graph
                                       re-projects, the report updates, new moves unlock
```

Each paste advances the whole app through one pure recomputation. Nothing is remembered that the
output did not prove.

---

## 8. The Coach Ranker, Concretely

The live ranker (`nextActionsV2`) sorts eligible, non-settled, non-obsolete moves by:

1. **tier**, recency (just-unlocked leads), with speculative payoffs capped.
2. **recon-first** (opening only) and **validate-first** (unvalidated credential held), bounded
   "prep before use" tie-breaks inside the fresh tier.
3. **score**, `reliability * (goalProgress + 0.6*enable + keystoneW*keystone)` + objective pull.
4. **priority** (hand-tuned) → **house toolkit** (prefer nxc) → **locus** (remote-first) → **id**.

`path.js` then buckets the ranked list into Ready Now, Coming Up (eligible but ahead of the
frontier, or no runnable command yet), and Report Checks (info-only writeup checks), and applies the
syllabus lens. Trap-doctor moves (gated on a pasted `blocker.*`) surface reactively in the
field-notes canvas, not as cards.

The operator preferences baked in: **remote-first always**, and **prefer NetExec to its fullest**
(one remote tool spanning SMB/LDAP/WinRM/MSSQL/RDP/WMI/SSH for cred validation, enumeration,
pass-the-hash exec, and secret dumping). See `docs/MOVE-ENGINE.md` for the full rationale and the
lints that enforce it.

---

## 9. Guardrails And Verification

Correctness is enforced mechanically, not by running labs. The pillars:

- **`tools/move-lint.js --check`**, the move contract, sharing the ranker's own fact
  classification. Catches: unresolvable fields, info-dead-ends that would headline a live box,
  nxc-first violations, nxc teach-vs-rank coverage gaps, self-satisfied moves, unindicated payoffs.
- **`tools/gap-report.js --check`**, decision-map graph truth: unreachable moves, missing
  hand-offs, and parser signature drift (every static `mkFact` kind must be declared in
  `data/parser-signatures.js`).
- **`tools/field-notes-coverage.js`**, **`tools/lint-study.js --check`**, content coverage and
  study lints.
- **`tests/engine/*.js`**, the pure engine test suite (facts, ranker, parsers, planner, chain,
  bloodhound, report, study, workbench, and the per-concern smokes). Runs in plain Node.
- **`tests/engine/corpus/*.json` + `corpus-smoke.js`**, golden-path box walkthroughs. Each step
  declares the facts it adds and the move that should be #1 after it, so a mis-rank is a failing
  test. Walked a box? Encode it here.
- **`tests/browser-smoke.js`**, a headless-Chromium smoke of the real app (needs Playwright +
  Chromium at `/opt/node-tools/node_modules`, Chromium pre-installed). Fails on any console error.
- **`tools/stamp-assets.js`**, after editing ANY asset, refreshes the content-hash cache-bust
  (`?v=...`) on every `<script>`/`<link>` in `index.html`. CI checks `index.html` is stamped in
  sync. This matters because GitHub Pages serves `main` verbatim with a ~10-minute cache; without
  the stamp a deploy can leave a stale bundle running against a fresh parser.

CI (`.github/workflows/ci.yml`) syntax-checks every file, regenerates and diffs the packs bundle,
runs the engine tests and the browser smoke, and verifies the asset stamp.

The full local verify loop (from AGENTS.md / CLAUDE.md):

```
node tools/field-notes-coverage.js
node tools/lint-study.js --check
node tools/gap-report.js --check
node tools/move-lint.js --check
for t in tests/engine/*.js; do node "$t"; done
NODE_PATH=/opt/node-tools/node_modules node tests/browser-smoke.js
node tools/stamp-assets.js            # after any asset edit
# then drive the app headless (0 console errors) and screenshot the changed surface
```

---

## 10. Build Pipeline And Deployment

There is no runtime build. The generators turn hand-authored source into bundled globals:

- `tools/build-packs.js`: `data/packs/*.json` → `data/packs-bundle.js`.
- `tools/build-gtfobins.js`: GTFOBins source → `data/gtfobins.js`.
- `tools/build-playbooks.js`: `data/playbooks/` → `data/playbooks-bundle.js`.
- `tools/stamp-assets.js`: content-hash cache-bust stamps in `index.html`.

Deployment is GitHub Pages serving `main` as static files. Because an underscore-prefixed file is
dropped by Pages/Jekyll, the shared parser common module is named `common.js` (not `_common.js`).

---

## 11. Extending The System

- **Add a move:** add a node to the right `data/packs/*.json` with honest `requires_*` / `produces`
  and a command, regenerate the bundle, and let the engine rank it. Read `docs/MOVE-ENGINE.md`
  first, then run the move-lint, gap-report, and corpus. Author its field note
  (`data/field-notes.js`) and its study-fixtures evidence entry.
- **Add a parser / a new fact kind:** mint it in the right `parsers/*.js`, declare the emitted kind
  in `data/parser-signatures.js`, and register a terminal/consumer so it is not a dead-end. The
  gap-report `--verify` cross-checks the signatures against what the parsers actually emit.
- **Add a surface that shows "next move":** call `OBOL.coach.rankFor(facts)`. Never re-implement
  ranking.
- **Keep the engine pure.** Anything under `assets/engine/*` must run in the window, a Web Worker,
  and Node. No DOM, no network, no `window`-only API.

---

## 12. Directory Map

```
index.html                 the app; critical boot path + lazy route registration
AGENTS.md                  agent entrypoint + working rules
README.md                  operator-facing tour
CLAUDE.md                  the active build's plan of record + status log
docs/
  MOVE-ENGINE.md           the move/ranking contract (read before touching moves)
  DECISION-MAP.md          the decision graph
  PARITY-OBOL-LOCAL.md     the obol-local source-of-truth map
  ...
assets/
  css/obol.css             the single stylesheet (tokens + light/dark)
  engine/                  the pure, shared engine (window / worker / Node)
    facts.js phases.js pack.js packs.js command.js workspace.js vfs.js loot.js
    profile.js findings.js resolve.js graph.js chain.js engmap.js bloodhound.js
    report.js study.js toolbuilder.js workbench.js pivotdoctor.js arsenal.js
    parsers/               the conservative parser pipeline (index + common + per-protocol)
    workers/               bloodhound-worker.js (runs the pure engine off-thread)
  ui/                      the DOM/IndexedDB/router layer
    store.js router.js lazy.js boot.js ingest.js util.js icons.js settings.js ...
    routes/                one file per surface (path, home, targets, report, domain, ...)
data/
  packs/*.json             the move set (SOURCE OF TRUTH; vendored from obol-local)
  packs-bundle.js          GENERATED by tools/build-packs.js (do not hand-edit)
  field-notes.js findings-catalog.js narratives.js study-fixtures.js gtfobins.js
  toolset.js decision-forks.js parser-signatures.js coverage-expected.js ...
tools/                     generators + linters (build-packs, stamp-assets, move-lint, gap-report)
tests/
  engine/*.js              pure-engine test suite
  engine/corpus/*.json     golden-path box walkthroughs
  browser-smoke.js         headless-Chromium smoke of the real app
```

---

*Obol web is AGPL-3.0. The engine is a faithful port of `obol-local`; keep behavior parity, and let
the test suites tell you when it drifts.*
