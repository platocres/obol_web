# Obol Architecture

This document explains how obol is put together and why. It is for anyone who wants to understand,
audit, or extend the technical side of the project. For the formal ranking, gating, and
graph-utility architecture, read [RANKING.md](RANKING.md); for the Wittgensteinian contextual
inference and parser architecture, read [INFERENCE.md](INFERENCE.md); for the operator-facing tour,
read [README.md](README.md).

obol is a static, browser-local penetration-testing operator cockpit. You paste the output of the
tools you run, obol parses it into facts, and a deterministic engine ranks the exact next move for
the box in front of you, with the command pre-filled from what it has learned.

---

## 1. What It Is, And The Non-Negotiable Contract

- **Static and browser-local.** The whole app is HTML, CSS, and JavaScript plus bundled data. There
  is no backend, nothing is executed on your behalf, and nothing is sent anywhere. Your engagement
  lives in the browser (IndexedDB).
- **No telemetry.** obol never phones home. What you paste stays on your machine.
- **Deterministic and explainable.** Every suggestion is a function of the facts you have given it.
  There is no model and no guessing: the same facts always produce the same next move, and the app
  can always tell you why.
- **The move set is the source of truth.** The methodology packs (`data/`) define every move, its
  prerequisites, what it produces, and its command. The ranker and every projection derive from
  them; they never invent a move or rewrite the graph.
- **House style & accessibility.** No em or en dashes anywhere; Title Case for UI labels, tabs, and
  headings; 11px font floor, WCAG-AA contrast across all 7 skins, keyboard reachable, and responsive
  from 4K down to 320px.

---

## 2. The Core Idea: Facts, Moves, Goals (And Scale At A Glance)

Three primitives drive everything:

- **Facts** are small, typed, append-only assertions about the target, each minted by a parser from
  real tool output (`ldap.reachable`, `ad.user_list`, `credential.validated`, `objective.root_flag`).
  Facts are proof-gated: a fact exists only because something you pasted proved it.
- **Moves** are methodology steps. Each declares what it requires, what it produces, a phase, a
  priority, and one or more commands. A move becomes eligible when its required facts are present.
- **Goals** are the objectives (a foothold, a credential, domain compromise, the flags). The Cockpit
  ranks eligible moves by how much they advance you toward the current goal.

### Scale At A Glance

- **Move packs:** `19 JSON move packs (355 moves, 1,923 commands total)` (including `oscp_gapfill_2026_10.json`, compiled into `data/packs-bundle.js`).
- **Parsers:** `17 modules in assets/engine/parsers/` (`217` dedicated terminal-output parsers: `145` `_parse_*` routines + `72` NetExec capability extractors in `nxc-catalog.js`, `2,255` regex pattern matchers, and `634` fact-minting rules emitting `246` fact kinds across `38` capability families, plus 45-atom Wittgensteinian contextual inference; `220` parsers engine-wide including `bloodhound.js`, `arsenal.js`, and `vfs.js`).
- **Study & reference content:** `data/study-fixtures.js (376 move keys: 355 active moves + 30 legacy aliases)`, `data/walkthroughs.js (37 complete practice boxes)`, `data/tools-glossary.js` / `data/tool-glossary.js (117 tools)`, and `data/tool-staging.js (13 payload keys across Windows/Linux/AD)`.
- **Routes:** `21 hash routes across 18 route modules in assets/ui/routes/`.
- **Verification discipline:** Validated prior to static bundling by deterministic engine smoke suites, headless UI specs, golden box replays, and structural linters.

---

## 3. Layered Architecture, Boot Order, And Lazy Loader

Three layers, cleanly separated:

- **The pure engine** (`assets/engine/`) is plain functions over facts and packs. It has no DOM and
  no storage dependency, so it runs identically in the page, in a worker, or headless.
- **The UI** (`assets/ui/`) is the DOM, the router, the store (IndexedDB), and one file per surface.
  It reads the engine and renders; it never encodes methodology itself.
- **The data** (`data/`) is the generated move bundle plus the reference catalogues the engine reads.

### 3.1 Boot Order (`index.html`)

`index.html` loads the engine core and primary shell/Cockpit surfaces up front, then boots the UI,
restores the active engagement from IndexedDB, and registers the routes.

| # | Core Boot Module / Group | Role in Critical Boot Path |
| :--- | :--- | :--- |
| 1 | `state.js` / `facts.js` + `phases.js` + `store.js` | Fact ledger (`Fact`, `ProofState`, `FactSet`), 6-phase model, and IndexedDB/in-memory engagement state |
| 2 | `context.js` (`ObolContext` / `OBOL.context`) | Identity-scoped context projection (`resolve`, `snapshot`, `credentials`, `computeMultiplier`) |
| 3 | `pack.js` (+ `packs.js`, `profile.js`, `command.js`, `workspace.js`, `vfs.js`, `loot.js`, `playbook.js`, `chain.js`, `findings.js`, `pivotdoctor.js`, `resolve.js`) | Move engine (19 packs / 355 moves), 7-tier Causal Frontier ranker, `getOperatorDeck`, A* planner, command templating |
| 4 | `router.js` (`OBOL.router`) | Deterministic single-paint hash router |
| 5 | `lazy.js` (`OBOL.lazy`) | On-demand `<script>` group loader (compatible with `file://` and HTTP) |
| 6 | `tool-staging.js` (`ObolToolStaging` / `OBOL.TOOL_STAGING`) | On-host payload & cradle staging catalog (13 payload keys across Windows/Linux/AD) |
| 7 | `rail.js` / `sidebar` (`factpick.js`, `mobile.js`, `util.js`, `icons.js`) | Left engagement/parameter rail, fact picker, and responsive mobile controls |
| 8 | `header.js` / `appbar` (`tips.js`, `ctxbar.js`) | Top navigation bar, calm tip feed, and global engagement/target context strip |
| 9 | `cmdbar.js` / `quickpaste.js` | Global command/paste bar and `Ctrl+V` QuickPaste handler |
| 10 | `credbar.js` (`OBOL.credbar`) | Active credential selector and identity switcher |
| 11 | `graphtip.js` (+ `chainview.js`, `graphview.js`) | Attack-graph tooltips and inline chain/graph projections |
| 12 | `drawer.js` / `ingest.js` | Evidence drawer and 4-stage session splitter / ingestion pipeline |
| 13 | `palette.js` (`Ctrl+K`) | Global command, move, and tool search palette |
| 14 | `backdrop.js` (+ `coin.js`, `settings.js`) | Motion backdrop, proof coin burst, and skin/appearance settings |
| 15 | `outcomes.js` (`ObolOutcomes` / `OBOL.outcomes`) | Attempt outcome classifier (`success`, `duplicate`, `completed-negative`, `authorization-denied`, `rejected`, `environment-error`, `partial`) |
| 16 | `app.js` / `boot.js` (+ up-front routes `home.js`, `targets.js`, `evidence.js`, `path.js`) | Shell initialization, store hydration, route registration, and router boot |

The `<script defer>` sequence in `index.html` is:

```
engine:  facts -> phases -> pack -> profile -> context -> command -> workspace ->
         vfs -> loot -> playbook -> chain
data:    findings-catalog -> narratives -> (engine: findings) -> packs-bundle ->
         tools-install -> tunnels -> pivot-troubleshooter -> field-notes -> tool-staging
engine:  pivotdoctor -> packs -> (data: gtfobins) -> resolve
ui:      util -> icons -> mobile -> factpick -> store -> credbar -> (data: tips) ->
         tips -> ctxbar -> quickpaste -> chainview -> graphview -> graphtip ->
         (engine: outcomes) -> ingest -> router -> lazy -> palette
routes:  home -> targets -> evidence -> path   (only the first surfaces up front)
ui:      boot -> backdrop -> coin -> settings
```

### 3.2 Lazy Loader Groups (`assets/ui/lazy.js`)

Heavy surfaces and parser modules are lazy-loaded on first navigation or paste via `OBOL.lazy.GROUPS`:

| Lazy Group | Scripts Loaded (`OBOL.lazy.GROUPS`) |
| :--- | :--- |
| `start` | `data/resources.js`, `assets/ui/routes/start.js` |
| `parsers` | `17 modules` (`217` terminal parsers): `assets/engine/parsers/common.js`, `nxc-catalog.js` (`72` dedicated NetExec capability extractors), 13 domain modules (`nmap.js`, `directory.js`, `creds.js`, `host.js`, `services.js`, `database.js`, `web.js`, `websource.js`, `findings.js`, `shape.js`, `pivot.js`, `dns.js`, `blockers.js`), `inference.js`, and `index.js` dispatcher |
| `help` | `data/help-content.js` (and `data/study-content.js` / Operator Manual chapters), `assets/ui/routes/help.js` |
| `study` / `studydata` | `data/tool-glossary.js`, `data/study-fixtures.js`, `assets/engine/study.js`, `assets/ui/routes/study.js` |
| `tools` | `assets/engine/toolbuilder.js`, `data/toolset.js`, `data/tool-glossary.js`, `data/tool-recipes.js`, `data/tool-stations.js`, `assets/engine/toolkit.js`, `assets/engine/shellkit.js`, `assets/engine/pivotkit.js`, `assets/ui/pivotstation.js`, `assets/engine/workbench.js`, `assets/ui/bind.js`, `assets/ui/routes/tools.js` |
| `workbench` | `assets/engine/workbench.js`, `assets/ui/routes/workbench.js` |
| `library` / `stuck` | `data/stuck-catalog.js`, `assets/engine/stuck.js`, `assets/ui/routes/stuck.js`, `data/attack-catalog.js`, `data/attack-move-map.js`, `data/tool-glossary.js`, `data/tool-recipes.js`, `data/tool-stations.js`, `assets/engine/toolbuilder.js`, `data/toolset.js`, `assets/engine/toolkit.js`, `assets/ui/bind.js`, `assets/engine/library.js`, `assets/ui/routes/library.js` |
| `domain` | `assets/jszip.min.js`, `assets/engine/bloodhound.js`, `assets/ui/bhgraph.js`, `assets/ui/routes/domain.js` |
| `report` | `assets/jszip.min.js`, `data/reportmeta.js`, `assets/engine/report.js`, `assets/ui/routes/report.js` |
| `decisionmap` | `data/decision-forks.js`, `data/parser-signatures.js`, `data/coverage-expected.js`, `data/flag-reach.js`, `assets/engine/decisionmap.js`, `assets/ui/decisiontree.js` |
| `findings` | `data/reportmeta.js`, `data/attack-catalog.js`, `data/attack-move-map.js`, `data/d3fend-map.js`, `data/frameworks-tables.js`, `data/kev-catalog.js`, `assets/engine/frameworks.js`, `assets/ui/routes/findings.js` |
| `cruise` / `playbooks` | `assets/engine/arsenal.js`, `data/playbooks-bundle.js`, `assets/engine/playbooks.js`, `assets/engine/cruise.js`, `assets/engine/pivotkit.js`, `assets/ui/pivotstation.js`, `assets/ui/routes/cruise.js` / `playbooks.js` |
| `loadout`, `graph`, `target`, `map`, `checklist`, `creds`, `scoreboard`, `history` | Respective engine projection (`arsenal.js`, `graph.js`, `engmap.js`, `oscp-scope.js`) + `assets/ui/routes/<name>.js` |

---

## 4. The Pure Engine (`assets/engine/`)

### 4.1 Move Engine & Operator Deck (`pack.js` + `packs.js`)

- **`pack.js`** (with **`packs.js`**) loads the **19 packs / 355 moves (1,923 commands)**, evaluates eligibility (`eligible`, `settled`, `obsolete`), and provides:
  - **`getOperatorDeck(state)`:** Builds the 5-tab Hero Operator Deck command suites (`flagCommands`, `smbCommands`, `credCommands`, `adCommands`), annotating each command with `isSpeculative`, `speculativeReason`, `speculativeHeader`, `recommended`, and `gateReason`.
  - **`inferTargetOs(state)` / `hostOsFamily(facts)`:** Infers target OS family (`windows` or `linux`) from banners, SMB/AD facts, TTLs, and footholds.
  - **`detectLoops(state)`:** Detects stalled or repetitive command cycles in the current `accessEpoch`.
  - **`planPath(facts)`:** A* planner computing the lowest-cost dependable route to any unachieved objective.

### 4.2 Fact Ledger (`facts.js`) & Phase Model (`phases.js`)

- **`facts.js`** is the fact ledger: the typed `Fact` model, `ProofState` (`supported`, `refuted`, `inconclusive`), and `FactSet` deduplicating on `(kind, scope, value)`.
- **`phases.js`** is the 6-phase model (`recon -> enum -> creds -> access -> escalate -> loot`) and frontier computation.

### 4.3 7-Tier Causal Frontier & Bayesian Utility Ranking (`pack.js`, `context.js`, `outcomes.js`)

Documented in full in [RANKING.md](RANKING.md), `nextActionsV2` / `rankActions` orders eligible moves using the **7-tier Causal Frontier & Bayesian Utility Ranking** model:

1. **7-Tier Causal Frontier Hierarchy** (conceptual tiers `Tier 6` down to `Tier 0`, mapped to `tier` in `{5, 4, 3, 2, 1, 0, -1}` and `stageRank` in `{-1..4}`):
   - **`Tier 6: Immediate Flag Capture`** (`tier = 5`, Endgame Cash-In Frontier)
   - **`Tier 5: Credential / Access Frontier`** (`tier = 4`, Earned Material / Active Lead in Hand)
   - **`Tier 4: Verified Exploitation & Unlocks`** (`tier = 4` / `tier = 3` verified vectors)
   - **`Tier 3: Wittgensteinian Inferred & High-Yield Pivot`** (`tier = 3` / `tier = 2` fresh frontier & contextual inference unlocks)
   - **`Tier 2: Service-Matched Active Recon`** (`tier = 1` / `tier = 2` service openers)
   - **`Tier 1: Broad / Baseline Enumeration`** (`tier = 0`)
   - **`Tier 0: Fallback / Low-Signal`** (`tier = -1`, speculative / unindicated gambles)
2. **Continuous Graph & Bayesian Utility:** Combines backward-chained AND/OR goal progress (`prog`), 1-step forward enablement (`enable`), and keystone breadth (`keystone`), weighted by move reliability (`R(a)`), context alignment multipliers (`context.js` `computeMultiplier()` / `OBOL.context.resolve`), and closed-loop outcome dampening (`outcomes.js`: `success`, `duplicate`, `failed` / `completed-negative`, `partial`).

### 4.4 Context Projection (`context.js`), Outcomes (`outcomes.js`), Inference (`inference.js`), And Supporting Modules

- **`assets/engine/context.js` (`ObolContext` / `OBOL.context`):** Identity-scoped context projection (`resolve`, `snapshot`, `credentials`, `select`, `computeMultiplier`), isolating target host, credential, authentication realm, and transport service.
- **`assets/engine/outcomes.js` (`ObolOutcomes` / `OBOL.outcomes`):** Attempt outcome classification (`success`, `duplicate`, `completed-negative` / `failed`, `authorization-denied`, `rejected`, `environment-error`, `partial`, `parser-error`, `unknown`), benign baseline detection, and error fix cards.
- **`assets/engine/parsers/` (`17 modules`, `217` terminal-output parsers, `2,255` pattern matchers, `634` fact-minting rules):** `index.js` dispatcher + `common.js` + `nxc-catalog.js` (`72` dedicated NetExec extractors) + 13 domain modules (`145` `_parse_*` routines across `38` capability families / `246` fact kinds) + `inference.js` (`ObolInference`, 45-atom Wittgensteinian contextual inference and causal entailment gate synchronization; see [INFERENCE.md](INFERENCE.md)).
- **`command.js`, `workspace.js`, `vfs.js`, `loot.js`, `findings.js`, `resolve.js`, `graph.js`, `chain.js`, `engmap.js`, `bloodhound.js`, `report.js`, `study.js`, `workbench.js`, `arsenal.js`:** Command templating, virtual workspace, findings projection, GTFOBins resolver, attack graph/chain/map projections, off-thread BloodHound analysis, OSCP report generator, Study mode, Workbench engine, and Loadout provisioner.

---

## 5. The Data Layer (`data/`)

- **Move packs (`data/packs-bundle.js`):** Generated from `19 JSON move packs (355 moves, 1,923 commands total)`, including `oscp_gapfill_2026_10.json`.
- **On-Host Tool Stager (`data/tool-staging.js`, `ObolToolStaging` / `OBOL.TOOL_STAGING`):** `13 payload keys across Windows/Linux/AD` in the Hero Operator Deck plus per-tool staging cradles.
- **Study & Reference Catalogs:** `data/study-fixtures.js (376 move keys: 355 active moves + 30 legacy aliases)`, `data/walkthroughs.js (37 complete practice boxes)`, `data/tools-glossary.js` / `data/tool-glossary.js (117 tools)`, `data/help-content.js` (7-chapter Operator Manual + 32-term glossary), `data/resources.js` (`#/start` curated resources and 5 practice scenarios), `data/field-notes.js`, `data/findings-catalog.js`, `data/narratives.js`, `data/gtfobins.js`, and `data/parser-signatures.js`.

---

## 6. The UI Layer And Routes (`assets/ui/`)

- **`store.js`, `router.js`, `lazy.js`, `ingest.js`, `boot.js`** manage IndexedDB persistence, deterministic routing, lazy script loading, and 4-stage paste ingestion.
- **`routes/` (`21 hash routes across 18 route modules in assets/ui/routes/`):**
  - **`#/start` (`assets/ui/routes/start.js` + `data/resources.js` - Startup Hub):** New Engagement launcher, Resume card, 5 Practice Scenarios, and Curated OSCP Resources.
  - **`#/path` (`assets/ui/routes/path.js` - Cockpit / Choose Your Path, `OBOL.coach` in code):** Features the **5-tab Hero Operator Deck** (`Flag Capture` with inline `CMD`/`PS` toggles and `Educated Guess` vs `Verified Path` epistemic badges, `SMB & Shares` with Remote/Local mode toggle, `Tool Stager` with 13-payload selector and bulk "Stage All Selected" cradle generator, `Cred & Hash Ops`, and `AD & Domain Ops`), ranked Move Cards, and Terminal Output Dropzone.
  - **`#/workbench` (`assets/ui/routes/workbench.js`):** **11 interactive offline studios** across 4 lanes (`Reverse Shells & TTY`, `File Transfer`, `Pivot & Tunnels`, `Hash ID & Extractors`, `JWT Studio`, `Spray Planner`, `Encode & Decode`, `Manual SQLi`, `Wordlists & Fuzzing`, `GTFOBins & LOLBAS`, `Output & Error Doctor`).
  - **`#/tools` (`assets/ui/routes/tools.js`):** **6-tab Tool Dock** (Reverse Shells, Transfers, Listeners, Tunnels & Pivoting, Wordlists, CyberChef Lite, plus Stations and 50 Tool Builders).
  - **`#/library` (`assets/ui/routes/library.js` + `stuck.js`):** **5 lenses** (Techniques, Tools (117), Checklists, Playbooks, Case Studies (37), plus Stuck?).
  - **`#/help` (`assets/ui/routes/help.js` + `data/help-content.js`):** **4-tab Operator Manual & Reference** (`#/help`, `#/help/manual` with 7 chapters, `#/help/index`, `#/help/glossary` with 32 terms, plus cross-tab search).
  - **Additional Routes:** `#/home`, `#/targets`, `#/target`, `#/evidence`, `#/study`, `#/loadout`, `#/domain`, `#/map`, `#/graph`, `#/creds`, `#/checklist`, `#/findings`, `#/scoreboard`, `#/history`, `#/cruise`, `#/playbooks`.

---

## 7. How Obol Parses Inputs (Pastes) And Mints Facts

When an operator pastes terminal output (via QuickPaste `Ctrl+V`, the Cockpit Terminal Output Dropzone, a move card, Cruise, or Evidence), it flows through a **4-stage ingestion pipeline**:

```
Raw Terminal Paste
   │
   ▼
1. Session Splitter & Scrollback Trimmer (assets/ui/ingest.js)
   │  Splits multi-command scrollback, sub-shells, or Cruise markers (===== OBOL STEP ... =====)
   │  Extracts typed command, strips ANSI escape codes & spinner CR overwrites
   ▼
2. Scope & Context Router (assets/ui/ingest.js + assets/engine/context.js)
   │  Auto-learns {{lhost}} from prompt stamps; routes output to host:<ip>,
   │  domain:<name>, and active credential
   ▼
3. 3-Tier Parser & Wittgensteinian Inference Cascade (assets/engine/parsers/: 17 modules, 217 parsers)
   │  ├── Tier 1: Tool & Protocol Parsers (13 domain modules + nxc-catalog.js, 2,250+ matchers)
   │  ├── Tier 2: Output-Shape & Blocker Fallback (shape.js, blockers.js)
   │  └── Tier 3: Wittgensteinian Contextual Inference (inference.js: 45 atoms + causal entailment)
   ▼
4. FactSet Deduplication, Proof-State Ledger & Outcome Classification (facts.js + outcomes.js)
```

---

## 8. How Obol Hypothesizes Deterministically And Settles Moves

1. **Eligibility Filtering (`Action.prototype.eligible`):** Checks `inferTargetOs` / `hostOsFamily(facts)`, `requires_all`, `requires_any`, `!settled(facts)`, and `!obsolete(facts)` within the identity-scoped context (`OBOL.context.resolve`).
2. **7-Tier Causal Frontier & Bayesian Utility Ranking (`pack.js`):** Ranks moves across `Tier 6: Immediate Flag Capture` -> `Tier 5: Credential / Access Frontier` -> `Tier 4: Verified Exploitation & Unlocks` -> `Tier 3: Wittgensteinian Inferred & High-Yield Pivot` -> `Tier 2: Service-Matched Active Recon` -> `Tier 1: Broad / Baseline Enumeration` -> `Tier 0: Fallback / Low-Signal` (`tier` in `{-1..5}`, `stageRank` in `{-1..4}`), scored by `Reliability(a) * computeMultiplier(ctx) * (prog + 0.6 * enable + 0.25 * keystone)` and dampened by `outcomes.js` (`success`, `duplicate`, `failed` / `completed-negative`, `partial`). See [RANKING.md](RANKING.md).
3. **Settling & Epoch Recovery (`outcomes.js` + `accessEpoch`):** Positive proofs (`success` / `duplicate`) settle satisfied `settled_by` commands and moves; environment errors (`environment-error`) surface Fix Doctor cards without retiring the move; negative or denied attempts (`completed-negative`, `authorization-denied`, `rejected`) retire the command for the current `accessEpoch` and rotate untried hypotheses to `#1` until new access transitions the epoch.

---

## 9. Guardrails, Verification, And Deployment

- **Pure Engine & Mechanical Verification:** The pure engine is UI-independent and verified prior to each release against deterministic engine smoke suites, headless browser specs, golden box replays, and structural linters.
- **Static Deployment:** Served directly from static files with content-hash cache-bust stamps (`?v=...`) across `index.html` and `assets/ui/lazy.js`.

---

## 10. Directory Map

```
index.html                 the app; critical boot path + lazy route registration
README.md                  operator-facing tour
ARCHITECTURE.md            technical architecture & deterministic engine guide
RANKING.md                 7-tier Causal Frontier & Bayesian Utility Ranking specification
INFERENCE.md               3-tier Wittgensteinian Contextual Inference & parser specification
assets/
  css/obol.css             the single stylesheet (tokens + 7 skins + responsive layout)
  engine/                  the pure, shared engine (page / worker / headless)
    facts.js phases.js context.js pack.js packs.js command.js outcomes.js
    cruise.js workspace.js vfs.js loot.js profile.js findings.js resolve.js
    graph.js chain.js engmap.js bloodhound.js report.js study.js workbench.js
    arsenal.js library.js pivotkit.js shellkit.js toolkit.js toolbuilder.js
    parsers/               17 modules, 217 terminal parsers (index.js, common.js, nxc-catalog.js,
                           inference.js + 13 domain modules; 2,255 pattern matchers, 634 rules)
    workers/               bloodhound-worker.js (runs the pure engine off-thread)
  ui/                      the DOM / IndexedDB / router layer
    store.js router.js lazy.js boot.js ingest.js util.js icons.js settings.js
    credbar.js ctxbar.js quickpaste.js palette.js graphtip.js bind.js pivotstation.js ...
    routes/                21 hash routes across 18 route modules (start.js, path.js, home.js,
                           targets.js, target.js, evidence.js, tools.js, workbench.js, library.js,
                           stuck.js, study.js, loadout.js, domain.js, report.js, checklist.js,
                           graph.js, creds.js, scoreboard.js, playbooks.js, cruise.js, map.js,
                           findings.js, history.js, help.js)
data/
  packs-bundle.js          generated move bundle (19 packs, 355 moves, 1,923 commands)
  tool-staging.js          ObolToolStaging (13 Hero Deck payload keys + staging cradles)
  resources.js             curated OSCP resources and practice scenarios for #/start
  help-content.js          4-tab Help & 7-chapter Operator Manual + 32-term glossary
  study-fixtures.js        355 move keys (1:1 coverage) & 37 practice box walkthroughs
  field-notes.js findings-catalog.js narratives.js gtfobins.js toolset.js tool-glossary.js ...
screenshots/               the images used by the README
```

---

*obol is AGPL-3.0.*
