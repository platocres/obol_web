# Obol Web Architecture

This document explains how Obol web is put together and why. It is for anyone who wants to
understand, audit, or extend the technical side of the project. For the formal ranking, gating, and
graph-utility architecture, read [RANKING.md](RANKING.md) and [docs/MOVE-ENGINE.md](docs/MOVE-ENGINE.md);
for the Wittgensteinian contextual inference and parser architecture, read [INFERENCE.md](INFERENCE.md);
for the operator-facing tour, read [README.md](README.md); for the agent working rules, read
[AGENTS.md](AGENTS.md).

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

## 2. The Core Idea: Facts, Moves, Goals (And Scale At A Glance)

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

From this one graph the engine computes: the ranked next moves (the Cockpit, `OBOL.coach` in code), the lowest-cost route
to a goal (the planner), the attack-path graph, the compromise chain, and the report. Adding a move
is adding a node with honest edges; the engine figures out where it belongs. That rule (a move must
be rankable from its own honest declaration) is what keeps ranking correct as the pack grows, and
it is enforced mechanically by the lints and the golden-path corpus (see Section 9).

### Scale At A Glance

- **Move packs:** `19 JSON move packs (355 moves, 1,923 commands total)` in `data/packs/` (`ad_2026_09.json`, `cisa_kev_2026_09.json`, `cracking_2026_09.json`, `credential_access_2026_09.json`, `database_2026_09.json`, `findings_catalog_2026_09.json`, `findings_checks_2026_09.json`, `known_exploits_2026_09.json`, `linux_privesc_2026_09.json`, `obol_flag_hunt_2026_09.json`, `obol_local_pivot_2026_09.json`, `pivoting_2026_09.json`, `recon_2026_09.json`, `scripts_2026_09.json`, `shells_2026_09.json`, `web_2026_09.json`, `web_exploit_checks_2026_09.json`, `web_fingerprints_2026_09.json`, `windows_privesc_2026_09.json`, and `oscp_gapfill_2026_10.json`), compiled into `data/packs-bundle.js`.
- **Parsers:** `18 files in assets/engine/parsers/` (17 domain modules + `common.js`, `nxc-catalog.js`, `inference.js`; `443 parser signals` + `5 Wittgensteinian contextual inference rules`).
- **Study & reference content:** `data/study-fixtures.js (376 move keys: 355 active moves + 30 legacy aliases)`, `data/walkthroughs.js (37 complete practice boxes)`, `data/tools-glossary.js` / `data/tool-glossary.js (117 tools)`, and `data/tool-staging.js (13 payload keys across Windows/Linux/AD)`.
- **Routes:** `21 hash routes across 18 route modules in assets/ui/routes/`.
- **Verification suite:** `99 engine smoke suites` in `tests/engine/`, legacy suites in `tests/engine/legacy/`, and `12 Playwright specs` in `tests/e2e/`.

---

## 3. Layered Architecture, Boot Order, And Lazy Loader

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  UI layer  (assets/ui/*, DOM + IndexedDB, browser only)                 │
  │  shell · router · lazy loader · routes · evidence ingest · store        │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  Pure engine  (assets/engine/*, runs in window / Web Worker / Node)     │
  │  facts · phases · context · pack+planner · command · parsers · outcomes │
  │  findings · resolve · graph · chain · engmap · bloodhound · report …    │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  Data  (data/*, bundled JSON generated from source)                     │
  │  packs (moves) · field-notes · findings-catalog · narratives · gtfobins │
  │  study-fixtures · tool-staging · resources · parser-signatures …        │
  └─────────────────────────────────────────────────────────────────────────┘
```

The sharp line is between the **pure engine** and the **UI**. Everything under `assets/engine/*`
is dependency-free JavaScript that runs identically in the window, in a Web Worker, and in Node
(the test suites import it directly). It touches no DOM, no `window`-only API, no network. The UI
layer under `assets/ui/*` is the only code that touches the DOM, IndexedDB, and the hash router.

### 3.1 Boot Order (`index.html`)

`index.html` loads the engine core and primary shell/Cockpit surfaces up front, then everything else lazily.

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

The exact `<script defer>` sequence in `index.html` is:

```
engine:  facts -> phases -> pack -> profile -> context -> command -> workspace -> vfs -> loot -> playbook -> chain
data:    findings-catalog -> narratives -> (engine: findings) -> packs-bundle -> tools-install -> tunnels ->
         pivot-troubleshooter -> field-notes -> tool-staging
engine:  pivotdoctor -> packs -> (data: gtfobins) -> resolve
ui:      util -> icons -> mobile -> factpick -> store -> credbar -> (data: tips) -> tips -> ctxbar ->
         quickpaste -> chainview -> graphview -> graphtip -> (engine: outcomes) -> ingest -> router -> lazy -> palette
routes:  home -> targets -> evidence -> path            (only the first surfaces up front)
ui:      boot -> backdrop -> coin -> settings
```

### 3.2 Lazy Loader Groups (`assets/ui/lazy.js`)

Every other route and heavy engine/data bundle is lazy-loaded on first navigation or first paste by
`assets/ui/lazy.js` (`OBOL.lazy.GROUPS`), which injects `<script>` tags on demand (working over both `file://` and HTTP):

| Lazy Group | Scripts Loaded (`OBOL.lazy.GROUPS`) |
| :--- | :--- |
| `start` | `data/resources.js`, `assets/ui/routes/start.js` |
| `parsers` | `assets/engine/parsers/common.js`, `nxc-catalog.js`, 15 domain parsers (`nmap.js`, `directory.js`, `creds.js`, `host.js`, `services.js`, `database.js`, `web.js`, `websource.js`, `findings.js`, `shape.js`, `pivot.js`, `dns.js`, `blockers.js`, plus `index.js` dispatcher), and `assets/engine/parsers/inference.js` |
| `help` | `data/help-content.js` (and `data/study-content.js` / Operator Manual chapters), `assets/ui/routes/help.js` |
| `study` / `studydata` | `data/tool-glossary.js`, `data/study-fixtures.js`, `assets/engine/study.js`, `assets/ui/routes/study.js` (`studydata` omits route UI for background preloading) |
| `tools` | `assets/engine/toolbuilder.js`, `data/toolset.js`, `data/tool-glossary.js`, `data/tool-recipes.js`, `data/tool-stations.js`, `assets/engine/toolkit.js`, `assets/engine/shellkit.js`, `assets/engine/pivotkit.js`, `assets/ui/pivotstation.js`, `assets/engine/workbench.js`, `assets/ui/bind.js`, `assets/ui/routes/tools.js` |
| `workbench` | `assets/engine/workbench.js`, `assets/ui/routes/workbench.js` |
| `library` / `stuck` | `data/stuck-catalog.js`, `assets/engine/stuck.js`, `assets/ui/routes/stuck.js`, `data/attack-catalog.js`, `data/attack-move-map.js`, `data/tool-glossary.js`, `data/tool-recipes.js`, `data/tool-stations.js`, `assets/engine/toolbuilder.js`, `data/toolset.js`, `assets/engine/toolkit.js`, `assets/ui/bind.js`, `assets/engine/library.js`, `assets/ui/routes/library.js` |
| `domain` | `assets/jszip.min.js`, `assets/engine/bloodhound.js`, `assets/ui/bhgraph.js`, `assets/ui/routes/domain.js` |
| `report` | `assets/jszip.min.js`, `data/reportmeta.js`, `assets/engine/report.js`, `assets/ui/routes/report.js` |
| `decisionmap` | `data/decision-forks.js`, `data/parser-signatures.js`, `data/coverage-expected.js`, `data/flag-reach.js`, `assets/engine/decisionmap.js`, `assets/ui/decisiontree.js` |
| `findings` | `data/attack-catalog.js`, `data/attack-move-map.js`, `data/d3fend-map.js`, `data/frameworks-tables.js`, `data/kev-catalog.js`, `assets/engine/frameworks.js`, `assets/ui/routes/findings.js` |
| `cruise` / `playbooks` | `assets/engine/arsenal.js`, `data/playbooks-bundle.js`, `assets/engine/playbooks.js`, `assets/engine/cruise.js`, `assets/engine/pivotkit.js`, `assets/ui/pivotstation.js`, `assets/ui/routes/cruise.js` / `playbooks.js` |
| `loadout`, `graph`, `target`, `map`, `checklist`, `creds`, `scoreboard`, `history` | Respective engine projection (`arsenal.js`, `graph.js`, `engmap.js`, `oscp-scope.js`) + `assets/ui/routes/<name>.js` |

---

## 4. The Pure Engine (`assets/engine/`)

### 4.1 Move Engine & Operator Deck: `pack.js` (+ `packs.js`)

`pack.js` loads the **19 packs / 355 moves (1,923 commands)** from `OBOL.packData` (`packs.js` caches the deduplicated `Action` list via `OBOL.packs.actions()`) and drives move eligibility, the Hero Operator Deck, target OS inference, loop detection, and A* path planning:

- **The `Action` model:**
  - Eligibility: `requires_all`, `requires_any`; `eligible(facts)`, `settled(facts)` (every produced kind already proven), `obsolete(facts)` (a later achievement makes it moot).
  - `locus`: **R** (remote, run from Kali), **F** (on-host one-shot), **I** (interactive on-host). Remote is preferred, always.
  - `scope`: `oscp` / `oscp+` / `beyond`, a newcomer-safe syllabus lens.
  - `priority`: hand-tuned tiebreak, kept strictly subordinate to tier and graph utility.
  - `commands[]`: copy-ready command templates (with `{{token}}` placeholders), plus per-command metadata (`tool`, `note`, `web` variant, `settled_by`, `sequence`).
- **`getOperatorDeck(state)`:** Generates the context-aware command suites powering the Cockpit's 5-tab Hero Operator Deck, returning `{ flagCommands, smbCommands, credCommands, adCommands }`. Each entry carries epistemic and gating metadata: `isSpeculative`, `speculativeReason`, `speculativeHeader`, `recommended`, and `gateReason` (distinguishing `Educated Guess` commands when OS/foothold/paths are unconfirmed from `Verified Path` commands when prerequisites are proven).
- **`inferTargetOs(state)` / `hostOsFamily(facts)`:** Infers target OS family (`windows`, `linux`, or unknown) and confidence from Nmap service banners, SMB/AD signals, TTLs, and active footholds.
- **`detectLoops(state)`:** Detects repeated unproductive command cycles or stalled enumeration loops in the current `accessEpoch` so the UI can nudge the operator toward untried hypotheses or Stuck? triage.
- **`planPath(facts)`:** A* search for the lowest-cost dependable route from current facts to any unachieved goal (`earned = 1.0`, `enum = 1.5`, `privilege shortcut = 8.0`, `speculative = 12.0`, plus `+0.3` on-host locus surcharge).

### 4.2 The Fact Ledger (`facts.js`) And Phase Model (`phases.js`)

- **`facts.js`:** A `Fact` has `kind` (dotted predicate, e.g. `smb.reachable`, `credential.available`, `host.hostname`), `scope` (`host:10.10.10.10` or `domain:corp.local`), `value` (structured payload), `state` (`ProofState`: `supported`, `refuted`, or `inconclusive`), `source`, and `created_at`. `FactSet` provides `has(kind)`, `values(kind)`, and `kinds()`, deduplicating on `(kind, scope, claim)`.
- **`phases.js`:** Orders an engagement across six phases: `recon -> enum -> creds -> access -> escalate -> loot`. Computes `targetPhase(facts)` and `frontierIndex`.

### 4.3 7-Tier Causal Frontier & Bayesian Utility Ranking (`pack.js`, `context.js`, `outcomes.js`)

The Cockpit ranker (`rankActions` / `nextActionsV2`, formally specified in [RANKING.md](RANKING.md) and [docs/MOVE-ENGINE.md](docs/MOVE-ENGINE.md)) replaces the legacy 4-tier model with the **7-Tier Causal Frontier & Bayesian Utility Ranking** model. Eligible, non-settled, non-obsolete moves are ordered by:

1. **7-Tier Causal Frontier Hierarchy** (conceptual tiers `Tier 6` down to `Tier 0`, encoded as `tier` in `{5, 4, 3, 2, 1, 0, -1}` alongside within-tier `stageRank` in `{-1..4}`):
   - **`Tier 6: Immediate Flag Capture`** (`tier = 5`, Endgame Cash-In Frontier): Capturing an uncaptured root/SYSTEM/user flag (`objective.root_flag`, `objective.local_flag` when located), executing a ready DCSync (`ad.control_paths` held), or opening an interactive admin shell once flags are handled.
   - **`Tier 5: Credential / Access Frontier`** (`tier = 4`, Earned Material / Active Lead in Hand): Validating newly recovered credentials (`validateFirst`), offline cracking of captured hashes (`hash.tgs`, `hash.asrep`, `gpp_cpassword`), or converting recovered credentials into authenticated access.
   - **`Tier 4: Verified Exploitation & Unlocks`** (`tier = 4` / `tier = 3` verified vectors): Exploiting confirmed writable ACLs (`ad.acl_lead`, `ad.attack_paths`), confirmed host privilege-escalation vectors (`privesc_act`, SUID/sudo/SeImpersonate), or confirmed CVEs.
   - **`Tier 3: Wittgensteinian Inferred & High-Yield Pivot`** (`tier = 3` / `tier = 2` fresh frontier): Moves newly unlocked by the latest paste or by Tier 3 Wittgensteinian contextual inference rules (`inference.js`), fast authenticated AD escalation probes (`bloodyad-acl`, `kerberoast`), and initial local privesc orientation (`linpeas`/`winpeas`).
   - **`Tier 2: Service-Matched Active Recon`** (`tier = 1` / `tier = 2` service openers): Targeted service enumeration matched to proven open ports and banners (SMB/LDAP/HTTP/MSSQL/SNMP/NFS probes).
   - **`Tier 1: Broad / Baseline Enumeration`** (`tier = 0`): Routine eligible baseline enumeration that advances discovery.
   - **`Tier 0: Fallback / Low-Signal`** (`tier = -1`, speculative / unindicated gambles): Moves marked `speculative` or claiming high payoff from a bare port without supporting evidence (`v2Speculative`).
2. **Bayesian & Graph-Theoretic Utility Score (`score`):**
   - Computes backward-chained AND/OR goal distance progress (`delta_d` / `prog`), 1-step forward enablement (`E`), and keystone breadth (`K`, count of blocked moves unblocked, capped at `2.5`), weighted by move reliability (`R(a)`).
   - Applies context alignment multipliers (`context.js` `computeMultiplier()` / `OBOL.context.resolve` for host, credential, service, and OS coherence) and closed-loop outcome dampening from `outcomes.js` (`success`, `duplicate`, `failed` / `completed-negative`, `partial`) plus epoch-scoped dry-probe rotation (`moveDryTriesInEpoch`).
3. **Deterministic Tie-Breakers:** `priority` (hand-tuned), then **house-toolkit** preference (prefer NetExec), then **locus** (remote-first), then `id`.

### 4.4 Identity-Scoped Context Projection: `assets/engine/context.js` (`ObolContext`)

`assets/engine/context.js` (`OBOL.context` / `ObolContext`) maintains strict separation between target identity, authentication identity (`credentialId`, `principal`, `authRealm`), and transport service (`smb`, `ldap`, `winrm`, `ssh`, `mssql`, `rdp`, `wmi`). It provides `resolve()`, `snapshot()`, `credentials()`, `select()`, and `computeMultiplier()` so facts and admin proofs from Host A or Credential 1 never contaminate commands or ranking on Host B or Credential 2.

### 4.5 Attempt Outcome Classification: `assets/engine/outcomes.js` (`ObolOutcomes`)

`assets/engine/outcomes.js` (`OBOL.outcomes` / `ObolOutcomes`) separates observation from operation completion. When terminal output is pasted, `OBOL.outcomes.classify` evaluates the text, command, extracted proof facts, and diagnostic blockers into formal outcomes (`success`, `duplicate`, `completed-negative` / `failed`, `authorization-denied`, `rejected`, `environment-error`, `partial`, `parser-error`, `unknown`), driving outcome dampening, command retirement (`retireCommand`), benign baseline detection (`_builtinBaselines`), and inline error fix cards (`_builtinErrorFixes`).

### 4.6 Command Templating (`command.js`) And Filesystem Modeling (`workspace.js`, `vfs.js`, `loot.js`)

- **`command.js`:** Builds an identity-coherent `{{token}}` context (`fillAll`, `fillCommand`), tracks `EARNED_TOKENS`, and computes `commandTriedInEpoch` and `moveDryTriesInEpoch`.
- **`workspace.js`, `vfs.js`, `loot.js`:** Models the operator's Kali working directory (`mkdir -p <root>/{scans,loot,...}`), virtual filesystem state, and fact-to-file glue (`{{userlist}}`, `{{hashfile}}`).

### 4.7 The Parser Pipeline (`assets/engine/parsers/`) And Wittgensteinian Contextual Inference (`inference.js`)

`assets/engine/parsers/` contains **18 files** (17 domain modules + `common.js`, `nxc-catalog.js`, `inference.js`; **443 parser signals + 5 Wittgensteinian contextual inference rules**):

- **Dispatcher & Shared Library:** `index.js` (`parseActionOutput` multi-strategy fan-out dispatcher) and `common.js` (compiled regexes, OS signatures, scoping helpers, `mkFact`).
- **Domain Parsers:** `nmap.js`, `directory.js`, `nxc-catalog.js` (NetExec capability map), `creds.js`, `host.js`, `services.js`, `database.js`, `web.js`, `websource.js`, `findings.js`, `shape.js`, `pivot.js`, `dns.js`, and `blockers.js`.
- **Wittgensteinian Contextual Inference Engine (`assets/engine/parsers/inference.js`, `ObolInference`):** Documented in full in [INFERENCE.md](INFERENCE.md). Implements Tier 3 contextual inference across **5 cross-domain language-game inference rules** (atomic primitive decomposition across ~45 atom types, 2D table and Key-Value geometry parsing, operator attention-frame binding from `copiedQueue` and recent activities, shell prompt/echo subtraction, and causal entailment gate synchronization).

### 4.8 Findings (`findings.js`), Resolver (`resolve.js`), Projections (`graph.js`, `chain.js`, `engmap.js`), BloodHound (`bloodhound.js`), And Engines (`report.js`, `study.js`, `toolbuilder.js`, `workbench.js`)

- **`findings.js`** (+ `data/findings-catalog.js`, `data/narratives.js`): Matches proven facts against the findings catalog to generate report-ready findings and Cockpit narratives.
- **`resolve.js`** (+ `data/gtfobins.js`): Pre-fills exact GTFOBins escapes and hashcat modes from discovered binaries and hashes.
- **`graph.js`, `chain.js`, `engmap.js`:** Pure SVG/data projections of the attack path, ordered compromise chain, and multi-host engagement map.
- **`bloodhound.js`** (+ `workers/bloodhound-worker.js`): Off-thread SharpHound/BloodHound-CE collection parser and shortest-path-to-DA analyzer.
- **`report.js`, `study.js`, `toolbuilder.js`, `workbench.js`:** Pure engines powering the OSCP report exporter (`preflightCheck`, Markdown/HTML/PDF/DOCX), Learn/Study mode, Tool Builders, and the 13 Workbench studios.

---

## 5. The Data Layer (`data/`)

- **Methodology packs (`data/packs/*.json` -> `data/packs-bundle.js`):** `19 JSON move packs (355 moves, 1,923 commands total)`, including `oscp_gapfill_2026_10.json`, compiled by `node tools/build-packs.js`.
- **On-Host Tool Stager (`data/tool-staging.js`, `ObolToolStaging` / `OBOL.TOOL_STAGING`):** `13 payload keys across Windows/Linux/AD` in the Hero Operator Deck (plus extended per-tool staging recipes such as `winpeas`, `linpeas`, `pspy`, `les.sh`, `powerview`, `powerup`, `sharphound`, `mimikatz`, `rubeus`, `certify`, `godpotato`, `printspoofer`, `ligolo`/`chisel`) with HTTP server cradle generation.
- **Study & Reference Content:**
  - `data/study-fixtures.js`: `355 move keys (100% 1:1 coverage across all 355 active moves)` with sample outputs and guided exercises.
  - `data/walkthroughs.js` (and walkthrough fixtures): `37 complete practice boxes`.
  - `data/tools-glossary.js` / `data/tool-glossary.js`: `117 tools` with flag-by-flag glossaries (`data/toolset.js`, `data/tool-recipes.js`, `data/tool-stations.js`, `data/tools-install.js`).
  - `data/help-content.js` (+ `data/study-content.js`): 7-chapter Operator Manual, section index, Charon quick-start, and 32-term glossary.
  - `data/resources.js`: Curated OSCP courses, practice labs, and scenario templates for `#/start`.
- **Graph & Parser Ground Truth:** `data/field-notes.js`, `data/findings-catalog.js`, `data/narratives.js`, `data/gtfobins.js`, `data/decision-forks.js`, `data/parser-signatures.js`, `data/coverage-expected.js`, `data/flag-reach.js`, `data/playbooks-bundle.js`, `data/tunnels.js`, `data/pivot-troubleshooter.js`.

---

## 6. The UI Layer And Routes (`assets/ui/`)

The UI layer comprises `store.js` (IndexedDB + synchronous memory cache), `router.js`, `lazy.js`, `ingest.js` (DOM-free 4-stage paste splitter and parser router), `boot.js`, and **21 hash routes across 18 route modules in `assets/ui/routes/`**:

- **`#/start` (`assets/ui/routes/start.js` + `data/resources.js` - Startup Hub):**
  - **New Engagement launcher** (target IP, domain, profile quick-start), **Resume card** for the active engagement, **5 Practice Scenarios** (guided lab templates), and **Curated OSCP Resources**.
- **`#/path` (`assets/ui/routes/path.js` - Cockpit / Choose Your Path, `OBOL.coach` in code):**
  - **5-Tab Hero Operator Deck** powered by `getOperatorDeck(state)`:
    1. **`Flag Capture`**: Copy-ready user/root/SYSTEM flag location and proof commands with inline **`CMD` / `PS` shell toggles** and **`Educated Guess` vs `Verified Path` epistemic badges** (indicating whether OS/foothold/flag path is heuristically inferred or backed by proven facts).
    2. **`SMB & Shares`**: Share enumeration, recursive spidering, and file download commands with a **Remote / Local mode toggle**.
    3. **`Tool Stager`**: Interactive **13-payload selector** across Windows, Linux, and Active Directory (`ObolToolStaging` / `data/tool-staging.js`) with a bulk **"Stage All Selected"** Kali HTTP server + target download cradle generator.
    4. **`Cred & Hash Ops`**: Fast credential validation, hash extraction, and offline cracking commands for held material.
    5. **`AD & Domain Ops`**: Domain discovery, Kerberoasting, AS-REP roasting, BloodHound collection, ACL abuse, and DCSync quick-actions.
  - **Ranked Move Cards**: Deterministic 7-tier Causal Frontier cards with `Because <prereq> -> expect <payoff>` hypotheses, progressive earned-token gating, Focus Mode toggle, and inline Field Notes.
  - **Terminal Output Dropzone**: Per-card and HUD paste intake with instant outcome receipts (`outcomes.js`) and reactive Fix Doctor cards.
- **`#/workbench` (`assets/ui/routes/workbench.js` + `assets/engine/workbench.js`):**
  - **13 Interactive Studios**: Reverse Shells, MSFVenom Builder, Living-Off-The-Land, Web Injection & LFI, Active Directory & BloodHound, Kerberos & Hash Ops, Lateral Movement, Persistence & Cleanup, Credential & Hash Lab, File Transfer, Tunnels & Pivot, CyberChef Lite, and Session Scratchpad.
- **`#/tools` (`assets/ui/routes/tools.js` + `assets/engine/toolkit.js`, `toolbuilder.js`, `shellkit.js`, `pivotkit.js`):**
  - **6-Tab Tool Dock**: Reverse Shells, Transfers, Listeners, Tunnels & Pivoting, Wordlists, and CyberChef Lite (alongside task-first Stations and 50 flag-annotated Tool Builders bound to engagement state via `OBOL.bind`).
- **`#/library` (`assets/ui/routes/library.js` + `assets/engine/library.js`, folding in `#/stuck` via `assets/ui/routes/stuck.js`):**
  - **5 Lenses**: Techniques (355 moves), Tools (117), Checklists (1,923 commands), Playbooks (ATT&CK & methodology chains), and Case Studies (37 complete box walkthroughs), plus Stuck? diagnostic breakers.
- **`#/help` (`assets/ui/routes/help.js` + `data/help-content.js`):**
  - **4-Tab Operator Manual & Reference**: `#/help` (Quick Start & Triage), `#/help/manual` (**7-chapter Operator Manual**), `#/help/index` (Surface-by-Surface Reference Index), and `#/help/glossary` (**32 terms**), plus live cross-tab search.
- **Additional Engagement Surfaces:** `#/home` (Engagement Hub), `#/targets` & `#/target` (Target Roster & Host Workspace), `#/evidence` (Evidence & Run Log), `#/study` (Learn / Interactive Curriculum), `#/loadout` (Attack Box Arsenal Sync), `#/domain` (BloodHound Graph & Pathfinding), `#/map` (Engagement Topology Map), `#/graph` (Attack Path DAG), `#/creds` (Credential Vault), `#/checklist` (OSCP Scope & Progress Checklist), `#/findings` (CVSS/ATT&CK/D3FEND Findings), `#/scoreboard` (Captured Flags & Pre-Flight Grader), `#/history` (Activity Timeline), `#/cruise` & `#/playbooks` (Experimental Batch Script Generator).

---

## 7. How Obol Parses Inputs (Pastes) And Mints Facts

When an operator pastes terminal output (via QuickPaste `Ctrl+V`, the Cockpit Terminal Output Dropzone, a move card, Cruise, or Evidence), it flows through a **4-stage ingestion pipeline**:

```
Raw Terminal Paste
   │
   ▼
1. Session Splitter & Scrollback Trimmer (assets/ui/ingest.js)
   │  Splits multi-command scrollback, interactive sub-shells, or Cruise markers (===== OBOL STEP ... =====)
   │  Extracts typed command, strips ANSI escape codes & spinner CR overwrites
   ▼
2. Scope & Context Router (assets/ui/ingest.js + assets/engine/context.js)
   │  Auto-learns {{lhost}} from prompt stamps; binds host:<ip>, domain:<name>, and active credential context
   ▼
3. 3-Tier Multi-Strategy Parser & Wittgensteinian Inference Cascade (assets/engine/parsers/index.js)
   │  ├── Tier 1: Command-Gated & Content-Sniffed Domain Parsers (15 domain modules + nxc-catalog.js, 443 signals)
   │  ├── Tier 2: Output-Shape & Blocker Fallback (shape.js, blockers.js)
   │  └── Tier 3: Wittgensteinian Contextual Inference Engine (inference.js: 5 cross-domain language-game rules + causal entailment)
   ▼
4. FactSet Deduplication, Proof-State Ledger & Outcome Classification (facts.js + outcomes.js)
```

---

## 8. How Obol Hypothesizes Deterministically And Settles Moves

Every move in Obol is an explicit **testable hypothesis** about the target (`"Because <held prerequisite fact> -> expect <produced payoff fact>"`).

### 8.1 Eligibility Filtering (`Action.prototype.eligible`)

A move enters the candidate pool only if:
1. Its OS constraint matches `inferTargetOs` / `hostOsFamily(facts)`.
2. Every fact in `requires_all` is `SUPPORTED` in the identity-scoped `FactSet` (`OBOL.context.resolve`).
3. At least one fact in `requires_any` is `SUPPORTED`.
4. The move is neither `settled(facts)` nor `obsolete(facts)`.

### 8.2 7-Tier Causal Frontier & Bayesian Utility Ranking (`pack.js`)

Eligible moves are partitioned into the **7-tier Causal Frontier hierarchy** (`Tier 6: Immediate Flag Capture` -> `Tier 5: Credential / Access Frontier` -> `Tier 4: Verified Exploitation & Unlocks` -> `Tier 3: Wittgensteinian Inferred & High-Yield Pivot` -> `Tier 2: Service-Matched Active Recon` -> `Tier 1: Broad / Baseline Enumeration` -> `Tier 0: Fallback / Low-Signal`, mapped to `tier` in `{-1..5}` and `stageRank` in `{-1..4}`) and scored by:

```
score(a) = Reliability(a) * computeMultiplier(ctx) * ( prog(a) + 0.6 * enable(a) + 0.25 * keystone(a) ) + Modifiers(a)
```

combined with outcome dampening from `outcomes.js` (`success`, `duplicate`, `failed` / `completed-negative`, `partial`) and epoch-scoped dry-probe rotation (`moveDryTriesInEpoch`). See [RANKING.md](RANKING.md) for the complete mathematical specification.

### 8.3 Confirming Vs. Falsifying A Theory: Settling Moves & Commands

- **Positive Proof (`success` / `duplicate`):** Individual commands settle when their `settled_by` fact is proven; moves settle when all `produces` facts are held; whole branches retire when `obsoleted_by` is achieved.
- **Fixable Environmental Traps (`environment-error` / `blocker.*`):** Clock skew (`KRB_AP_ERR_SKEW`), missing `/etc/hosts` entries, or non-interactive TTY errors never retire the move; they surface a reactive Fix Doctor card.
- **Target Refusal (`authorization-denied` / `rejected`) & Clean Negative Results (`completed-negative` / `failed`):** Retires the tried command in the current `accessEpoch` (`accessEpoch(facts)`), increments `moveDryTriesInEpoch` so untried hypotheses rotate to `#1`, and automatically wakes the move back up when a new credential, hash, or foothold transitions the engagement into a new `accessEpoch`.

---

## 9. Guardrails And Verification

Correctness is enforced mechanically across the codebase:

- **`tools/move-lint.js --check`**: Enforces the move contract across all 355 moves across 19 packs.
- **`tools/gap-report.js --check`** & **`tools/post-parse-audit.js --check`**: Verifies 0 `parseGap`, 0 `parsePartial`, 0 `unreachable`, 0 `deadEnd`, 0 `orphan`, 0 `drift`, 0 `missedGain`, 0 `probeRetire`, 0 `reOffer`, and 0 `failureGap`.
- **`tools/gate-audit.js --check`**, **`tools/field-notes-coverage.js`**, **`tools/lint-study.js --check`**, **`tools/attack-coverage.js`**.
- **`tools/ranker-sim.js`** (8 archetypes, 25 stages) & **`tools/ranker-sweep.js`** (2,500 sampled states, 0.0% violation rate).
- **`99 engine smoke suites` in `tests/engine/`** (plus legacy suites in `tests/engine/legacy/` and golden-path box replays in `tests/engine/corpus/*.json`).
- **`12 Playwright specs` in `tests/e2e/`** (and `tests/browser-smoke.js` headless Chromium verification with 0 console errors).
- **`tools/stamp-assets.js`**: Refreshes content-hash cache-bust stamps (`?v=...`) across `index.html` and `assets/ui/lazy.js`.

---

## 10. Build Pipeline And Deployment

There is no runtime build. The generators turn hand-authored source into bundled globals:

- `tools/build-packs.js`: `data/packs/*.json` (19 packs, 355 moves) -> `data/packs-bundle.js`.
- `tools/flag-paths.js --emit`: Regenerates `docs/FLAG-PATHS.md` and `data/flag-reach.js`.
- `tools/build-gtfobins.js`: GTFOBins source -> `data/gtfobins.js`.
- `tools/build-playbooks.js`: `data/playbooks/` -> `data/playbooks-bundle.js`.
- `tools/stamp-assets.js`: Content-hash cache-bust stamps in `index.html` and `assets/ui/lazy.js`.
- `tools/publish/publish.mjs`: Syncs verified, stamped bundles from `qa/` to `prod/`.

---

## 11. Extending The System

- **Add a move:** Add a node to the appropriate `data/packs/*.json` (including `oscp_gapfill_2026_10.json`), add its 1:1 `data/field-notes.js` entry and `data/study-fixtures.js` entry, run `node tools/build-packs.js` and `node tools/flag-paths.js --emit`, and verify with `move-lint.js`, `gap-report.js`, and `post-parse-audit.js`.
- **Add a parser signal or inference rule:** Mint the fact in `assets/engine/parsers/*.js` (or `inference.js`), declare the emitted kind in `data/parser-signatures.js`, and ensure a downstream move or terminal classification consumes it.
- **Add a surface that shows "next move":** Call `OBOL.coach.rankFor(facts)`. Never re-implement ranking.
- **Keep the engine pure:** Everything under `assets/engine/*` must run identically in `window`, Web Worker, and Node.

---

## 12. Directory Map

```
index.html                 the app; critical boot path + lazy route registration
AGENTS.md                  agent entrypoint + working rules
CLAUDE.md                  master reference, verification gauntlet, and milestone log
README.md                  operator-facing tour
ARCHITECTURE.md            technical architecture & deterministic engine guide
RANKING.md                 7-tier Causal Frontier & Bayesian Utility Ranking specification
INFERENCE.md               3-tier Wittgensteinian Contextual Inference & parser specification
OPEN_ITEMS.md              active roadmap and UX/accessibility open items
docs/
  MOVE-ENGINE.md           the move/ranking contract (read before touching moves)
  DECISION-MAP.md          the decision graph and gap-report guide
  FLAG-PATHS.md            generated port-to-flag reachability map (tools/flag-paths.js --emit)
  CORPUS-MINING.md         walkthrough and tool-output corpus mining methodology
  CORPUS-LEDGER.md         running ledger of mined walkthroughs and derived signals
assets/
  css/obol.css             the single stylesheet (tokens + 7 skins + responsive layout)
  engine/                  the pure, shared engine (window / worker / Node)
    facts.js phases.js context.js pack.js packs.js command.js outcomes.js
    workspace.js vfs.js loot.js profile.js findings.js resolve.js
    graph.js chain.js engmap.js bloodhound.js decisionmap.js frameworks.js
    report.js study.js toolbuilder.js toolkit.js shellkit.js pivotkit.js
    workbench.js pivotdoctor.js arsenal.js library.js cruise.js playbooks.js stuck.js
    parsers/               18 files: index.js + common.js + nxc-catalog.js + inference.js + 14 domain modules
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
  packs/*.json             19 JSON move packs (355 moves, 1,923 commands; includes oscp_gapfill_2026_10.json)
  packs-bundle.js          GENERATED by tools/build-packs.js (do not hand-edit)
  tool-staging.js          ObolToolStaging (13 Hero Deck payload keys + on-host staging cradles)
  resources.js             curated OSCP resources and practice scenarios for #/start
  help-content.js          4-tab Help & 7-chapter Operator Manual content + 32-term glossary
  study-fixtures.js        355 move keys (100% 1:1 coverage across all 355 active moves) & 37 practice box walkthroughs
  field-notes.js findings-catalog.js narratives.js gtfobins.js toolset.js tool-glossary.js
  decision-forks.js parser-signatures.js coverage-expected.js flag-reach.js ...
tools/                     generators, linters, ranker simulators, and publish pipeline
tests/
  engine/*.js              98 pure-Node engine smoke suites
  engine/legacy/           legacy engine regression suites
  engine/corpus/*.json     golden-path box walkthroughs
  e2e/                     12 Playwright E2E specs
  browser-smoke.js         headless-Chromium smoke of the real app
```

---

*Obol web is AGPL-3.0. The engine is a faithful port of `obol-local`; keep behavior parity, and let
the test suites tell you when it drifts.*
