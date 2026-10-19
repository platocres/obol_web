# Obol Architecture

This document explains how obol is put together and why. It is for anyone who wants to understand,
audit, or extend the technical side of the project. For the operator-facing tour, read
[README.md](README.md).

obol is a static, browser-local penetration-testing methodology coach. You paste the output of the
tools you run, obol parses it into facts, and a deterministic engine ranks the exact next move for
the box in front of you, with the command pre-filled from what it has learned.

## 1. What it is, and the non-negotiable contract

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

## 2. The core idea: facts, moves, goals

Three primitives drive everything:

- **Facts** are small, typed, append-only assertions about the target, each minted by a parser from
  real tool output (`ldap.reachable`, `ad.user_list`, `credential.validated`, `objective.root_flag`).
  Facts are proof-gated: a fact exists only because something you pasted proved it.
- **Moves** are methodology steps. Each declares what it requires, what it produces, a phase, a
  priority, and one or more commands. A move becomes eligible when its required facts are present.
- **Goals** are the objectives (a foothold, a credential, domain compromise, the flags). The coach
  ranks eligible moves by how much they advance you toward the current goal.

## 3. Layered architecture

Three layers, cleanly separated:

- **The pure engine** (`assets/engine/`) is plain functions over facts and packs. It has no DOM and
  no storage dependency, so it runs identically in the page, in a worker, or headless.
- **The UI** (`assets/ui/`) is the DOM, the router, the store (IndexedDB), and one file per surface.
  It reads the engine and renders; it never encodes methodology itself.
- **The data** (`data/`) is the generated move bundle plus the reference catalogues the engine reads.

### Boot order (the critical path)

`index.html` loads the engine and the data bundles up front (they are small and pure), then boots the
UI, restores the active engagement from IndexedDB, and registers the routes. Heavy surfaces are
lazy-loaded on first navigation.

## 4. The pure engine (`assets/engine/`)

- **`facts.js`** is the fact ledger: the typed fact model, the proof states, and a `FactSet` that
  dedups on (kind, scope, value) and answers "do I have this fact".
- **`phases.js`** is the phase model (recon, enum, creds, access, escalate, loot) and the frontier
  computation that says how far along the box you are.
- **`pack.js`** (with **`packs.js`**) is the planner and the coach ranker: it loads the packs, decides
  which moves are eligible, and sorts them. See section 8.
- **`command.js`** fills a move's command template from the engagement parameters and the earned
  facts, and hides any command still waiting on a fact you have not proven.
- **`workspace.js`, `vfs.js`, `loot.js`** model the operator's working directory and output paths, so
  a command writes to a sensible file and later moves can read it back.
- **`parsers/`** is the conservative parser pipeline: a dispatcher plus a common library and one
  module per protocol or tool family. Parsers only mint a fact when the output genuinely proves it.
- **`findings.js`** (with `data/findings-catalog.js`, `data/narratives.js`) turns proven facts into
  report findings with severity, remediation, and references.
- **`resolve.js`** (with `data/gtfobins.js`) is the reference resolver: given a parsed fact (a SUID
  binary, a hash type), it hands back the exact, pre-filled next thing to try.
- **`graph.js`, `chain.js`, `engmap.js`** are read-only projections of the move graph used by the
  map, the decision tree, and the lane views.
- **`bloodhound.js`** (with `workers/bloodhound-worker.js`) ingests a BloodHound collection and
  derives owned-to-Domain-Admin paths, closeness-to-goal, and the best next accounts to hunt, off the
  main thread.
- **`report.js`, `study.js`, `workbench.js`, `arsenal.js`** power the report writer, the methodology
  training mode, the Workbench tools (hash identifier, reverse-shell builder, encoder/decoder, JWT,
  wordlists, manual SQLi, and more), and the installed-tools helper.

## 5. The data layer (`data/`)

- **The move set** ships as a generated bundle (`data/packs-bundle.js`, the `OBOL.packData` global).
  It is produced from curated source and is the single source of truth for every move and command.
- **Other data** bundles carry the reference material the engine reads: the findings catalogue, the
  GTFOBins data, the ATT&CK and D3FEND maps, the KEV list, field notes, narratives, and the fact
  catalogues the Stuck and Help surfaces use. Everything is bundled JavaScript so the app loads
  instantly with no network calls.

## 6. The UI layer (`assets/ui/`)

- **`store.js`** owns the engagement state in IndexedDB: parameters, the fact ledger, activities,
  checklist, and per-surface view state. It is the one store; every surface reads and writes it.
- **`router.js`, `lazy.js`** are the hash router and the lazy-group loader.
- **`ingest.js`** is the Evidence pipeline: it splits a pasted session into per-command segments,
  routes each to a host, runs the parsers, and folds the minted facts into the store.
- **`routes/`, `boot.js`** are one file per surface (Next Steps, Evidence, Map, Domain, Creds,
  Findings, Report, Workbench, Stuck, Help, Cruise, and more) plus the shell and navigation.

## 7. How Obol Parses Inputs (Pastes) And Mints Facts

When an operator pastes terminal output (via QuickPaste `Ctrl+V`, a move card, Cruise, or Evidence), it flows through a **4-stage ingestion pipeline**:

```
Raw Terminal Paste
   │
   ▼
1. Session Splitter & Scrollback Trimmer (assets/ui/ingest.js)
   │  Splits multi-command scrollback or Cruise markers (===== OBOL STEP ... =====)
   │  Extracts typed command, strips ANSI escape codes & spinner CR overwrites
   ▼
2. Scope & Context Router (assets/ui/ingest.js: detectTarget / detectLhost)
   │  Auto-learns {{lhost}} from prompt stamps; routes output to host:<ip> or domain:<name>
   ▼
3. Multi-Strategy Fan-Out Dispatcher (assets/engine/parsers/index.js: parseActionOutput)
   │  ├── Command-Gated Dispatch (nmap, nxc, ldapsearch, impacket, certipy, hashcat...)
   │  ├── Content-Sniffed Dispatch (recognizes linpeas, winpeas, bloodhound, mimikatz, flags even without a command line)
   │  ├── Blocker & Auth Failure Dispatch (blockers.js: clock skew, lockout, access denied...)
   │  └── Output-Shape Fallback (shape.js: bare port tables, HTTP responses, CVE/version banners)
   ▼
4. FactSet Deduplication & Proof-State Ledger (assets/engine/facts.js: FactSet.add)
```

### Key Parsing Design Principles

1. **Dual Routing (Command + Content Signatures)**:
   - In `assets/ui/ingest.js` (`run`), obol inspects what the paste *actually shows* (`deriveCommand` + `dispatchLabel`) rather than blindly trusting which card the user pasted into. If you paste `ldapsearch` output into an Nmap card, or paste a raw file attachment with no prompt at all, `assets/engine/parsers/index.js` routes on both the command string and conservative content regexes (and falls back to `assets/engine/parsers/shape.js` for bare outputs).
2. **Conservative Proof Gating ("Running a command != It worked")**:
   - Parsers never mint a fact merely because a command ran. For example, running `nxc smb 10.10.10.5 -u '' -p '' --shares` only mints `smb.null_session` if `[+]` session establishment is present, and only mints `smb.readable_share` if a non-`IPC$` share has `READ` permissions.
3. **Three Proof States (`ProofState` in `assets/engine/facts.js`)**:
   - `SUPPORTED`: Evidence affirmatively established the claim (gates `FactSet.has(kind)`).
   - `REFUTED`: Evidence proved the claim is *false* (for example, `credential.validation` with `works: false`, or an anonymous bind explicitly rejected).
   - `INCONCLUSIVE`: Attempted, but output was ambiguous.
   - If a fact's proof state changes on a later paste (for example, an earlier assumption is refuted or superseded), `FactSet.prototype.add` updates the state in-place on `(kind, scope, value)` so stale claims immediately stop gating the planner.

---

## 8. How Obol Hypothesizes Deterministically

Every move in obol is an explicit **testable hypothesis** about the target. In `assets/ui/routes/path.js` (`nsNarrative`), obol renders this cause-and-effect relationship directly on every move card:

> **"Because `<held prerequisite fact>` -> expect `<produced payoff fact>`"**
> *(for example, "Because **Domain User List** -> expect **AS-REP Hash**")*

To decide which hypothesis to test next, `nextActionsV2` in `assets/engine/pack.js` runs a **4-part deterministic ranking algorithm**:

### Step A: Eligibility Filtering (`Action.prototype.eligible`)

A move enters the candidate pool only if:
1. Its OS constraint matches `hostOsFamily(facts)` (inferred from Nmap banners, SMB/AD signals, or footholds).
2. Every fact in `requires_all` is `SUPPORTED` in the target's `FactSet`.
3. At least one fact in `requires_any` is `SUPPORTED`.
4. The move is neither `settled(facts)` nor `obsolete(facts)`.

### Step B: Recency & Evidence Tiering (`tier` in `assets/engine/pack.js`)

Every eligible move is placed into a strict priority tier based on **what your latest paste just proved**:
- **Tier 2 (`fresh`)**: Moves that were *locked* before your most recent paste and *just unlocked* because of a fact minted in the latest ingest batch (`v2Recency`). This captures operator momentum: *"I just got an AS-REP hash, so cracking it is my immediate next step."*
- **Tier 1 (`indicated` / `v2Earned`)**: Moves gated on a specific, high-signal earned primitive (`V2_SPECIFIC`, such as `privesc.sudo_rights`, `ad.control_paths`, `vuln.dirtypipe`, `smb.ms17_010`).
- **Tier 0 (Standard Enumeration)**: Routine eligible moves that advance discovery.
- **Tier -1 (`speculative` / unindicated gambles)**: Moves marked `speculative` or moves that claim a high payoff (a foothold or credential) from a bare open port *without* any supporting vulnerability fingerprint, hash, or credential (`v2Speculative`). These are capped at Tier -1 so blind gambles (like blind password spraying or unindicated CVE checks) never bury deterministic enumeration.

### Step C: Backward-Chained Goal Distance + 1-Step Forward Lookahead

Within each tier, obol scores every move over the hypergraph:

```
score(a) = Reliability(a) * ( prog(a) + 0.6 * enable(a) + 0.15 * keystone(a) ) + TransitionBonuses(a)
```

- **`prog(a)` (Goal Progress via Backward Chaining)**: `v2GoalDistance` computes the minimum number of steps from the current facts to any Goal (`AND` over `requires_all`, `OR` over `requires_any`). `prog(a) = d0 - d(H U produces(a))` measures how many steps closer to root, Domain Admin, or flags this move takes you.
- **`enable(a)` (Best Door Opened)**: 1-step forward lookahead over all currently locked moves `b` that become eligible if `a` succeeds, rewarding the single deepest unlock.
- **`keystone(a)` (Breadth of Doors Opened)**: How many currently blocked moves `a`'s produced facts unblock (capped at `V2_KEYSTONE_CAP = 4`), so pivotal facts like `credential.available` or `ad.user_list` naturally bubble up.
- **`Reliability(a)`**: `1.0` for earned cash-ins (`v2Earned`), `0.8` for standard enumeration, `0.3` for generic privilege jumps, and `0.25` for speculative gambles.
- **Explore-vs-Exploit Opening Discipline**:
  - *Orient before exploit*: After a quick port scan, the thorough version scan (`scan.nmap.version`) and `diagnostic: true` moves with the highest `eliminates` breadth lead before deeper exploitation.
  - *Validate before use*: When a found credential is not yet validated, the cheap validation probe leads before moves that spend the credential.
- **A* Full-Route Planner (`planPath` in `assets/engine/pack.js`)**: Runs A* search over the action graph using `v2ActionCost` (earned = `1.0`, enum = `1.5`, speculative = `12.0`, plus a small `+0.3` locus surcharge for on-host commands) to display the complete multi-step **"Planned Route To The Objective"**.

---

## 9. Confirming Vs. Falsifying A Theory: Settling Moves & Commands

A deterministic coach must know both **when a theory succeeded** (so it advances the attack chain and stops nagging you to repeat what worked) and **when a theory failed** (so it retires dead ends, diagnoses fixable errors, and pivots to the next viable hypothesis).

### Case A: Confirming A Theory (Positive Proof)

When a paste mints the facts a command or move was designed to prove:
1. **Command-Level Settlement (`commandSettled` in `assets/engine/pack.js`)**:
   - Individual commands inside a move can declare `settled_by: ["smb.null_session"]` (or `ad.group_joined`, `objective.flag_located`).
   - Once that specific sub-question is answered, **that individual command disappears from the card**, while follow-up commands in the same move remain active.
   - Simultaneously, previously hidden commands that were waiting on an **Earned Token** (`{{domain}}`, `{{basedn}}`, `{{userlist}}`, `{{hashfile}}`, `{{user}}`, `{{password}}` in `assets/engine/command.js`) automatically un-gate and pre-fill with the newly parsed values.
2. **Move-Level Settlement (`Action.prototype.settled` in `assets/engine/pack.js`)**:
   - Once **every** fact in `action.produces` is held in `FactSet` (or, for multi-OS foothold moves, once the host's OS foothold/admin equivalent is held), `action.settled(facts)` returns `true`. The move retires from the active Coach queue because re-running it yields zero new graph progress.
3. **Obsolescence & Goal Cash-In (`Action.prototype.obsolete` in `assets/engine/pack.js`)**:
   - If a later achievement makes an entire branch moot (for example, achieving `foothold.linux`, `access.root`, or `loot.ntds` is listed in an earlier move's `obsoleted_by`), `action.obsolete(facts)` retires the entire branch, both ready and locked moves alike, so the coach never steers you toward a means to an end you already hold.

### Case B: Proving A Theory False (Falsification & Dead-End Retirement)

When an operator runs a command and the theory fails, obol distinguishes **three different kinds of failure** so it never confuses a typo or clock-skew with a dead attack path:

```
Operator Pastes Unsuccessful / Empty Output
   │
   ├──► 1. Fixable Environmental / Syntax Trap (isEnvBlocker in ingest.js)
   │       Examples: KRB_AP_ERR_SKEW (clock skew), Name resolution failure, chmod 600 SSH key
   │       Result: Does NOT retire the move! Mints blocker.* and surfaces a reactive
   │               "DIAGNOSTIC DETECTED" Fix Card (path.js) with the exact fix command.
   │               Auto-retracts the blocker as soon as the fix or next command succeeds.
   │
   ├──► 2. Explicit Target Refusal (isRefusalBlocker / REFUTED in blockers.js & creds.js)
   │       Examples: STATUS_ACCESS_DENIED on null SMB, Anonymous LDAP bind disabled,
   │                 STATUS_LOGON_FAILURE (credential.validation works:false)
   │       Result: Mints refusal blocker + marks command/move tried in current Access Epoch.
   │               If other commands/tools exist on the card, advances to the next untried one;
   │               once all eligible commands are tried, retires the move (empty:<epoch>).
   │
   └──► 3. Clean Empty / Negative Result (Tool ran cleanly, >= 2 lines, 0 facts minted)
           Examples: GetNPUsers.py finds no AS-REP roastable users; find finds no SUIDs
           Result: Marks that command as "Already tried" (commandTriedInEpoch) and promotes
                   the next untried command on the card. When no untried commands remain on the
                   card for the current Access Epoch, marks checklist[moveId] = "empty:<epoch>"
                   (ingest.js) and retires the move from Ready Now!
```

### Access-Epoch Attempt Memory (`accessEpoch` in `assets/engine/pack.js`)

Why does obol retire a falsified move with `empty:<epoch>` instead of permanently deleting it?
- In penetration testing, **"SMB share enumeration proved nothing"** is only true *relative to your current privilege and credential state* (your **Access Epoch**, computed by `accessEpoch(facts)`: for example, `anon` -> `cred:svc-alfresco:pw` -> `fh:win|cred:svc-alfresco:pw` -> `adm:system`).
- If you run SMB share enumeration or BloodHound collection anonymously (`epoch = "anon"`) and it fails or comes back empty, `assets/ui/ingest.js` records `checklist[moveId] = "empty:anon"`, and `commandTriedInEpoch` retires those commands during the `anon` epoch.
- The moment you crack a password or land a foothold, `accessEpoch(facts)` transitions to a new epoch string (for example, `cred:bob:pw`). Every move that was marked `empty:anon` **automatically wakes back up** with its commands re-filled with `bob`'s credentials, ready to test the hypothesis under the new privilege state.

### Summary Table

| Stage | Component | What It Does |
| :--- | :--- | :--- |
| **1. Ingest & Split** | `assets/ui/ingest.js` | Splits terminal scrollback and Cruise batches, detects target IP and `{{lhost}}`, strips ANSI and spinners. |
| **2. Parse & Mint** | `assets/engine/parsers/index.js` | Dual command + content-signature fan-out; mints scoped `Fact` objects (`SUPPORTED`, `REFUTED`, `blocker.*`). |
| **3. Hypothesize** | `assets/engine/pack.js` (`nextActionsV2`) | Ranks eligible moves by Recency Tier -> Reliability * (Backward Goal Progress + Forward Enablement + Keystone Breadth). |
| **4. Confirm & Settle** | `commandSettled` / `Action.settled` / `Action.obsolete` | Retires individual commands once `settled_by` is proven; retires moves once `produces` or `obsoleted_by` is held; unlocks earned `{{tokens}}`. |
| **5. Falsify & Pivot** | `blockers.js` + `accessEpoch` + `empty:<epoch>` | Separates fixable env traps (shows reactive Fix Card) from negative results (retires command/move for the current `accessEpoch`, waking it up if new creds/access are earned later). |

---

## 10. Design Guardrails

- **The engine is pure.** It takes facts and packs and returns rankings, projections, and filled
  commands, with no DOM or storage dependency, so its behavior is fully determined by its inputs and
  is independently testable.
- **Parsers are conservative.** They never invent a fact; a fact exists only because the output
  proved it. This is what keeps the guidance trustworthy.
- **Presentation never forks the engine.** New surfaces are views over the one store, the fact
  ledger, the ranker, and the one command filler. They enrich presentation; they never rewrite the
  move graph or change which command the coach ranks.
- **House style.** Title Case for labels and headings; commas, colons, and periods rather than
  dashes.

## 11. Deployment

obol is served as static files (GitHub Pages friendly: an empty `.nojekyll` lets the asset folders
serve as-is). The data bundles are generated and committed, and asset references carry a content hash
for cache-busting, so a new release invalidates only what actually changed.

## 12. Extending The System

Adding a capability is almost always a data change: author a move (its requires, produces, command,
and field note) in the pack source, and the ranker, the map, the decision tree, and the study lane
all pick it up. A new parser mints a new fact kind; a new finding maps a fact to a report entry. The
engine code changes only when the mechanism itself changes.

## 13. Directory Map

```
index.html                 the app; boot path + lazy route registration
README.md                  operator-facing tour
ARCHITECTURE.md            technical architecture & deterministic engine guide
assets/
  css/obol.css             the single stylesheet (tokens + light/dark)
  engine/                  the pure, shared engine (page / worker)
    facts.js phases.js pack.js packs.js command.js cruise.js workspace.js vfs.js loot.js
    profile.js findings.js resolve.js graph.js chain.js engmap.js bloodhound.js
    report.js study.js workbench.js arsenal.js library.js pivotkit.js shellkit.js toolkit.js
    parsers/               the conservative parser pipeline (index + common + per-protocol)
    workers/               bloodhound-worker.js (runs the pure engine off-thread)
  ui/                      the DOM / IndexedDB / router layer
    store.js router.js lazy.js boot.js ingest.js util.js icons.js settings.js
    routes/                one file per surface (path, home, cruise, domain, findings, report, ...)
data/                      the generated move bundle + reference catalogues (bundled JavaScript)
screenshots/               the images used by the README
```

---

*obol is AGPL-3.0.*
