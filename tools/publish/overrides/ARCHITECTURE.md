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

## 7. The evidence loop (how a paste becomes guidance)

You run a command, paste its output into Evidence (or onto the move card), and the loop runs: split
the paste, route it to the target, parse it into facts, fold those facts into the store, re-rank the
moves, and re-render. A command that has done its job retires from its card; the next move surfaces
with its command already filled from what obol just learned.

## 8. The coach ranker, concretely

Eligible moves are sorted by, in order: recency tier, then a score (goal progress plus an enablement
term plus a keystone term, weighted by each move's reliability), then the move's hand-tuned priority,
then a house-toolkit tie-break, then locus (remote-first), then id. Preferences are always expressed
as data or as soft tie-breaks below the hand-tuned priority, so the ordering stays legible and the
same facts always yield the same next move. A handful of surgical rules keep the sequencing sane (do
the thorough service scan before per-service recon, validate a found credential before leaning on it,
map the domain before abusing a named misconfiguration).

## 9. Design guardrails

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

## 10. Deployment

obol is served as static files (GitHub Pages friendly: an empty `.nojekyll` lets the asset folders
serve as-is). The data bundles are generated and committed, and asset references carry a content hash
for cache-busting, so a new release invalidates only what actually changed.

## 11. Extending the system

Adding a capability is almost always a data change: author a move (its requires, produces, command,
and field note) in the pack source, and the ranker, the map, the decision tree, and the study lane
all pick it up. A new parser mints a new fact kind; a new finding maps a fact to a report entry. The
engine code changes only when the mechanism itself changes.

## 12. Directory map

```
index.html                 the app; boot path + lazy route registration
README.md                  operator-facing tour
assets/
  css/obol.css             the single stylesheet (tokens + light/dark)
  engine/                  the pure, shared engine (page / worker)
    facts.js phases.js pack.js packs.js command.js workspace.js vfs.js loot.js
    profile.js findings.js resolve.js graph.js chain.js engmap.js bloodhound.js
    report.js study.js workbench.js arsenal.js
    parsers/               the conservative parser pipeline (index + common + per-protocol)
    workers/               bloodhound-worker.js (runs the pure engine off-thread)
  ui/                      the DOM / IndexedDB / router layer
    store.js router.js lazy.js boot.js ingest.js util.js icons.js settings.js
    routes/                one file per surface (path, home, domain, findings, report, ...)
data/                      the generated move bundle + reference catalogues (bundled JavaScript)
screenshots/               the images used by the README
```

---

*obol is AGPL-3.0.*
