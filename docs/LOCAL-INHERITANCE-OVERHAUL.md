# Obol Web — Local-Inheritance Overhaul — Build Plan & Context

> **Purpose.** Working brief for a multi-build effort to rebuild obol_web around the
> mature engine, packs, parsers, reporting, BloodHound analysis, checklist, and
> operator-console aesthetic proven in the sibling terminal tool **obol-local**
> (`platocres/obol-local`). Point an agent at this file to resume any build with full
> context.
>
> **This is a deliberately selected feature lane** (owner-directed), separate from the
> README Product Build Next queue. It supersedes the smaller `docs/EXPERIENCE-REVAMP.md`
> effort's scope where they overlap (Next Steps, report), and reuses that effort's
> shipped skin engine + palette as the theming substrate.
>
> _Last updated: 2026-09-26._

---

## 0 · The unifying insight

`obol-local/docs/SOURCES.md` states the lineage: **obol_web is the older planning app**
that obol-local mined its methodology from. Their schemas already map 1:1 — an obol_web
methodology card equals an obol-local `Action`
(`id, title, hypothesis, prereq{all,any} → requires_all/any, produces[], commands[{tool,run,note}],
expected[], onFailure, defender, report{finding,severity}, tools[], os[]`).

So this is not a port across foreign systems; it is **reuniting the child's grown-up brain
with the parent, over shared DNA.**

**North star:** turn obol_web into **the static-site edition of obol-local** — the same
surfaces, methodology, packs, parsers, coach, graph, checklist, BloodHound analysis, and
report, minus only the two things a static site cannot do (live command execution and the
SSE feed that streams run results). obol_web is a planner, so it never wanted those anyway.

**Everything the owner asked to inherit is portable.** obol-local's planner/coach is
*pure, deterministic, I/O-free* Python (`pack.py` + `phases.py` + `facts.py`, ~1,200 lines)
— it ports to browser JS directly. The only non-portable pieces are the **runner**
(executing commands) and the **SSE** live feed — and obol_web is a planning tool that
**deliberately never executes anything**, so those are things obol_web doesn't want anyway.

---

## 1 · Locked decisions (owner, 2026-09-26)

1. **New lean core, old app as donor.** Build a fresh, lean obol_web around obol-local's
   pure engine + packs. Harvest obol_web's still-good parts (Tool Builder engine, skin
   engine, report metadata, BloodHound CSV ingest, ⌘K palette/playbook/cred-matrix
   ergonomics) rather than patching the heavily-laden historical runtime.
2. **Reimplement obol-local's engine in vanilla JS** (planner, parsers, bloodhound) — no
   Pyodide/WASM. Stays truly static/offline/lean, matching obol_web's ethos. The
   obol-local 79-case parser fixture corpus becomes the JS test suite.
3. **First milestone = the coach** (Next Path overhaul). Proves the engine port
   end-to-end and delivers the centerpiece of the request.

### Non-negotiable product contract (unchanged from obol_web)

Static site, no backend, no telemetry, **no command execution**. Commands are generated for
a human to run externally. Conservative Evidence / proof boundaries are preserved.
Browser-local workspace only. Source stays directly runnable (open `index.html`); any
minification/compression is a delivery optimization, never required to develop.

### Performance & storage architecture (first-class requirement)

History to not repeat: obol_web struggled with many uncompressed runtime layers and tabs
that never loaded properly (e.g. `#/path` rendered twice via `setTimeout`/`hashchange`
races). The rebuild must be **smooth and fast**:

- **Browser database (IndexedDB) as the primary store**, not one synchronous localStorage
  blob. Async, structured object stores: `facts`, `evidence`, `targets`, `credentials`,
  `activities`, `bloodhound`, `screenshots` (Blobs), `settings`. localStorage is reserved
  only for tiny per-viewer prefs (active skin, last route). A thin async `store` module
  wraps IndexedDB with an in-memory cache so reads are cheap and writes never block paint.
  Migrate an existing `obol-state-v2` localStorage blob into IndexedDB on first load.
- **Offload heavy compute to the user's machine via Web Workers** — parsers
  (`analyzeTerminal`), the BloodHound owned→DA bounded DFS + census, and graph layout run
  in a worker so the main thread stays responsive on large inputs (SharpHound zips,
  long transcripts). Results post back and patch the DOM.
- **Small critical path, route-lazy everything else.** Boot loads only the engine trio +
  active-route bundle. Packs and per-surface code load on first navigation to that surface,
  cached thereafter. No 2.5MB uncompressed startup bundle; no long parser-blocking chains.
- **Deterministic rendering.** Each route renders **once**, from engine output, with no
  timing races or double-paints. Tab switches are instant (state already in memory);
  skeletons only where an async load is genuinely in flight.
- **Compressed delivery.** Ship minified assets; keep large static data (packs) as compact
  JSON, lazy-fetched. Rely on GitHub Pages gzip for text assets; measure real transfer size.
- **Budget & proof.** A boot-time-to-interactive and per-route request/byte budget is part
  of the milestone acceptance, checked by the browser smoke test — a regression fails CI.

---

## 2 · Source-of-truth map (what to port, from where)

All obol-local paths are read-only reference. All new code lands in obol_web.

### 2.1 The engine (reimplement in JS — pure functions)

| obol-local source | Lines | New JS owner (proposed) | What it is |
|---|---|---|---|
| `obol/facts.py` | 113 | `assets/engine/facts.js` | `Fact{kind,scope,value,state,source,created_at}`, `ProofState` (SUPPORTED/REFUTED/INCONCLUSIVE), `FactSet.has/values/kinds` |
| `obol/phases.py` | 138 | `assets/engine/phases.js` | `PHASES=[recon,enum,creds,access,escalate,loot]`, `_PHASE_RULES` longest-prefix kind→phase, `phase_of_action`, `target_phase`, `frontier_index` |
| `obol/pack.py` | 457 | `assets/engine/pack.js` | `Action.eligible/settled/unmet`, `next_actions()` ranking, `locked_actions()`; the `_FRIENDLY` kind labels (~200 kinds) |
| `obol/graph.py` `build_graph_model` + `build_graph_svg` | ~666 | `assets/engine/graph.js` | pure `{phases,nodes,edges}` model + inline-SVG renderer (obol-local's `webapp/static/js/views.js:flowSVG` is already the JS version with identical layout constants) |
| `obol/board.py` `command_context` + `fill_template` | — | `assets/engine/command.js` | `{{token}}` fill from facts, `shlex.quote` for shell-significant values, SSTI-payload protection |
| `obol/bloodhound.py` | 1507 | `assets/engine/bloodhound.js` | `parse()` (zip via JSZip — already vendored), `_derive_census`, `_owned_paths` (bounded DFS), `_paths_to_graph`, `domain_view`, `domain_report_html` |
| `obol/parsers/*` (16 modules, 129 fns) | — | `assets/engine/parsers/*.js` + one dispatcher | `parse_action_output` command-gated router; structured-first (nmap XML, ffuf/httpx/nuclei/feroxbuster JSON, airodump CSV), regex fallback |
| `obol/report.py` + `report_profiles/*` | ~1017 | `assets/engine/report.js` | profile → ordered sections → Block-doc → md/html; two-layer redaction (value + structural regex), base64 screenshots, OSCP proof/interactivity labels |

**Ranking (the coach core), verbatim intent:** `next_actions` filters to
`eligible(facts) && !settled(facts) && id∉done`, then sorts by the 3-tuple
`(max(0, phase_index(action) - frontier), on_type_nudge, -priority)`. The **frontier**
(`min(reached+1, last)`) is the key innovation: it separates *how valuable* a move is
(priority) from *is it time yet* (phase distance from the target's frontier). Moves ≥2
phases ahead are demoted below everything on-flow. This is what makes the path a coach,
not a flat cheatsheet.

### 2.2 The data (ship as static JSON)

- `obol-local/obol/packs/*.json` — **~157 actions across 14 action packs**
  (ad 47, web 23, recon 12, linux_privesc 12, findings_checks 11, windows_privesc 10,
  cracking 9, pivot 8, database 7, shells 6, pivoting 5, credential_access 3,
  flag_hunt 2, web_exploit_checks 2) + non-action data packs
  (`known_exploits`, `findings_catalog`, `web_fingerprints`, `cisa_kev`, `scripts`).
  Mind `obol-local/obol/packs/NOTICE.md` for licensing (project-authored).
- These replace the `data/lanes.js` (~142 cards) + `data/lanes-notes.js` (~53) +
  47 `methodology-v*.js` sprawl as the methodology source of truth.
- `obol-local/obol/playbooks/*.json` — 5 named ordered action sequences → power the
  playbook feature (obol_web already has a `.sh` exporter to reuse).

### 2.3 Harvest from current obol_web (keep, restyle)

- **Tool Builder engine** — `assets/tool-builder-current.js` (token compiler + `shellQuote`),
  `data/tool-builder-schema.js`, `data/tool-builders.js` (`tb-ffuf` golden pattern),
  `assets/tools-library-current.js`. The command *building* home. obol-local's
  `command_options.py` toggles + `HOST_COMMANDS` menus are ready-made additional inputs.
- **Skin engine + palette** — the 5-skin token system from `EXPERIENCE-REVAMP` (Build 1),
  reconciled with obol-local's console tokens (§4).
- **Ergonomics** — ⌘K palette (Build 2), playbook `.sh` export (Build 3), cred reuse
  matrix (Build 4), kill-chain spine (Build 5), favorites/history (Build 6).
- **Report metadata** — `data/reportmeta.js` (MITRE/NIST/CWE/CVE/remediation per card).
- **BloodHound CSV/JSON ingest** — `assets/bh.js` + JSZip (`assets/jszip.min.js`), folded
  into the new `bloodhound.js` (which adds the full census + attack-path analysis).
- **State model** — the fact-centric `obol-state-v2` localStorage shape + migrations
  (single key, `params/hosts/domains/facts/artifacts/credentials/activities/ui`).

### 2.4 Aesthetic to inherit (§4)

obol-local `static/style.css` (1758 lines) + `static/js/theme.js` + `core.js` constants.

---

## 3 · Target architecture ("new obol_web")

Three clean layers, fact-centric:

```
data/packs/*.json            (static methodology: ~157 actions + findings/fingerprints/exploits)
        │
assets/engine/*.js           (PURE, ported from obol-local: facts, phases, pack/planner,
        │                     graph, command-template, bloodhound, parsers, report)
        │
assets/ui/*.js               (routes render engine output; reuse obol_web's best UI, restyled)
        │
localStorage: obol-state (single fact-centric blob)
```

### The five operator routes (primary loop)

- **Home** — engagement context, coverage, blockers, report readiness.
- **Targets** — target cards (obol-local `.tcard` styling), scope, services.
- **Evidence** — paste tool output → JS parsers mint facts (replaces the 34
  `intake-v*` fragments) → coach recomputes. BloodHound zip upload lands here too.
- **Next Steps → the coach** — see §5 (milestone 1).
- **Report** — obol-local profile pipeline (OSCP/executive/technical), redaction on.

### Secondary surfaces

- **Tools** — the *only* place commands are *built*. Reduced to obol-local's equipped tool
  set, each builder very robust (§ M7).
- **Path graph** — `build_graph_model` + interactive SVG (a Next Steps view mode).
- **BloodHound / Domain** — upload SharpHound zip → census + attack paths + printable
  report, 100% client-side.
- **Checklist** — pack-driven, phase-grouped, tickable (localStorage).
- **Map** — engagement map (`build_engagement_graph` projection) if kept.

---

## 4 · Aesthetic reconciliation

obol_web already shipped a mature 5-skin theme engine (Classic/Ghostwire/Amber
Phosphor/Neon Noir/Recon Daylight). obol-local brings a stronger **operator-console
information design**. Reconcile, don't replace:

- **Adopt obol-local's layout + component vocabulary** — deep-navy/indigo elevation ramp,
  the **6 phase-accent colors** (`--ph-recon…--ph-loot`, used on flow chart / checklist
  heads / chain bar), severity scale, **mono-for-data + uppercase-tracked labels**
  typography, `.card`/`.pill`/`.tcard` atoms, the **objective chain bar**, the phase-colored
  flow chart, the BloodHound-idiom graph styling.
- **Render it through obol_web's skin tokens** — map obol-local's `--accent`/`--bg`/phase
  colors onto obol_web's existing `--accent`/`--bg`/etc. token names so the 5 skins survive
  as *palettes over the better layout*. obol-local's phase accents become new shared tokens.
- **Optional flair (opt-in):** animated canvas backgrounds, coin-burst on manual proof
  milestones, extra themes, the 8 layouts, the `--surface-alpha` see-through slider. Keep
  `prefers-reduced-motion` discipline from both apps.

Everything is plain CSS + vanilla JS in both apps — no framework to bridge.

---

## 5 · Milestone 1 — The Coach (Next Path overhaul)

**Goal:** replace the toggle-heavy path with a proof-gated coach that suggests *many*
ranked commands; move all command *building* into Tools.

**What's wrong today:** `#/path` renders twice (dead legacy `viewPath()` toggle-list, then
`operator-route-current.js` coach-ish surface); and every "Open" dumps the operator into
the per-card toggle builder (`optsHTML`/`renderCmdWithOpts` in `obol-app-current.js`). The
existing "suggest a command" primitive (`data/scripts.js`, ~21 prereq-gated snippets) is the
right shape but far too thin vs. obol-local's ~157 proof-gated actions.

**Build:**
1. **Port the engine trio** — `facts.js`, `phases.js`, `pack.js` (§2.1) as pure JS.
2. **Ship the packs** — `data/packs/*.json` from obol-local; a loader that concatenates +
   dedupes by id (first wins), exactly like `load_packs()`.
3. **Port command templating** — `command.js` (`{{token}}` fill from facts + shell-quote).
4. **Coach UI** — a ranked list of moves, each showing: title, one-line *why* (hypothesis),
   **copy-ready command variants** (all `commands[]`, not toggles), *does-not-prove* honesty
   line, `produces` facts, and a **paste-back** affordance. Frontier-aware ordering; blocked
   moves shown separately with their unmet-prereq reason (`locked_actions`).
5. **Move building out** — "Open / build this command" links to the **Tools** builder for
   that tool, not to a per-card toggle form. Retire the legacy `viewPath()` render entirely.
6. **Stand up the store** — the async IndexedDB `store` module (§ Performance & storage) with
   its in-memory cache and the `obol-state-v2` localStorage → IndexedDB migration. The coach
   reads facts from it.
7. **Wire the loop** — Evidence paste → (milestone 2 parsers, or interim manual fact add via
   the existing sidebar Facts panel) → `next_actions` recompute → single re-render.

**Acceptance:**
- Next Steps shows a ranked, frontier-aware list of proof-gated commands from the ported
  packs; **no toggles/switches on the path surface**.
- Each move exposes its command variant(s) copy-ready, its *why*, its *does-not-prove*, and
  its `produces`.
- Blocked moves are listed with reasons; adding the unlocking fact promotes them live.
- Command *building* happens only in Tools.
- Ranking matches obol-local's `next_actions` order for a shared fact set (port test).
- State lives in IndexedDB (async, non-blocking); an old localStorage workspace migrates in.
- Static/offline; no execution; the route renders **once** (no double-paint/`setTimeout`
  races); boot + Next Steps meet the performance budget; no console errors.

---

## 6 · Later milestones (sequence TBD with owner)

- **M2 — Parsers.** Port the 16 parser modules + dispatcher to JS; wire Evidence paste-back
  to mint facts. Bring the **79-case golden fixture corpus** as the JS test suite (encodes
  the anti-overclaim contract via `forbidden_supported_kinds`).
- **M3 — Path graph.** `build_graph_model` + SVG renderer as a Next Steps view mode.
- **M4 — BloodHound domain analysis.** SharpHound zip → census + attack paths + printable
  report, client-side (JSZip). Crown-jewel "wow".
- **M5 — Checklist.** Pack-driven, phase-grouped, tickable (localStorage).
- **M6 — Reporting (improve the existing feature).** obol_web already generates standard +
  OSCP Markdown (`report.js` + `reportmeta.js`). Do not rebuild — **vastly improve it** by
  grafting on obol-local's report pipeline: profile → ordered sections → one document →
  md/**html**; two-layer redaction (value-based + structural regex, on by default);
  base64-embedded screenshots; OSCP proof/interactivity discipline as UI labels. Keep the
  existing MITRE/NIST/CWE/CVE/remediation metadata as the finding backing.
- **M7 — Tools, reduced & robust.** **Collapse the Tools section to exactly the tool set
  obol-local is prepared to equip** — the union of tools referenced by obol-local's packs'
  `tools[]`/`commands[].tool` and its `command_options.py` (`_BY_TOOL`/`_BY_ACTION`) +
  `HOST_COMMANDS`. Delete obol_web's ~262 "modeled" placeholder inventory rows outside that
  set. **Every remaining builder must be very robust** — full flag/mode coverage, real
  presets, grouped fields, header/cookie snippets, credential modes, and evidence
  expectations to the `tb-ffuf` golden-surface depth (not a thin one-liner). Fold
  obol-local's `command_options` toggles + `HOST_COMMANDS` menus in as builder inputs. This
  is the **only** surface where commands are *built*.
- **M8 — Aesthetic pass.** §4 reconciliation across all surfaces.
- **Mx — Baggage purge.** Delete the versioned ledger, `data/product-hardening/`
  (98 files/1.9MB), the note-mining pipeline, 180 per-version docs, most of the 49
  validators + 47 `run-v*` tests. The runtime manifest's retired/live lists are the deletion
  map. (Can run early to clear ground, or in waves as owners are replaced.)

---

## 7 · Baggage deletion map (from the runtime manifest)

Runtime loads only ~23 `-current` bundles + `data/runtime-manifest.js`. Candidate removals
(none are loaded at runtime; the manifest already flags retired vs live):

- **Versioned source ledger** — `data/*.js` 141 files (47 `methodology-v*.js`, ~24
  `orange-fidelity-v*.js`, ~23 `project-model-v*.js`, ~20 `dashboard-v*.js`); `assets/*.js`
  236 files (only 23 `-current`; rest are `app-v*`/`core-v*`/`intake-v*`/`report-v*`/`nmap-v*`).
- **Product-hardening machinery** — `data/product-hardening/` 98 files/1.9MB (~5 load);
  `product-hardening.html`; `assets/product-hardening-dashboard.js`.
- **Note-mining pipeline** — `note-integration*.js`, `lanes-notes.js`, `field-notes.js`,
  10 `docs/NOTE*` docs, `tools/validate-note-*.js`, `tools/select-next-notes-batch.js`.
- **Docs** — 180 per-version `docs/v*.md`, `docs/CHANGELOG-through-v7.6.md`, process docs.
- **Tooling/tests** — most of 49 `tools/validate-*.js` + 47 `tests/run-v*-tests.js` (they
  police the ledger being deleted).

Preserve: browser-local workspace migration/export, conservative proof boundaries,
human-run command behavior. Delete only with a green replacement owner in place.

---

## 8 · Working rules

- **Repos:** develop on branch `claude/obol-web-overhaul-local-59ttbx` in
  `platocres/obol_web`. `platocres/obol-local` is **read-only donor/reference** — do not
  push to it. Commit/push only when the owner asks; open a PR only when asked.
- **New lean core:** build the new engine/data/ui under clean paths; keep old files as
  reference until a surface is replaced, then delete per §7. Do not extend the old
  versioned-source→generated-bundle machinery for new work.
- **Prove behavior:** port obol-local's tests where they apply (planner ranking, the 79
  parser fixtures, redaction, bloodhound census). Keep a browser smoke check green.
- **No execution, ever.** The Tool Builder schema already forbids `execute/exec/spawn/
  runCommand/autoRun`; keep that invariant everywhere.
