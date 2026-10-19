# Obol Web: Master Reference & Active Backlog

Read and follow [AGENTS.md](AGENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md), [docs/MOVE-ENGINE.md](docs/MOVE-ENGINE.md), and [docs/DECISION-MAP.md](docs/DECISION-MAP.md).

**Repository Topology:**
- `e:\KaliFiles\obol\obol-site\qa` is the **authoritative development and QA workspace** (345 moves across 19 packs, 51 engine smoke suites, 24 build/audit tools). Always edit and run tests in `qa/`.
- `e:\KaliFiles\obol\obol-site\prod` is the **production static mirror** (bundled assets only; synced from `qa/` after verification).
- `e:\KaliFiles\obol\obol-site\obol` is a legacy snapshot directory; do not develop there.

---

## 1. Non-Negotiable Contracts & House Style

1. **Static, Browser-Local, Zero Execution, Zero Telemetry:**
   - Pure client-side HTML/CSS/JS plus bundled static data. Runs directly from `index.html` (`file://` or GitHub Pages) and in Node for tests.
   - Obol generates commands for a human to run externally and parses pasted terminal output into facts. It never executes commands or sends network traffic.
   - **Exam-Legal by Construction:** No LLM at runtime, no automated exploitation, no mass scanners.
2. **Pure Engine vs. UI Separation:**
   - Everything in `assets/engine/*` must be pure, dependency-free JS that runs in Browser, Web Worker, and Node. Never reference `window`, `document`, or DOM APIs inside `assets/engine/*`.
   - **One Store, One Filler, One Ranker:** All surfaces read `OBOL.store` (IndexedDB + in-memory cache), fill commands via `OBOL.command.fillCommand`, and rank moves via `OBOL.coach.rankFor` (`OBOL.pack.nextActionsV2`). Never fork state or re-implement ranking.
3. **Pack Source of Truth & Build Discipline:**
   - Edit moves in `data/packs/*.json`, NEVER directly in `data/packs-bundle.js`.
   - When adding or reordering commands in `data/packs/*.json`, update the corresponding `commands[]` array in `data/field-notes.js` in lockstep (1:1 index pairing).
   - When minting a new fact kind in `assets/engine/parsers/*.js`, register it in `data/parser-signatures.js` and ensure it has a downstream move consumer or terminal classification in `assets/engine/decisionmap.js`.
   - After ANY edit to `data/packs/*.json`, run `node tools/build-packs.js` and `node tools/flag-paths.js --emit`.
   - After ANY edit to JS, CSS, or bundles, run `node tools/stamp-assets.js`.
4. **House Style & Accessibility:**
   - **No em dashes or en dashes anywhere** in code, comments, strings, field notes, narratives, or docs. Use commas, colons, parentheses, or hyphens (` - `).
   - **Title Case** for UI labels, tabs, and section headings.
   - **No decorative emoji** in source files (enforced by `tests/engine/no-decorative-emoji.js`); use `OBOL.ic(name)` (`assets/ui/icons.js`).
   - **Accessibility is acceptance:** 11px font floor, WCAG-AA contrast across all 7 skins, colour never the sole signal, keyboard reachable, `prefers-reduced-motion` honoured, responsive from 4K down to 320px.

---

## 2. The Verification Gauntlet (Live Green Baselines)

Run these from `e:\KaliFiles\obol\obol-site\qa` before and after any change. Every check below is currently **100% green** and must remain green:

```powershell
# 1. Regenerate bundles & reachability map (after pack edits)
node tools/build-packs.js
node tools/flag-paths.js --emit

# 2. Structural & methodology linters (must all exit 0)
node tools/gap-report.js --check          # 0 parseGap, 0 parsePartial, 0 unreachable, 0 deadEnd, 0 orphan, 0 drift
node tools/post-parse-audit.js --check    # 0 missedGain, 0 probeRetire, 0 reOffer, 0 failureGap
node tools/move-lint.js --check           # 0 FAIL across 345 moves
node tools/gate-audit.js --check          # 0 dead gates, 0 ungated moves, 0 phase-effect faults
node tools/field-notes-coverage.js        # 0 bare commands (use --missing <lane> to inspect fb+note)
node tools/lint-study.js --check          # LINT OK (no em/en dashes, study fixtures valid)
node tools/attack-coverage.js             # ATT&CK mapping integrity clean

# 3. Ranking scoreboard & fuzzer (must stay 0 violations)
node tools/ranker-sim.js                  # 0 / 25 violations across 8 archetypes
node tools/ranker-sweep.js                # 0.0% violation rate across 2,500 sampled states

# 4. Golden E2E replays & 51 pure-Node engine smoke suites
node tools/verify-replay-goldens.js       # HTB Forest (9 stages) + HTB Active (6 stages)
node tools/verify-oscp-practice-exams.js  # All 18 targets across OSCP A, B, and C
node tools/verify-e2e-flag-flow.js
node tools/verify-multi-target.js
Get-ChildItem tests/engine/*.js | ForEach-Object { node $_.FullName; if ($LASTEXITCODE -ne 0) { throw "Failed: $($_.Name)" } }

# 5. Stamp assets (always last after any asset/bundle edit)
node tools/stamp-assets.js
```

---

## 3. Codebase Quick Index

### Pure Engine (`assets/engine/`)
- `facts.js` - `Fact`, `ProofState` (`supported`/`refuted`/`inconclusive`), `FactSet` (`has`, `values`, `kinds`).
- `phases.js` - Phase ordering (`recon -> enum -> creds -> access -> escalate -> loot`), `phaseOfKind`, `phaseOfAction`, `evaluateEngagementState`.
- `pack.js` - `Action` model (`eligible`, `settled`, `obsolete`), `nextActionsV2` / `rankActions` coach ranker, `planPath` A* planner, `hostOsFamily`, `FRIENDLY` fact labels, `V2_SPECIFIC` evidence weights.
- `command.js` - `fillCommand`, `fillAll`, `commandContext`, `EARNED_TOKENS`, `commandTriedInEpoch`.
- `decisionmap.js` - `gapReport()` graph/parser X-ray powering `tools/gap-report.js`.
- `findings.js` - Fact-to-finding matcher (`evaluateFindings`, `observedFlags`, `presentHeaders`, `matchTriggerKinds`).
- `report.js` - OSCP report generator (`buildContext`, `collectProofs`, `findingTriggerActivities`, `initialAccessFindings`, `privescFindings`, Markdown/HTML/PDF/DOCX export).
- `bloodhound.js` - SharpHound/BloodHound-CE ingest, pathfinding (`ownedPaths`, `bestNextTargets`), `domainView`, `domainActionCommands`.
- `workbench.js` - Reverse-shell builder, hash identifier, multi-layer smart decoder/encoder, JWT decoder, GTFOBins browser, wordlist picker, manual SQLi builder, Explain Output, lockout-aware spray planner.
- `toolkit.js`, `toolbuilder.js` - Tools launchpad recipes, flag-by-flag glossary (`glossCommand`), station engine switching.
- `shellkit.js`, `pivotkit.js`, `cruise.js`, `library.js`, `resolve.js`, `study.js` - Access kits, Cruise batch planner, Library catalogue, GTFOBins resolver, Study engine.

### Parser Pipeline (`assets/engine/parsers/`)
- `index.js` - `parseActionOutput({ command, stdout, scope, source, domain })` dispatcher + content-sniff fallbacks (`_looks_like_linux_enum`, `_looks_like_windows_enum`).
- `common.js` - Shared regexes, `_OS_SIGNATURES`, `_add_os_from_text`, `_add_os_observation`, `_os_product_from_label`, `_check_linux_kernel_vulns`.
- `nmap.js` - Nmap text/XML/grepable parser, service reachability, OS banner/XML extraction, NSE vuln scripts.
- `services.js`, `directory.js`, `host.js`, `creds.js`, `web.js`, `websource.js`, `database.js`, `dns.js`, `pivot.js`, `findings.js`, `shape.js`, `blockers.js`, `nxc-catalog.js`.

### Data (`data/`)
- `packs/*.json` -> `packs-bundle.js` (19 packs, 345 moves).
- `field-notes.js` - 100% per-move and per-command guidance + `FIELD_DOCTORS` blocker cards.
- `findings-catalog.js` & `narratives.js` - Vulnerability catalog rules and OSCP remediation/proves narratives.
- `parser-signatures.js` - Authoritative list of fact kinds emitted by each parser.
- `toolset.js`, `tool-recipes.js`, `tool-stations.js`, `tool-glossary.js` - Tool builders, presets, stations, flag dictionary.

### UI & Routes (`assets/ui/`)
- `store.js` (IndexedDB + memory cache), `ingest.js` (`run`, `splitSession`, `importSession`, `detectTarget`), `bind.js` (shared engagement-binding bar), `pivotstation.js` (shared Pivot UI).
- `routes/`: `path.js` (Next Steps Coach), `home.js` (Engagement Hub), `target.js` / `targets.js`, `evidence.js`, `tools.js`, `workbench.js`, `library.js`, `cruise.js`, `domain.js`, `findings.js`, `report.js`, `scoreboard.js`, `study.js`, `loadout.js`, `help.js`.

---

## 4. What Has Shipped (Completed Milestones)

- **Core Port & IA Overhaul:** Vanilla JS engine port of `obol-local` (`PARITY-OBOL-LOCAL` 100% complete, including all 11 credential/service parsers, `C-1/C-2/C-3` fixes, and 11 port modules), 7-tab global nav, Engagement Hub, and per-target workspace.
- **Workbench (PR #302, P0-P8):** 11 client-side utilities (Reverse Shell Builder with PowerShell `-EncodedCommand`, Hash Identifier, Encoder, Smart Decoder, JWT Decoder, GTFOBins Browser, Wordlist Picker, Manual SQLi Builder, Explain This Output, Lockout-Aware Spray Planner) + 100% Field Notes coverage across all 14 action lanes.
- **Cruise (CR0-CR3) & Library (PR #306, L1-L5):** Exam/Lab batch script generator with `===== OBOL STEP =====` self-segmenting ingest, and the 4-lens Library catalogue (Moves, Commands, ATT&CK, Stuck?).
- **Tools Revamp & Access Kits (TA-TD):** Shared engagement-binding bar (`OBOL.bind`), 4 substitute Stations (Port Scan, Web Content Discovery, Crack Hashes, Database Shell), 50 validated Tool Builders with flag glossaries, Shell Station (`shellkit.js`), and Pivot Station (`pivotkit.js` + `pivotstation.js`).
- **Holistic Ecosystem Overhaul (Phases 1-4):**
  - Hardened OS/distro/version identification across all parsers (`common.js`, `nmap.js`, `services.js`, `directory.js`, `host.js`, `shape.js`, `index.js`), including Samba-vs-Windows disambiguation and version-range detection for DirtyCow, DirtyPipe, Baron Samedit, Polkit, and GNU Screen 4.5.0.
  - Wired all orphan parser facts, eliminated all `parseGap`, `parsePartial`, `missedGain`, `probeRetire`, `reOffer`, and `failureGap` issues (`gap-report.js` and `post-parse-audit.js` both at `0` across all lenses).
  - Connected `parsers/findings.js` <-> `engine/findings.js` <-> `data/findings-catalog.js` <-> `engine/report.js` so all security headers, flags, move-level findings, proof flags, and discovery+exploitation command chains render in the OSCP exam report.

---

## 5. Active Master Backlog & Flash Handoff Specs (`docs/tasks/`)

Each item below has a self-contained, line-numbered implementation spec in `docs/tasks/` designed so a fast, cost-effective model (e.g., Gemini Flash) can execute it with zero ambiguity, followed by a quick verification pass:

- [x] **[TASK-01: Interactive Session Splitter & Multi-Host Scoping](docs/tasks/TASK-01-ingest-and-multihost-hardening.md)**
  - Teach `splitSession` in `assets/ui/ingest.js` to split interactive sub-shell prompts (`mssqlclient.py` `SQL (...)>`, `mysql>`/`MariaDB`, `postgres=#`, `smb: \>`, `rpcclient $>`, `ftp>`, `meterpreter >`).
  - Audit and test multi-host vs. domain-scoped fact isolation in `assets/engine/command.js` so host-local facts (`objective.flag_located*`, `foothold.*`) never bleed across targets in multi-box engagements.
- [x] **[TASK-02: Remaining OSCP Curriculum Gaps](docs/tasks/TASK-02-oscp-curriculum-gaps.md)**
  - Add explicit hashcat/john moves or command variants for LM (`-m 3000`), NetNTLMv1 (`-m 5500`), and Kerberos TGS AES-128/256 (`-m 19600` / `-m 19700`) in `data/packs/cracking_2026_09.json`.
  - Add Volume Shadow Copy (`HiveNightmare` / `SeriousSAM` `HarddiskVolumeShadowCopy1`) extraction command to `windows-old-hives` in `data/packs/windows_privesc_2026_09.json`.
  - Add explicit `ESC3` (`-on-behalf-of`) and `ESC4` (`certipy template` write-ACL) commands to `adcs-esc` in `data/packs/ad_2026_09.json` (with 1:1 `data/field-notes.js` entries).
- [x] **[TASK-03: Lead-Command Ordering Auditor & Service Version Upper-Bounds](docs/tasks/TASK-03-lead-command-and-service-version-guards.md)**
  - Add Check #4 (`LEAD ORDER`) to `tools/post-parse-audit.js` to flag moves whose `commands[0]` gates on an unearned token when an ungated command exists at a later index, and fix any flagged moves.
  - Add upper-bound version guards in `assets/engine/parsers/nmap.js` and `services.js` so modern patched service banners (`Apache 2.4.5x+`, `OpenSSH 8.x+`, `Samba 4.1x+`) do not promote legacy exploit checks.
- [x] **[TASK-04: Cruise CR3 Single-Script Self-Healing Pivot Orchestrator](docs/tasks/TASK-04-unified-pivot-orchestrator.md)**
  - Upgrade `assets/engine/pivotkit.js` and `assets/ui/pivotstation.js` with runtime `tun0` VPN-drift self-healing, local subnet collision detection, `sudo -v` keepalive + `trap cleanup EXIT INT TERM` teardown, port cascade (`443 -> 8443 -> 80`), and the `=== OBOL PIVOT SYNC ===` paste-back token parsed by `assets/engine/parsers/pivot.js`.
- [x] **[TASK-05: OSCP Report Pre-Flight Grader & Archetype E2E Replays](docs/tasks/TASK-05-report-preflight-and-e2e-archetypes.md)**
  - Add `OBOL.report.preflightCheck(ctx)` in `assets/engine/report.js` (surfaced in Report & Scoreboard UI) warning if any captured flag lacks same-paste `whoami` + IP proof, if any compromised host lacks an Initial Access or Privesc chain, or if Lab-mode/restricted tools were used.
  - Add pure-Node stateful E2E replay tests (`tests/engine/linux-web-e2e-replay.js` and `tests/engine/win-standalone-e2e-replay.js`) alongside `forest-e2e-replay.js`.
- [x] **[TASK-06: UI Focus Mode, Help Completion (H2-H5) & Study Graph](docs/tasks/TASK-06-ui-focus-and-help-polish.md)**
  - Add Next Steps "Focus Mode" toggle in `assets/ui/routes/path.js` (collapsing non-lead commands behind `"N more ways -> Library"`).
  - Complete Help tab phases `H2-H5` (`data/help-content.js` & `assets/ui/routes/help.js`: deeper surface prose, expanded glossary, Help search bar, resumable Charon quick-start).
- [x] **[TASK-07: Loadout & Arsenal Provisioner Completeness](docs/tasks/TASK-07-loadout-arsenal-completeness.md)**
  - Upgrade `assets/engine/arsenal.js` (`download-arsenal.sh`) so `obol_fetch` extracts `.zip` archives (`Procdump.zip`, `AccessChk.zip`), `obol_git` creates executable shims in `~/.local/bin`, Linux staged binaries and pivot agents (`linpeas.sh`, `pspy64`, `chisel`, `agent`) are copied into `$WWW` and linked into `~/.local/bin`, filename aliases are created in `$WWW`, and `seclists` is installed if missing.
  - Expand `data/tools-install.js` (`OBOL.ARSENAL`) and `data/tool-staging.js` (`OBOL.TOOL_STAGING`) to cover 100% of tools, scripts, and staged binaries across all 345 moves and stations, verified by `tests/engine/arsenal-completeness-smoke.js`.

