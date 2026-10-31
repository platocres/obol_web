# OBOL Open Items: UX, Neurodivergent/Accessibility & Operator Roadmap

> **Trigger Phrase**: When the user says **"Let's look at open items"** (or asks about the roadmap, backlog, or next UX improvements), read this file (`OPEN_ITEMS.md` in `qa/`, dev-only) and keep it updated as items are completed or refined.

---

## October 2026 agreed review: items 1-3 implemented

- **Item 1, shared context:** target-specific credential selection, separate target domain/account realm, explicit no-credential selection, and a visible temporary cross-target pin. Command generation and recommendations use the same scoped context.
- **Item 2, truthful results:** recovered material, authentication, authorization, shell execution, and privilege are separate observations. Shared receipts cover supported success, completed-negative, rejection, denial, environment errors, partial/mixed/duplicate output, and unresolved/parser errors. Legacy unsupported claims are archived and automatic unsupported retirements reopen.
- **Item 3, behavioral verification:** CI now runs stateful engine, parser corpus, migration, export, and real-browser checks. Coverage reports distinguish declared capability from demonstrated samples and remaining gaps.
- **Item 4 remains under discussion.** The current Coach overview remains available; proposed alternative views are optional concepts. Cruise stays separate while experimental. Preserve the neon-glass visual language and meaningful methodology/organization/phase colors, with 1920x1080 as the primary desktop baseline and responsive behavior elsewhere.

See [`assets/engine/context.js`](assets/engine/context.js) and [`assets/engine/outcomes.js`](assets/engine/outcomes.js) for the implemented contract, migration behavior, and outcome classification rules. The UI ideas below are a backlog, not authorization to implement them.

---

## Pillar 1: Information Architecture & Navigation Consolidation

### 1.1 Streamline the 13-Item Engagement Sub-Nav (`assets/ui/ctxbar.js`)
> Unapproved historical proposal. In particular, combining Coach and Cruise conflicts with the current decision to keep Cruise separate.

- **Problem**: Inside an engagement, the user sees three control surfaces simultaneously: the top `appbar`, the 13-link `ctxbar` sub-nav (`Hub`, `Loadout`, `Targets`, `Next Steps`, `Evidence`, `Map`, `Domain`, `Creds`, `Checklist`, `Findings`, `Run Log`, `Flags`, `Report`), and the left `#sidebar`. 13 items in a secondary nav bar creates visual overload and splits unified workflows across multiple tabs.
- **Solution**:
  - Consolidate `ctxbar` from 13 links down to **6-7 primary engagement stations**:
    1. **Hub** (`#/home`)
    2. **Scope & Map** (`#/targets`, with an internal view switcher bar for `Target Board` | `Network Map (#/map)` | `AD Domain (#/domain)`)
    3. **Coach & Cruise** (`#/path` and `#/cruise` paired with a 1-click `Coach ⇄ Cruise` mode toggle in their headers)
    4. **Evidence & Log** (`#/evidence` with `Run Log (#/history)` integrated as a timeline sub-tab)
    5. **Loot & Creds** (`#/creds` and `Flags (#/scoreboard)` linked via sub-navigation)
    6. **Report & Findings** (`#/report`, `Findings (#/findings)`, and `Checklist (#/checklist)` grouped as the deliverable station)
    7. **Loadout** (`#/loadout`)
- **Key Files**:
  - `assets/ui/ctxbar.js`
  - `assets/ui/routes/evidence.js` & `assets/ui/routes/history.js`
  - `assets/ui/routes/targets.js`, `assets/ui/routes/map.js`, `assets/ui/routes/domain.js`

### 1.2 Seamless `Coach ⇄ Cruise` Mode Switcher & Inline Paste on Coach (`assets/ui/routes/path.js`, `assets/ui/routes/cruise.js`)
> The Coach/Cruise switcher is unapproved. Cruise stays separate. The old claim that Coach lacks inline paste is stale; retain the existing paste flow and shared outcome receipts.

- **Problem**: `Next Steps` (`#/path`, step-by-step Coach) and `Cruise` (`#/cruise`, automated batch stage scripts) are two ways of working the exact same active target/engagement, yet `Cruise` sits in the top global nav labeled `Experimental` and Coach cards require opening the modal overlay or leaving for `#/evidence` to paste output.
- **Solution**:
  - Add a 1-click **`Step-by-Step Coach ⇄ Cruise Stage Runner`** toggle pill in the header of both `#/path` and `#/cruise`.
  - Add an inline **`Paste Output for This Move`** drawer directly inside active Coach move cards on `#/path` (matching the zero-navigation paste experience on Target Dossier and Cruise).
- **Key Files**:
  - `assets/ui/routes/path.js`
  - `assets/ui/routes/cruise.js`
  - `index.html`

---

## Pillar 2: Neurodivergent (ADHD / AuDHD / Dyslexia) & Disabled Operator Pack

### 2.1 Rabbit-Hole Circuit Breaker / Box Dwell Guard (Time-Blindness Protection)
- **Problem**: During labs and 24-hour exams (OSCP/CPTS), ADHD time-blindness and hyperfocus cause operators to spend 3+ hours on a dead-end service port while other open ports or targets sit untouched.
- **Solution**:
  - Track time spent on the active target/phase since the last high-signal fact (`foothold.*`, `credential.*`, `access.*`, `privesc.*`, `objective.*`) was minted.
  - After a configurable threshold (e.g. **45-60 minutes** without new progress), surface a calm, dismissible **Rabbit-Hole Nudge** in the Coach/Hub header:
    - *"You have been enumerating `10.10.10.10` for 50m with no new facts. Want to check Stuck / Pivot Doctor, try another open port, or rotate to `10.10.10.20`?"*
- **Key Files**:
  - `assets/ui/store.js`
  - `assets/ui/routes/path.js`
  - `assets/ui/routes/home.js`

### 2.2 True "One-Move-At-A-Time" Zen / Focus Mode (`#nav-focus`)
- **Problem**: Clicking `Focus` (`#nav-focus` in `ctxbar.js`) currently sets `data-focus="1"` which hides only minor elements; `#/path` (Coach) still displays metrics, lens bars, multiple move cards, coming-up moves, and blocked moves. When an operator is fatigued or experiencing executive dysfunction, a wall of cards triggers decision paralysis.
- **Solution**:
  - Upgrade `data-focus="1"` into a true **Single-Card Zen HUD**:
    - Auto-collapse secondary rails, coming-up/blocked move lists, and non-essential chrome.
    - Spotlight **only the #1 Ready Move** with a large, high-contrast command block and an always-ready inline **Paste Output** box directly underneath (`Copy -> Run -> Paste -> Next Move`).
- **Key Files**:
  - `assets/ui/ctxbar.js`
  - `assets/ui/routes/path.js`
  - `assets/css/obol.css`

### 2.3 "Where Was I?" Per-Target Scratchpad & Context Resume Anchor (Working-Memory Aid)
- **Problem**: Rotating across 4-6 machines (or taking a break) wipes working memory: operators forget which terminal has which shell, what hash is cracking, or what hypothesis they were testing on a host.
- **Solution**:
  - Add a persistent 1-line **Pin-My-Thought / Scratchpad** field per target (`t.note` in `eng.targets`), editable inline on the Hub target row, Target Dossier (`#/target/<ip>`), and Coach header.
  - Show a compact **"Last 3 Actions on This Host"** breadcrumb strip when switching targets so context is restored in 2 seconds.
- **Key Files**:
  - `assets/ui/routes/home.js`
  - `assets/ui/routes/target.js`
  - `assets/ui/routes/targets.js`
  - `assets/ui/routes/path.js`

### 2.4 Motor / RSI Keyboard-First Operator Hotkeys
- **Problem**: Operators with RSI, motor impairments, or keyboard-centric workflows have to mouse-click tiny `Copy` and `Paste` buttons hundreds of times per engagement.
- **Solution**:
  - Add global single-keystroke shortcuts (active whenever focus is not in an `input`/`textarea`/`select`):
    - `c` -> Copy the #1 recommended command on the current screen (with toast confirmation)
    - `p` or `v` -> Open Quick-Paste (`#nav-paste`) and focus `#qp-text`
    - `1`-`9` -> Switch active target to target `#1`-`#9` in scope
    - `f` -> Toggle Focus / Zen HUD mode
    - `?` -> Open a clean Keyboard Shortcut cheat-sheet modal
- **Key Files**:
  - `assets/ui/palette.js` or `assets/ui/boot.js`
  - `assets/ui/quickpaste.js`

### 2.5 Sensory, Dyslexia & Color-Vision Controls in Settings (`assets/ui/settings.js`)
- **Problem**: Long terminal outputs and dense badges can strain low-vision, dyslexic, or colorblind operators during multi-hour sessions.
- **Solution**:
  - Expand the bottom-right Appearance Gear (`assets/ui/settings.js`) with an **Accessibility & Reading** section:
    - **Font Scale**: `100%` | `110%` | `120%`
    - **Dyslexia-Friendly Spacing Mode**: Increased line-height (`1.65`), wider letter/word spacing, and clear glyph separation.
    - **Colorblind-Safe Status Shapes/Icons**: Pair every status badge and phase chip with a distinct geometric/icon prefix (`◎ SCAN`, `◈ ENUM`, `🔑 CREDS`, `⚡ FOOTHOLD`, `★ OWNED`) so status is never conveyed by color alone.
- **Key Files**:
  - `assets/ui/settings.js`
  - `assets/css/obol.css`

---

## Pillar 3: Operator "Wow" Force-Multipliers

### 3.1 Sidebar 1-Click "Listener & PTY Shell Upgrade" Helper (`assets/ui/boot.js`)
- **Problem**: Catching a reverse shell and stabilizing a dumb netcat shell into a full interactive PTY (`python3 -c 'import pty; pty.spawn("/bin/bash")'`, `export TERM=xterm-256color`, `stty raw -echo; fg`) or serving/fetching files from `{{lhost}}` happens on almost every box, requiring repetitive typing.
- **Solution**:
  - Add a compact, collapsible **`⚡ Listener & Shell Upgrade`** helper drawer directly beneath `LHOST` / `LPORT` in the left `#sidebar`:
    - 1-click copy: `rlwrap -cAr nc -lvnp {{lport}}`
    - 1-click copy: Full Linux PTY upgrade sequence
    - 1-click copy: Linux (`curl`/`wget`) & Windows (`iwr`/`certutil`) download cradles pre-filled with `http://{{lhost}}/`
- **Key Files**:
  - `assets/ui/boot.js`
  - `assets/css/obol.css`

### 3.2 Live Exam Score & Proof-Readiness Auditor (OSCP / CPTS / Exam Profiles)
- **Problem**: On exams like OSCP (70/100 points to pass; strict OffSec rules requiring interactive shell flag read + `ipconfig`/`ifconfig` + `whoami` screenshot), students risk stopping early with a missing screenshot or miscounted points.
- **Solution**:
  - When `OBOL.profile.isExamPlatform(eng.profile.platform)` is active, display a live **Exam Score & Proof Audit** strip on the Hub (`#/home`), Flags (`#/scoreboard`), and Report (`#/report`):
    - Calculates estimated points earned across AD + standalone targets.
    - Highlights **Proof Warnings** before the operator tears down the VPN (e.g., *"Flag captured on `10.10.10.10` (`root.txt`), but no proof screenshot is attached yet"*).
- **Key Files**:
  - `assets/ui/routes/home.js`
  - `assets/ui/routes/scoreboard.js`
  - `assets/ui/routes/report.js`

---

## Pillar 4: Curriculum Coverage & Exam Onramp

### 4.1 Whole-Syllabus Audit Against the Engine
> Backlog, not authorization. Agreed direction for now: **stay narrow** (confirm only the handful of candidate gaps already flagged). This item records the larger audit so it is not lost.

- **Problem**: The 345-move graph grew organically, so we have no systematic check that every technique the OSCP (OffSec PEN-200) and CPTS (HTB) syllabi expect is represented end to end in the deterministic ecosystem: a move, a filled command, a parser that mints the right fact, a downstream consumer, and (where relevant) a finding and report wiring. Candidate gaps spotted from the PEN-200 and CPTS tables of contents: client-side attacks (Office macros, Windows library files, phishing delivery), AV evasion (on-disk, in-memory, thread injection), cross-compiling and fixing public exploits, cloud and AWS (S3, AWS CLI), LLM-aided enumeration, Net-NTLMv2 relaying, and deeper web-app coverage (IDOR, HTTP verb tampering, file-upload bypass chains, LFI wrapper chains).
- **Solution**:
  - Build a coverage cross-walk: a table mapping every syllabus technique to its OBOL move, command, parser, fact, and finding status, flagging blanks as backlog. Use the course tables of contents only as a private technique checklist. Author all OBOL content originally; never copy course prose.
  - Feed confirmed gaps through the normal pack, parser, field-note, and report pipeline under the existing lint and audit gates.
- **Key Files**:
  - `data/packs/*.json`, `data/field-notes.js`, `data/parser-signatures.js`
  - `assets/engine/parsers/*.js`, `assets/engine/decisionmap.js`, `assets/engine/report.js`
  - `tools/gap-report.js`, `tools/move-lint.js`, `tools/attack-coverage.js`

### 4.2 Start Here Onramp (Replaces The Learn Landing)
> Agreed direction. **Status: COMPLETE (2026-10-23).** Both the additive (`#/start`) and subtractive (`#/study`) halves are shipped and verified.

- **Problem**: Learn (`#/study`) opened on a dense landing (lanes, Atlas, by-port, gears) that assumed prior knowledge. New users needed an interactive onramp that teaches how OBOL works, helps them set up a lab, maps core pentest concepts and vocabulary, and places them into their first engagement before handing off to Learn's methodology reference.
- **Done (shipped in qa & prod):**
  - `assets/ui/routes/start.js` + `data/resources.js`:
    - **60-Second Interactive OBOL Sandbox** (`Try OBOL Right Now` with 3 realistic presets: Linux Web + SUID, Windows SMB + WinRM, Active Directory DC, live `OBOL.parsers.parseActionOutput` fact minting, and unlocked next moves).
    - ** Guided First Box Walkthrough** (5-step end-to-end operational loop from engagement setup to report export).
    - **Pentest Mental Model & Jargon Decoder** (12 core terms in plain English with direct links to Learn tracks and moves).
    - **3 Self-Placement Doors** (`New To All This`, `I Know The Basics`, `Prepping For An Exam`) with **1-Click Launch Practice Engagement** buttons on every curated exam box (OSCP, CPTS, PNPT) that pre-configure the engagement profile and navigate straight to `#/home`.
  - `#/study` (`assets/ui/routes/study.js`) stripped of duplicate onramp/front-door weight (`renderStartHere`, `renderFirstBox`, `renderPrereqs`) and focused purely on methodology, with a compact banner pointing new operators to `#/start`.
  - Verified by `tests/engine/start-route-smoke.js` (31 assertions) and `tools/lint-study.js --check`.

### 4.3 Curated Resource Index (Authored Help, Not A Link Farm)
> Agreed direction. Backlog, not authorization.

- **Problem**: Beginners stitch together VulnHub, TryHackMe, PortSwigger Academy, IppSec, HackTricks, GTFOBins and LOLBAS, tool docs, and course pages by accident. OBOL could centralize the map, but a bare link list adds nothing over existing aggregators.
- **Solution**:
  - A curated index living inside Start Here (4.2). Each entry is a stable, canonical link (download page, video channel, reference site) wrapped in original OBOL help: a short "what this is, when to reach for it, what to watch for" in OBOL's voice, cross-linked into the relevant move or field note where one exists.
  - Point links at the gaps the coach does not already teach (foundational theory, full courses, video walkthroughs). For anything OBOL teaches, the coach is the help and the link is only a citation.
  - A budget-aware "ways to practice" comparison, free paths first (VulnHub, TryHackMe free, PortSwigger Academy, OverTheWire, Proving Grounds Play), paid tiers above (TCM, HTB Academy, OffSec, SANS), with approximate price ranges and a "last verified" date, never precise figures that rot.
- **Key Files**:
  - `assets/ui/routes/start.js`, new `data/resources.js` (the curated index as data)
  - `assets/css/obol.css`

### 4.4 "Untried" Coverage Checklist (The Stuck-In-The-Exam View)
> Agreed direction. Backlog, not authorization. Exam-legal by construction: derives only from the operator's own facts and tried commands, suggests technique categories against the operator's own box, never a solution to a named exam host.

- **Problem**: When the Coach's ranked list thins out, a stuck operator (especially mid-exam) has no calm way to see which standard techniques for the current services and access level they have not yet tried. The methodology Checklist tracks what is proven, not what is unexplored.
- **Solution**:
  - Primary home: the Coach (`#/path`). When ranked moves thin out, surface an **auto "Untried" panel**: for the active target's services and current access, the eligible-but-untried move categories, in OBOL's voice, with no navigation.
  - Deliberate home: an **"Untried" lens** on the Checklist route (`#/checklist`), the inverse of the existing proven-coverage view, for scanning the whole surface on purpose.
  - Derive from the existing epoch and tried-command tracking (`commandTriedInEpoch`) and the eligible/blocked move computation; no new state model.
  - Wire the Rabbit-Hole nudge (2.1) and the Exam Proof Auditor (3.2) to open this view so the "stuck in the exam" moment has one destination. Keep distinct from `stuck.js` (the pivot and connectivity doctor); cross-link, do not merge.
- **Key Files**:
  - `assets/ui/routes/path.js`, `assets/ui/routes/checklist.js`
  - `assets/engine/pack.js` and `assets/engine/command.js` (eligible-vs-tried derivation)
  - `assets/ui/routes/home.js` (nudge CTA)

### 4.5 Client-Side Delivery Builder And Coach Move
> Agreed direction. Backlog, not authorization. Educational and authorized-engagement framing with scope warnings; no targeting of real people and no untargeted campaigns.

- **Problem**: Tricky multi-step client-side techniques (Office macro with email delivery, HTA, LNK, Windows library files) are where users lose the most time. The hard part is orchestration, not any single command: build the payload, stand up the listener, craft delivery, catch the callback, know what to paste back.
- **Solution**:
  - **Workbench**: extend the Reverse Shell Builder into a **Client-Side Delivery** builder. Pick a vector (VBA macro, HTA, LNK, library file), fill LHOST and LPORT once, get three coupled outputs: the payload body, the matching listener command, and a short delivery checklist, with a pinned scope note.
  - **Coach**: represent client-side as a move gated on a user-interaction surface (an email address, an upload-and-wait, a document drop). There is no tool output to parse, so the move's **proof is the caught shell**: the listener callback paste mints `foothold.shell`, the same as any other initial-access move. This keeps it inside the fact model and the determinism contract.
- **Key Files**:
  - `assets/engine/workbench.js`, `assets/ui/routes/workbench.js`
  - `data/packs/shells_2026_09.json` (or a dedicated client-side pack), `data/field-notes.js` (1:1), `data/parser-signatures.js`
  - `assets/engine/parsers/*` (listener callback to `foothold.shell`)

---

## Pillar 5: Corpus-Driven Parser And System Hardening

> Agreed direction. Backlog, not authorization. Full methodology lives in its own canonical
> doc: [docs/CORPUS-MINING.md](docs/CORPUS-MINING.md). This is the pointer; read that doc for
> the point of it all, the principles, the source portfolio, the extraction schema, and the
> staged plan. The program is **qa-only** (dev asset, never prod, never runtime), so the
> detailed doc is not mirrored to prod; only this pointer is.

- **Problem**: Parsers are the weakest link and the hinge the whole system turns on, yet they
  are hardened only against our own fixtures, not the real-world output variance the world
  actually produces. We have no broad, independent corpus to measure parsing, fact-minting,
  and fact-handling against, so exceptions and nuance slip through.
- **Solution (summary)**: A build-time, offline, qa-only program that collects a broad corpus
  of real tool output and methodology from a matched **source portfolio** (not just 0xdf, and
  not only token-heavy walkthroughs), measures gaps with OBOL's own engine as the oracle, and
  closes them. Priority order is fixed: **parsers and fact-handling first**; commands, moves,
  and ordering are captured but deferred (they feed Pillar 4.1). Two load-bearing rules:
  *mine once, extract everything, analyze many*; and the *Whole-Asset Rule*, that no asset is
  called done until every axis of value (code blocks and screenshots alike) is taken off it.
- **Status**: **0xdf Corpus Re-Mining Complete (Stages 0-7 DONE, 2026-10-23)**.
  - **Stage 0 & 1**: 194 walkthroughs inventoried; extraction schema and live `PARSER_SIGNATURES` fact-kind vocabulary locked (`tools/corpus/extraction-schema.js`, `tests/engine/corpus-extraction-schema-smoke.js`).
  - **Stage 2, 5 & 6**: Full output, loot, state-change, and failure-axis sweep across 6,916 command units with output. Actionable enumeration coverage reached **97.5%** (1,796 minted / 46 blind of 1,842 units), with 27 reactive blocker doctors and corpus-free regression suites (`tests/engine/stage5-corpus-remining-smoke.js`, `tests/engine/stage6-fact-followup-smoke.js`).
  - **Stage 3**: Full 194-walkthrough screenshot structural context sweep (2,396 captures) + 75-image visual inspection across 63 boxes; `--candidates` filter added to `tools/corpus/harvest-screenshots.js` and 19 `fidelity: 'ocr'` records locked in `tools/corpus/labels/0xdf-screenshots-ocr.json` (`tests/engine/stage3-screenshot-harvest-smoke.js`).
  - **Stage 4**: `facts`-axis ground-truth confusion matrix expanded to **102 labeled blocks** (259 expected facts across 21 tool families) at **100.0% recall** and **0 forbidden-kind hits** (`tools/corpus/labels/0xdf-facts.json`, `tests/engine/facts-axis-smoke.js` ratcheted to `MIN_LABELS = 100`).
  - **Stage 7**: Flow & move-ordering audit across all 194 ranked walkthroughs confirmed 100% directionally consistent precedence enforced by eligibility gates (`tests/engine/stage7-flow-ordering-smoke.js`).
  - Full progress and provenance are logged in `docs/CORPUS-LEDGER.md` and `docs/CORPUS-MINING.md`.
- **Key Files**:
  - `docs/CORPUS-MINING.md` (the canonical program doc) & `docs/CORPUS-LEDGER.md` (the running ledger)
  - `tools/corpus/*` (`extraction-schema.js`, `harvest-markdown.js`, `harvest-screenshots.js`, `facts-axis.js`)
  - `tools/corpus/labels/*` (`0xdf-facts.json`, `0xdf-screenshots-ocr.json`, `0xdf-screenshots-worklist.json`)
  - `data/parser-signatures.js`, `assets/engine/decisionmap.js`, `assets/engine/parsers/*`
  - `tools/gap-report.js`, `tools/post-parse-audit.js`

---

## Pillar 6: One-Click "Command #1" Operator Resilience & Dual-Tier Web / SVG Burp Co-Pilot

> **Aligned via `/grill-me` (2026-10-31).**
> **Completion Rule:** None of the items in Pillar 6 may be marked `COMPLETE` until the owner has encountered them in live hands-on testing and signed off on them personally. Current QA implementation status is `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`.

### 6.1 Pivot 1-Click Bridge: Routed-First Priority & Automatic SOCKS `proxychains4 -q` Wrapping
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - Rank routed tunnels first: `pivot-ligolo` `#1` by default (`pivot-sshuttle` `#1` when SSH credentials exist on a Linux foothold; `pivot-chisel-socks` `#2` fallback) because routed TUN interfaces allow every downstream command on internal targets to run unmodified.
  - Whenever an internal target (`Host B`) is reached over an active SOCKS tunnel (`tunnel.socks` / `tunnelKind === 'socks'` from Chisel or `ssh -D`) without an active routed tunnel (`tunnel.route`), automatically wrap remote Cockpit commands on `Host B` with `proxychains4 -q` (and convert `nmap` TCP scans to `-sT -Pn -n` without `sudo`), displaying a visible `Via SOCKS (proxychains4 auto-applied)` badge and a 1-click `[Show Unwrapped]` toggle (`aria-pressed`).
- **Built Files**: `data/packs/pivoting_2026_09.json`, `assets/engine/pack.js`, `assets/engine/command.js`, `assets/ui/routes/path.js`, `assets/css/obol.css`

### 6.2 Two-Terminal / Multi-Step (`stepper: true`) Guided Micro-Stepper
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - For genuine two-terminal / multi-step workflow moves (`OBOL.pack.isGuidedSequenceMove`, including `pivot-ligolo`, `pivot-chisel-socks`, `dns-tunnel`, and `jdwp-local-privesc`), focus **Step 1** in the primary Command #1 slot with an explicit terminal/locus badge (`STEP 1 OF 2 · ON KALI TERMINAL 1` vs `ON TARGET SHELL`) and a `[Step 1 Running -> Show Step 2]` button.
  - Auto-advance to Step 2 when Step 1's startup output is pasted (holding move settlement until all required sequence steps complete), while preserving the normal `[Remote (Kali) | On-Host Shell]` locus switcher on ordered-alternative catalog moves (`flag-hunt-*`, `bloodhound-collect`, `adcs-esc`) and providing a native `<details>` `Show all N steps` peek disclosure.
- **Built Files**: `data/packs/pivoting_2026_09.json`, `assets/engine/pack.js`, `assets/ui/routes/path.js`, `assets/css/obol.css`

### 6.3 Strict Fallback Variant Auto-Rotation Inside Multi-Command Cards
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - Tag optional side-quest commands (`cewl`, `eyewitness`, `rustscan`, `masscan`, `getTGT.py` inside `asrep-roast`) with `"alt": true` across packs so automatic command rotation focuses strictly on true payload/protocol fallback chains (`evil-winrm -> psexec -> wmiexec`, `Jinja2 -> Twig -> Freemarker`, `/etc/passwd -> php://filter`).
  - When a pasted attempt fails or returns `completed-negative`, rotate the next untried viable sibling variant directly into the Command #1 slot via `commandRanExactOrSig` + `cmdWasTriedInEpoch`, retiring or demoting the card cleanly after dry probes.
- **Built Files**: `data/packs/web_2026_09.json`, `data/packs/recon_2026_09.json`, `data/packs/ad_2026_09.json`, `assets/engine/pack.js`, `assets/engine/command.js`, `assets/ui/routes/path.js`

### 6.4 Safe-Copy Flagless Exploit-DB (`searchsploit`) Auto-Patcher
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - When `parsers/edb.js` inspects a `searchsploit -x` / `-m` script that relies on hardcoded author constants (`RHOST`, `URL`, `TARGET`, `RPORT`, `LHOST`, `LPORT`, or leftover `127.0.0.1:8080` `proxies`) rather than CLI flags, generate a 1-shot safe-copy Command #1 on `edb-run-adapted-exploit` (`cp <id>.py <id>_obol.py && sed -i -E ... <id>_obol.py && python3 <id>_obol.py`).
  - Preserves the untouched original Exploit-DB file for diffing/inspection while displaying a 1-line `edbPatchSummary` badge listing the exact constants OBOL patched.
- **Built Files**: `assets/engine/parsers/edb.js`, `assets/engine/command.js`, `data/packs/recon_2026_09.json`, `assets/ui/routes/path.js`

### 6.5 Explicit "What to Paste Back" Prompts on Silent & Hanging Commands
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - On listeners (`nc -lvnp`, `socat`, `pwncat`, `ligolo-proxy`, `chisel server`), background tunnels (`sshuttle`, `ssh -D/-L/-R`), and staging file servers (`python3 -m http.server`, `impacket-smbserver`), display a calm 1-line **What to paste back:** prompt directly beneath the active primary command row explaining what terminal output proves the step succeeded.
- **Built Files**: `assets/ui/routes/path.js`, `assets/css/obol.css`

### 6.6 Dual-Tier Web Upgrade: Tier A Cookie-Jar Form Extractor & Tier B Glowing SVG Burp Repeater Co-Pilot
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - **Tier A (CLI `curl` + HTML Form/CSRF Extractor + UI HTML Collapse)**:
    - Keep `curl` probes short and standard (`curl -skL -i -c loot/cookies.txt -b loot/cookies.txt "{{url}}"` on `recon-web-triage`).
    - Parse `<form action method enctype>`, `<input>/<textarea>/<select>` names/types/values (including hidden CSRF fields), and `?param=` query links in `parsers/websource.js` (`web.forms_discovered`), auto-collapse raw pasted HTML bodies (`>= 12` lines) inside native `<details class="hl-out html-collapse">` in `#/history`, render a compact **Discovered Forms & Parameters** strip (with form-selector pills when multiple forms exist), and auto-wire exact field names, hidden CSRF values, and `-b loot/cookies.txt -c loot/cookies.txt` into downstream web-exploitation Command #1s.
  - **Tier B (Dual-Home 3-State Glowing SVG Burp Repeater Co-Pilot + Raw HTTP Request Parser)**:
    - **Raw Burp HTTP Request Parser (`parsers/web.js`)**: Deterministically parse pasted raw HTTP requests (`POST /path HTTP/1.1`, `Host:`, `Cookie:`, `Authorization:`, `X-CSRF-Token:`, URL-encoded, JSON, XML, and `multipart/form-data` parts/filenames) into structured `web.http_request_captured` facts and persist per-target captured requests in engagement state (`eng.webRequests[targetIp]`, capped at 12 per target).
    - **Dual-Home Shared Renderer (`OBOL.burpCopilot` in `assets/ui/burp-copilot.js`)**:
      1. **Contextual Cockpit Home (`#/path`)**: Appears on web-exploitation cards via a `[ 1-Click CLI (curl) | Burp Guide ]` mode toggle and a `[ Burp Co-Pilot ]` Right-Canvas tab. Uses **Smart Auto-Open**: leads with 1-click CLI `curl` when runnable params/forms are already known, and auto-opens the Right-Canvas SVG Burp Co-Pilot when a raw Burp request is pasted, multipart/CSRF/JS browser capture is needed, or the user clicks `[ Burp Guide ]`. Vanishes automatically once the web card settles on foothold/bypass proof.
      2. **Persistent Workbench Home (`#/workbench/burp` under `Codecs & Web`)**: Allows returning at any time with saved per-target captured request chips.
    - **3-State Live SVG Repeater Instrument**:
      1. *State 1 (Capture)*: Accessible inline SVG (`role="img"` + `<title>`, compositor-safe `opacity`/`transform` glow with `@media (prefers-reduced-motion: reduce)`) highlighting `Proxy -> HTTP history -> Send to Repeater -> Copy Request`.
      2. *State 2 (Mutate)*: Renders the user's captured HTTP request with glowing `<mark class="burp-glow-tok">` token highlights (`tabindex="0"` scrollable `<pre>`), clickable attack/bypass mutation pills (`.phtml`/`GIF89a`, SQLi, LFI/`php://filter`, SSTI, XXE, NoSQL `[$ne]`, command injection, SSRF, IDOR, Host/XFF bypass), `[Copy Mutated Repeater Request]` + `[Copy Equivalent 1-Click curl]`, and a glowing orange `Send` prompt.
      3. *State 3 (Verdict)*: Evaluates the pasted HTTP response via `OBOL.ingest.run`, settles on confirmed foothold/bypass, or auto-rotates to the next untried bypass pill when blocked/filtered.
- **Built Files**: `assets/engine/parsers/websource.js`, `assets/engine/parsers/web.js`, `assets/engine/parsers/index.js`, `data/parser-signatures.js`, `data/packs/web_2026_09.json`, `assets/engine/command.js`, `assets/ui/burp-copilot.js`, `assets/ui/routes/path.js`, `assets/ui/routes/workbench.js`, `assets/ui/routes/history.js`, `assets/ui/store.js`, `assets/ui/lazy.js`, `index.html`, `assets/css/obol.css`

### 6.7 First-Launch Authorized Use & Assumption of Risk Clickwrap Gate + README Disclaimer
- **Status**: `BUILT IN QA (2026-10-31) - AWAITING OWNER HANDS-ON TESTING`
- **Aligned Spec**:
  - Display a non-bypassable first-launch native `<dialog id="aup-dialog">` (`closedby="none"`, `Escape`-guarded) detailing authorized-targets-only representation, zero-execution sole operator responsibility (`18 U.S.C. § 1030` / CFAA), `"AS IS"` no-warranty/no-liability terms (`AGPL-3.0` Sections 15-16), and non-affiliation / third-party trademark attribution, unlocked via a single `[I Understand & Agree]` button (`localStorage['obol.aup-accepted'] = 'v1:<ISO>'`) with permanent read-only review access in `#/help` (`Authorized Use & Legal Notice`).
  - Add a matching `## Authorized Use & Legal Disclaimer` section near the bottom of `README.md` right above `## License`.
- **Built Files**: `index.html`, `assets/ui/boot.js`, `assets/ui/routes/help.js`, `assets/css/obol.css`, `README.md`, `tests/browser-smoke.js`, `tests/browser-audit-smoke.js`, `tests/browser-outcome-flow.js`, `tests/browser-performance-smoke.js`

### Pillar 6 QA Verification Summary (2026-10-31)
- `tests/engine/pillar6-oneclick-and-burp-copilot-smoke.js`: **PASS (`40/40` assertions)** covering `6.1`-`6.6` end-to-end.
- Trajectory & Multi-Target Regressions: `challenge-labs-trajectories-smoke.js` (`69/69`), `challenge-labs-multi-target-smoke.js` (`66/66`), `exploitdb-adapter-doctor-smoke.js` (`54/54`), `0xdf-trajectories-smoke.js` (`31/31` tests, `204` assertions), `verify-oscp-practice-exams.js` (`18/18` targets), `verify-replay-goldens.js` (`100%`), `verify-multi-target.js` (`100%`).
- Full Corpus & Anti-Overfit Gates: `980/980` labeled blocks across `0xdf` (`1,383/1,383`), `pg-practice-2026-10-29` (`1,799/1,799`), and `pg-challenge-labs-2026-10-29` (`390/390`) at **`100.0%` recall / `0` forbidden hits**; `ranker-sweep.js --check` (`4,000` samples, `0.00%` violations); `gate-audit`, `move-lint`, `gap-report`, `post-parse-audit`, `field-notes-coverage` (`100.0%`), and `verify-no-overfit.js --base 2eb3ac26` (**CLEAN, `0` violations**).
