# OBOL Open Items: UX, Neurodivergent/Accessibility & Operator Roadmap

> **Trigger Phrase**: When the user says **"Let's look at open items"** (or asks about the roadmap, backlog, or next UX improvements), read this file (`OPEN_ITEMS.md`) and keep both `qa/OPEN_ITEMS.md` and `obol/OPEN_ITEMS.md` in sync as items are completed or updated.

---

## Pillar 1: Information Architecture & Navigation Consolidation

### 1.1 Streamline the 13-Item Engagement Sub-Nav (`assets/ui/ctxbar.js`)
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
