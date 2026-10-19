# TASK-06: UI Focus Mode & Help Completion (Phases H2-H5)

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, or strings. Use commas, colons, parentheses, or hyphens (` - `). Title Case for all UI labels, tabs, and headings.

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `assets/ui/routes/path.js`
- `data/help-content.js`
- `assets/ui/routes/help.js`
- `assets/css/obol.css`
- `tests/engine/help-coverage.js`

**Do NOT edit:** `data/packs/*.json`, `assets/engine/pack.js`, or `assets/engine/parsers/*.js`.

---

## 2. Part A: Next Steps "Focus Mode" Toggle (`assets/ui/routes/path.js`)

### Context (from CLAUDE.md Library Spec)
In `assets/ui/routes/path.js`, each Ready Now card currently renders its lead command plus all alternative commands in `move.commands`. For neurodivergent/disabled learners, seeing 6-10 command variants on every card can be overwhelming when they only need the #1 preferred command right now.

### Exact Changes Required in `assets/ui/routes/path.js`
1. Add a **"Focus Mode"** toggle pill next to the existing `"Keep Cards Open"` toggle in `assets/ui/routes/path.js`:
   - Persist its state per engagement in `eng.ui.nsFocusMode` (boolean, default `false` so existing headless tests that inspect all command rows on a card continue to pass without surprise, or toggleable with one click).
2. When `eng.ui.nsFocusMode === true`:
   - On each expanded move card in Next Steps, render ONLY the active/lead runnable command (` preferredCommandIndex`) and its field note.
   - Collapse the remaining `N` runnable command alternatives behind a clean inline chip:
     `Show N More Ways` (which expands the remaining commands on that card) plus a deep link `Open In Library ->` (`#/library/moves?q=<move.id>`).

---

## 3. Part B: Help Tab Phases H2-H5 (`data/help-content.js` & `assets/ui/routes/help.js`)

### Context
Phases `H1` (Help skeleton with Index, Quick Start, Glossary) and `H6` (header `?` context-aware button) are shipped. Phases `H2`, `H3`, `H4`, and `H5` remain:

### Exact Changes Required
1. **H2 (Deepen Per-Surface Prose in `data/help-content.js`)**:
   - In `OBOL.HELP.sections`, ensure every section row carries a concise `when` ("When to use it") and `tip` ("Pro tip / common workflow") alongside `what` and `href`, with zero em/en dashes.
2. **H3 (Expand Glossary in `data/help-content.js`)**:
   - Expand `OBOL.HELP.glossary` from 10 terms to 20+ core Obol & OSCP methodology terms (adding: `Access Epoch`, `Blocker / Field Doctor`, `Cruise Batch`, `Earned Token`, `Frontier`, `Goal Distance`, `Keystone Move`, `Locus (Remote / On-Host)`, `Proof Discipline`, `Settled Command`, `Speculative Move`, `Station`).
3. **H4 (Help Search Filter in `assets/ui/routes/help.js`)**:
   - Add a live search input (`#help-search`) at the top of the Help route (`assets/ui/routes/help.js`) that filters both the Index accordion sections/sub-rows and the Glossary terms in real time as the user types.
4. **H5 (Stepped Resumable Quick Start in `assets/ui/routes/help.js`)**:
   - On the Quick Start sub-view (`#/help/start`), add a per-step completion checkbox (`1. Set Your Loadout`, `2. Create An Engagement & Target`, `3. Run & Paste Your First Scan`, `4. Follow Next Steps To Proof`) persisted in `localStorage.getItem('obol-quickstart-steps')` with a progress indicator (`N of 4 Complete`).

---

## 4. Verification Checklist (Must All Pass Before Completion)

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tests/engine/help-coverage.js
node tests/engine/no-decorative-emoji.js
node tools/lint-study.js --check
node tools/gap-report.js --check
node tools/post-parse-audit.js --check
node tools/stamp-assets.js
```
All commands must exit with code `0`.
