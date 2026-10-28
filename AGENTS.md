# OBOL Workspace Agent Guidelines & Open Items Pointer

1. **Open Items / Roadmap Trigger ("Let's look at open items")**:
   - Whenever the user says **"Let's look at open items"** (or asks about open items, backlog, roadmap, neurodivergent/accessibility features, or next UX improvements), immediately view [`OPEN_ITEMS.md`](OPEN_ITEMS.md) in `qa/`, the authoritative backlog document (dev-only; scrubbed from `prod/` by `publish.mjs`).
   - As open items are completed or refined, update `qa/OPEN_ITEMS.md`.

2. **Dual-Tree Synchronization (`qa/` and `prod/`)**:
   - The user develops and QAs in `e:\KaliFiles\obol\obol-site\qa` (the authoritative workspace: always edit and run tests here) and ships the verified result to `e:\KaliFiles\obol\obol-site\prod` (the active production repository, bundled assets only). Only `qa/` and `prod/` exist as repos under `obol-site\`; do not create an `obol/` subdirectory.
   - After modifying JS/CSS assets, run `node qa/tools/stamp-assets.js` (it rewrites the `?v=` hashes in `index.html` and `assets/ui/lazy.js`), then sync the stamped/bundled assets to `prod/` after verification via `node qa/tools/publish/publish.mjs --publish e:\KaliFiles\obol\obol-site\prod`.

3. **House Style**:
   - Never use em-dashes or en-dashes in any JS, CSS, HTML, or JSON strings or comments. Use commas, colons, parentheses, or standard hyphens (` - `).

4. **Automatic Live Run / Workspace File Detection (`e:\KaliFiles\obol\obol-site\test-runs\` & `e:\KaliFiles\obol\obol-site\`)**:
   - At the start of every turn, proactively check `e:\KaliFiles\obol\obol-site\test-runs\` (and `e:\KaliFiles\obol\obol-site\`) for newly created or modified user run logs, exported workspaces, and reports (`.txt`, `.json`, `.docx`, `.pdf`, `.md`, `.html`) without waiting for the user to ask or explain what changed.

5. **Corpus Mining Program (hardening parsers, facts, and moves from real-world data)**:
   - Method and rationale: [`docs/CORPUS-MINING.md`](docs/CORPUS-MINING.md). Read it before doing ANY work that mines walkthroughs, tool output, or other external data to improve parsing, fact-minting, fact-handling, commands, moves, or ordering.
   - Running record: [`docs/CORPUS-LEDGER.md`](docs/CORPUS-LEDGER.md) logs what has been mined, how thoroughly (which axes), and what was derived. Read it before mining a source and update it in the same change right after, so work is never redone between chats or agents.
   - This program is **qa-only** (dev asset, never prod, never runtime).

6. **Terminology Mapping (`Cockpit = coach / path` in code) & Scale Baseline**:
   - The primary operator workspace at `#/path` is named **Cockpit** (`Cockpit / Choose Your Path - 5-tab Hero Operator Deck + ranked moves`) in all user-facing UI strings and documentation (formerly *Coach* / *Next Steps*).
   - In the codebase, it maps to `assets/ui/routes/path.js`, `OBOL.coach` (`OBOL.coach.rankFor`), `#/path`, and `.coach-*` / `.ns-*` CSS selectors. Keep internal code identifiers unchanged while using **Cockpit** for all user-facing copy and documentation.
   - Live scale baseline: 19 JSON move packs (`355 moves`, `1,923 commands`), 18 parser files (`443 parser signals` + `5 Wittgensteinian contextual inference rules` in [`INFERENCE.md`](INFERENCE.md)), 7-tier Causal Frontier & Bayesian Utility Ranker ([`RANKING.md`](RANKING.md)), `21 routes` across 18 route modules (including `#/start` in `assets/ui/routes/start.js` + `data/resources.js`), and `99 engine smoke suites` in `tests/engine/`.
