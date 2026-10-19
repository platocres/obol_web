# OBOL Workspace Agent Guidelines & Open Items Pointer

1. **Open Items / Roadmap Trigger ("Let's look at open items")**:
   - Whenever the user says **"Let's look at open items"** (or asks about open items, backlog, roadmap, neurodivergent/accessibility features, or next UX improvements), immediately view [`OPEN_ITEMS.md`](file:///e:/KaliFiles/obol/obol-site/obol/OPEN_ITEMS.md) (mirrored at [`qa/OPEN_ITEMS.md`](file:///e:/KaliFiles/obol/obol-site/qa/OPEN_ITEMS.md)).
   - As open items are completed or refined, update both `obol/OPEN_ITEMS.md` and `qa/OPEN_ITEMS.md`.

2. **Dual-Tree Synchronization (`qa/` and `obol/`)**:
   - The user tests and previews changes in `e:\KaliFiles\obol\obol-site\qa` and ships from `e:\KaliFiles\obol\obol-site\obol`.
   - Always keep `qa/` and `obol/` in sync and run `node qa/tools/stamp-assets.js` (then copy `index.html` and `assets/ui/lazy.js` to `obol/`) after modifying JS/CSS assets.

3. **House Style**:
   - Never use em-dashes or en-dashes in any JS, CSS, HTML, or JSON strings or comments. Use commas, colons, parentheses, or standard hyphens (` - `).

4. **Automatic Live Run / Workspace File Detection (`e:\KaliFiles\obol\obol-site\test-runs\` & `e:\KaliFiles\obol\obol-site\`)**:
   - At the start of every turn, proactively check `e:\KaliFiles\obol\obol-site\test-runs\` (and `e:\KaliFiles\obol\obol-site\`) for newly created or modified user run logs, exported workspaces, and reports (`.txt`, `.json`, `.docx`, `.pdf`, `.md`, `.html`) without waiting for the user to ask or explain what changed.


