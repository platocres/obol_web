# Agent entrypoint

Obol web is the **static-site edition of obol-local** — a browser-local, no-backend OSCP
operator tool. Read [README.md](README.md) for the surfaces and architecture, and
[docs/LOCAL-INHERITANCE-OVERHAUL.md](docs/LOCAL-INHERITANCE-OVERHAUL.md) for the overhaul plan
and the obol-local → obol_web source-of-truth map.

## Contract

- **No backend, no build step to run, no telemetry, and no command execution.** Commands are
  generated for a human to run externally. Conservative Evidence / proof boundaries hold:
  parsers never invent a fact; a run is not a win.
- **The engine is pure and shared.** `assets/engine/*` runs in the window, a Web Worker, and
  Node, and is ported faithfully from obol-local (`facts`/`phases`/`pack`/`command`/`graph`/
  `bloodhound`/`report`/`toolbuilder`/`profile`/`parsers`). Keep behavior parity with the
  Python source; the test suites encode it.
- **Source stays directly runnable** — open `index.html`. Keep the critical boot path tiny and
  lazy-load surfaces (`assets/ui/lazy.js`). State is in IndexedDB (`assets/ui/store.js`).

## Working rules

- Methodology packs are generated into `data/packs-bundle.js` from `data/packs/*.json` via
  `node tools/build-packs.js` — regenerate after editing packs (CI checks it is in sync).
- Prove changes: run `node tests/engine/*.js` and `node tests/browser-smoke.js` (needs
  Playwright + Chromium). CI (`.github/workflows/ci.yml`) runs both.
- The router renders each route **once** — never reintroduce timed double-paints.
