# Obol — Offensive Box Operations Ledger (web)

**The static-site edition of [obol-local](https://github.com/platocres/obol-local).** A
browser-local, no-backend OSCP/CTF operator companion: an evidence-driven **coach** that
ranks the next commands to run, conservative **parsers** that turn pasted tool output into
proven facts, client-side **BloodHound** domain analysis, a pack-driven **checklist**, a
robust **Tools** command-builder, and an OSCP-style **report** — all running in the browser.
No backend, no telemetry, and it never executes commands: it builds them for a human to run.

Live site: `https://platocres.github.io/obol/`

## The loop

`Engagement (pick platform + scope) → Next Steps (coach) → run a command externally →
paste output on Evidence → parsers mint facts → coach recomputes → Report`

## Run locally

Open `index.html` in a browser — no server, no build step. The app boots a tiny critical
path and lazy-loads each surface on first navigation. State lives in the browser's IndexedDB.

## Surfaces

- **Engagements** (home) — create a run with a platform profile (HTB, OffSec/OSCP, PWK,
  TryHackMe, HTB CPTS, CTF, OSWP, custom) + machine type + scope, then launch.
- **Next Steps** — the coach: frontier-ranked, proof-gated moves with copy-ready commands,
  what each proves / does *not* prove, and blocked moves with their unmet prerequisite.
- **Evidence** — paste tool output; conservative parsers mint facts (nothing is invented).
- **Tools** — schema-driven command builders for obol-local's equipped tool set (the only
  place commands are *built*).
- **Domain** — upload a SharpHound zip → high-value census, owned→DA attack paths, printable
  report, entirely client-side.
- **Checklist** — the full methodology, phase-grouped and tickable.
- **Report** — OSCP/executive/technical profiles, redaction on by default, HTML/Markdown.
- **Graph** — the path graph (proven facts + done/next moves), or the whole methodology DAG.

## Architecture

- **`assets/engine/`** — the ported obol-local engine (pure JS): `facts`, `phases`, `pack`
  (planner), `command` templating, `graph`, `bloodhound`, `report`, `toolbuilder`, `profile`,
  and the conservative `parsers/`. Runs in the window, a Web Worker, and Node.
- **`assets/ui/`** — the shell: `store` (IndexedDB), `router` (deterministic single render),
  `lazy` loader, and the route surfaces.
- **`data/packs/`** + generated `data/packs-bundle.js` — obol-local's ~157-action methodology
  packs (regenerate with `node tools/build-packs.js`). `data/toolset.js`, `data/reportmeta.js`.
- **`tests/engine/`** — the ported obol-local test suites (planner, 79-case parser fixtures,
  bloodhound, report, toolbuilder, profile). **`tests/browser-smoke.js`** drives the real app.
- CI: `.github/workflows/ci.yml` (engine node tests + headless browser smoke).

The overhaul plan and full source-of-truth map: [`docs/LOCAL-INHERITANCE-OVERHAUL.md`](docs/LOCAL-INHERITANCE-OVERHAUL.md).

## Legal / ethics

For authorized labs, training, CTFs, exam prep, and permitted engagements only.
