# The by-port decision map — and the gap-finding loop it powers

*The Learn tab's by-port view has two modes: **Cards** (the ordered-move lists, one per open port)
and **Decision map** (a left-to-right decision forest). This doc is the design contract and, more
importantly, the standing guide for using the map to **find and close coverage gaps** in future
chats. Read it before touching any of the files in [§ Files](#files).*

---

## 1. What the map is

A single screen that answers *"I scanned, these ports are open — what do I actually do, and where
does each path lead?"* It paints the **whole forest at once** (the "impressive mass"), zoomed out,
then lets you zoom, pan, filter to the ports you care about, fold branches, and click any move to
open its study cell.

The non-negotiable property: **the map is DERIVED, never hand-drawn.**

- The **structure** (which move follows which) comes from the real move graph — a move B hangs off
  move A when A `produces` a fact that B `requires`. Same edges the coach walks.
- The **ranked "spine"** (the lit path) comes from the **same ranker the coach uses**
  (`OBOL.pack.nextActionsV2`), replayed within each port's move set. So the map's recommended path
  and Next Steps' recommendation **can never disagree** — there is one source of truth, consulted
  twice.
- A port's tree ends at a **hand-off leaf** (`→ you have a shell on Linux`, `→ you have a hash to
  crack`, …) rather than inlining the whole endgame under every port. The post-foothold maps
  (shell-linux, offline-hash, domain-cred, proof, pivot) are the shared continuations.

Because it is derived, **adding a move or wiring a fact updates the map and every diagnostic below
automatically.** Nothing here is maintained per-port by hand.

The only **authored** layers are three lint-gated sentence files — never trees:

- `data/decision-forks.js` — one plain-language fork *condition* per move ("Does anonymous login
  succeed?"). Absence just shows as a fork-coverage gap; the structure still renders.
- `data/parser-signatures.js` — the plain-English "what each parser looks for", **and** the
  authoritative parser capability set (see §3).
- `data/coverage-expected.js` — the expected-technique oracle per port (see §4).

---

## 2. Why it exists: it is also a gap X-ray

The map doubles as a self-diagnostic. Because it is derived from the same graph, ranker, and parsers
that run the app, three classes of gap surface on it **automatically** — that is the whole point.
Flip the **Parser cover** lens on the map to see the parse layer in colour; run
`node tools/gap-report.js` for the full text report.

| Gap class | Meaning | Found by |
|---|---|---|
| **coverage gap** | a technique that *should* exist for a port, but no move represents it | diffing moves against `data/coverage-expected.js` |
| **wiring gap** | a move exists but isn't connected: it needs a fact nothing produces (**unreachable**), produces a fact nothing uses (**dead-end**), or lands a foothold with no **hand-off** | the move graph itself |
| **parse gap** | a move runs and is wired, but **no parser can read its result** into the fact it claims to produce — so running it never advances the coach ("write-only" move) | the parser capability set (§3) |

This is not a toy. When first run, the derived parse-gap lens **independently rediscovered every
unported parser we already knew about** (the findings-checks `http.*`/`tls.*`/`dns.*`, `ad.trusts`,
`ad.zerologon`, `sccm.enumerated`, ADCS templates, `db.session`, `loot.files`) — with no list handed
to it. That is the signal the derivation is trustworthy.

---

## 3. The parser capability set (the heart of the parse lens)

`data/parser-signatures.js` is **two things at once**:

1. the readable "obol looks for: …" sentence pinned on each move in the Parser-cover lens; and
2. the **capability set** — the union of every signature's `emits` list is *"every fact obol can
   ever recognize from pasted output."* An `emits` entry ending in `.` is a prefix wildcard
   (`service.` covers `service.mysql`, …).

A move is graded by whether each fact it `produces` is **readable**:

- `verified` — every produced fact is in the capability set (or is environmental / a legitimate
  action-intent fact / a hand-off). Running it advances the coach.
- `partial` — some produced facts are unreadable.
- `gap` — **none** of its produced facts can be read. A write-only move.
- `noproduce` — an enumeration/terminal move that declares no fact (correct, not a gap).

**This set must not drift from the real parsers**, or the lens lies. `node tools/gap-report.js
--verify` cross-checks it both ways against the actual parsers (static `mkFact('literal')` kinds ∪
the live fixture corpus run through `OBOL.parsers.parseActionOutput`):

- *missing emit* — a real parser mints a fact no signature lists → the lens would hide a real
  readable move. Fix: add it to the right signature's `emits`.
- *stale emit* — a signature lists a fact no parser mints → the lens would falsely show a move as
  readable. Fix: remove it (and note the real gap it was masking).

`--check` exits non-zero on any unreachable move, missing hand-off, or signature drift — wire it into
CI next to the pack/stamp checks.

---

## 4. The gap-finding loop (for future chats — read this)

This is the durable payoff the build was for. To find and close coverage gaps:

1. **Run the X-ray.** `node tools/gap-report.js --verify` from `obol_web/`. It prints COVERAGE,
   PARSE (gap + partial), WIRING (unreachable / dead-end / missing hand-off), orphan parser facts,
   fork-condition coverage, and the drift check. The counts line at the top is the at-a-glance score.
2. **Triage by class, in this order:**
   - **unreachable / missing hand-off / signature drift** are hard — they mean the app is actually
     broken for that move. Fix first. (`--check` gates these.)
   - **parse gap** — decide per move: either the move is real OSCP methodology and deserves a parser
     (port one from obol-local or write one, then add its emits to a signature), or the move should
     not claim that `produces` fact. Both close the gap honestly.
   - **coverage gap** — a seeded expectation in `coverage-expected.js` with no backing move. Either
     author the move (preferred) or, if deliberately out of scope, leave the `moves: []` seed as a
     documented known-gap so it stays visible.
   - **dead-end** is a *review* list, not an error — many are genuinely terminal (loot, proof,
     observations). Scan it for a fact that *should* feed a downstream move but doesn't.
3. **Close the gap** by editing the real engine/packs/parsers — **never** by hand-editing the map.
   The map re-derives.
4. **Re-run** `--verify` until the class you targeted is zero (or documented), and
   `node tests/engine/decisionmap-smoke.js` passes.
5. **Extend the oracle as you learn.** When you discover a technique the map *should* teach for a
   port, add it to `coverage-expected.js` — now the gap is tracked even before the move exists.

Seeding a gap on purpose is a first-class move: a `moves: []` entry in `coverage-expected.js`, or a
move left without a `decision-forks.js` entry, keeps the hole on the radar instead of forgotten.

### How to close a **parse** gap concretely

A parse gap means a parser is missing. The parsers live in `assets/engine/parsers/*.js`,
dispatched by command in `parsers/index.js`; `obol-local` is the donor for ported logic. After
adding/porting a parser: add every fact kind it mints to the matching signature's `emits` in
`data/parser-signatures.js`, then `node tools/gap-report.js --verify` must show **0 drift** both ways
and the move should flip to `verified`/`partial`.

---

## 5. Files

| File | Role |
|---|---|
| `assets/engine/decisionmap.js` | `OBOL.decisionMap` — derives the forest, the spine, parser coverage, and the gap report. The engine. |
| `assets/ui/decisiontree.js` | `OBOL.decisionTreeView.mount(el, opts)` — the left-to-right renderer: pan/zoom/wheel, semantic LOD, fold, port filter, the methodology ⇄ parser lens, hover cards. |
| `data/decision-forks.js` | authored one-line fork **conditions** (`OBOL.DECISION_FORKS`). |
| `data/parser-signatures.js` | authored "looks for" sentences **and** the parser **capability set** (`OBOL.PARSER_SIGNATURES`). |
| `data/coverage-expected.js` | authored expected-technique oracle per port (`OBOL.COVERAGE_EXPECTED`). |
| `tools/gap-report.js` | the CLI X-ray. `--verify` adds the drift check; `--check` exits non-zero on hard problems. |
| `tests/engine/decisionmap-smoke.js` | engine smoke: forest shape, filter, spine, hand-offs, the three gap lenses. |
| `assets/ui/routes/study.js` | by-port view: the Cards ⇄ Decision map toggle (`_evMode`) and the `wirePortMap` mount hook. |

The renderer is deliberately reusable: it is mounted in the Learn by-port view now, and is meant to
drop into the target view (simulated with the real engagement's facts) and an engagement-wide forest
later, with no engine changes.

---

## 6. Accessibility contract

The map is a zoomable canvas (same class as the Atlas), held to the same gate: keyboard-reachable
controls and stage, visible focus rings, a ≥ 11px font floor on all chrome, token-based colours that
redefine per skin so contrast holds on all seven skins, and colour used only as **reinforcement** —
every lane/parse state is also named in text (the node label, the hover card, the legend). The
parse/lane hues tint borders and fills, never the body text, which stays on the AA-safe
`--text`/`--surf2` pairing.
