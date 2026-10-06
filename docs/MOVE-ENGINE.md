# The move & ranking engine — how to grow the move set without whack-a-mole

> Read this before adding or re-ranking moves. It is the contract that keeps "what's my next move?"
> correct as the pack grows, so correctness stops depending on running labs to find mis-ranked moves.

## The one rule

**A move must be rankable from its own honest declaration. Adding one must never mean wedging it into a
global priority ladder relative to every other move.** When that rule holds, a new move slots itself in and
the engine computes where it belongs. When it breaks — a dishonest effect, an unregistered dead-end, a
hand-tuned priority fighting the graph — you get the bug-of-the-week, found only by running a lab.

Everything below exists to keep that rule true mechanically.

## The model (what's already here)

Facts → moves → goals form an attack graph. Each move (`data/packs/*.json`, loaded as `OBOL.pack.Action`)
declares:

- `requires_all` / `requires_any` — the facts that make it **eligible** (its in-edges).
- `produces` — the facts it mints when it lands (its out-edges). **These must be honest** (see below).
- `locus` — **R** (remote, run from Kali), **F** (on-host one-shot), **I** (interactive on-host). Derived
  if omitted. **Remote is preferred, always** — running from Kali beats getting on the box.
- `phase` — recon · enum · creds · access · escalate · loot (derived from `produces` if omitted).
- `report.severity` — `info` marks a **report-only** writeup check (SPF/DMARC, headers, TLS…).

Two consumers of the graph:

- **`nextActionsV2` / `rankActions`** (`assets/engine/pack.js`) — the coach's ranker. Orders eligible,
  non-settled moves by: **tier** (recency: a move that *just* became possible is surfaced; speculative
  moves are capped) → **score** (goal-distance progress + 1-step enablement, weighted by reliability) →
  **priority** (hand-tuned, a tiebreak) → **locus** (remote-first) → id.
- **`planPath`** (A* in `assets/engine/pack.js`) — the lowest-cost dependable route to a goal. Costs
  (`v2ActionCost`) encode preference: evidenced step = 1, ordinary = 1.5, privilege shortcut = 8,
  speculative = 12, **plus a small locus surcharge so the route prefers Kali-side steps**.

The coach, the hub's "Your Next Move", each hub/target card, and the Evidence summary all rank through one
shared function, **`OBOL.coach.rankFor(facts)`** (`assets/ui/routes/path.js`) — report-only checks excluded,
frontier-ready first. If you add a surface that shows "next move", use `rankFor`; never re-implement ranking.

## The three pillars that keep it sustainable

### 1. Lints — `node tools/move-lint.js` (CI-gated: `--check`)

Static contract checks that share the ranker's own fact-classification (`OBOL.pack.isEvidenceFact`,
`producesFoothold`, `producesPrivilege`, `isReportOnly`, `GOALS`). A move that passes is one the ranker
places sanely.

- **FAIL · FIELDS** — locus/phase can't resolve to a valid value.
- **FAIL · INFO-DEADEND** — a move produces *only* informational facts (not a goal, not consumed by any
  move, not an evidence fact, not a **registered terminal**) yet isn't tagged `severity: info`. This is the
  class that let *Email DNS Review (SPF/DMARC)* headline a live box. The terminal-facts allow-list lives in
  the tool, explicit and documented — see "adding a fact" below.
- **WARN · UNINDICATED-PAYOFF** — produces a real payoff (foothold/privilege, or a **validated
  credential**) with no evidence gate, so it can only fire as a gamble (blind password spraying,
  default-cred guessing, an exploit at a bare port). The ranker caps it — gate it on the fact that
  actually yields the payoff (a found `credential.candidate` to spray, a `hash.*` to crack) or confirm it's
  meant to be speculative.
- **WARN · SHORTCUT** — produces a privilege fact straight from a soft AD lead with nothing in hand (an
  over-claimed one-step jump to DA; prefer modeling the honest intermediate).

### 2. Honest effects + cost, not sort hacks

Remote-first is achieved by **correct data**, not by overriding the sort order (which backfires — forcing
locus above score once promoted a speculative remote move). The pattern:

- A move's `produces` must be what it *actually* proves. ACL abuse yields object **control**
  (`ad.control_paths`), not domain admin — so `ad-acl-abuse` produces `ad.control_paths` and hands off to
  `dcsync`, it does not claim `access.admin`. (The linter's SHORTCUT warning flags violations.)
- **Twins that do the same thing share priority.** `ad-acl-abuse` (on-host) and `bloodyad-acl` (remote)
  both do ACL abuse, so they carry equal priority — and the remote-first locus tiebreak then picks the
  Kali-side one. That is how you express "prefer the remote version": equal priority + a cheaper locus, not
  a bespoke rule.
- Preferences live in `v2ActionCost`/locus, not in a per-move number war.

### 3. The golden-path corpus — `tests/engine/corpus/*.json`

Real box kill-chains as **fact-timeline → expected next move** checkpoints, replayed by
`tests/engine/corpus-smoke.js` (runs in the normal engine suite). This is the ground truth that turns
"run 50 labs to find a ranking regression" into "run CI". **Adding a box is adding one JSON file — no code.**
Schema and assertion keys (`top`, `topIn`, `present`, `absentTop`, `prep`) are documented at the top of
`corpus-smoke.js`; prefer the loosest key that still pins the behaviour (`topIn` tolerates defensible
co-leads). Seeded with Forest (full anon-LDAP → AS-REP → BloodHound → WriteDacl/DCSync chain) and a web
standalone (exploit-gating). **Grow it: every box you walk, encode it.**

## Adding a move — the checklist

1. Declare `requires_*`, `produces`, `locus`, `phase` honestly. Every produced fact must be a **goal**,
   **consumed** by some move, an **evidence** fact, a **registered terminal** (`TERMINAL_FACTS` in
   `tools/move-lint.js`), or the move is tagged `severity: info`.
2. If it's a remote twin of an existing on-host move (or vice-versa), give them **equal priority** and set
   `locus` correctly — do not out-prioritize the remote one.
3. **Gate the payoff behind the fact that produces it.** If it produces a foothold/privilege fact *or a
   validated credential*, gate it on an **evidence** fact (a proven fingerprint/verdict, a held
   credential/hash) — not a bare port or a `*.reachable` recon fact — or accept it's speculative and will be
   capped. (Reachability is recon, never evidence: a reachable port proves nothing about a cred or a vuln.
   Blind `password-spray` is gated on `credential.candidate` so it's reliable only once you actually hold a
   password to spray; with nothing in hand it's a capped gamble, below the deterministic AS-REP roast.)
4. Run `node tools/build-packs.js && node tools/move-lint.js --check && node tools/gap-report.js --check`.
5. If you walked a box to design it, **add it to the corpus** (`tests/engine/corpus/<box>.json`).
6. Run the engine suite + browser smoke (see AGENTS.md).

## Adding a fact kind

A new produced fact must be one of: consumed by a move's `requires_*`, a goal (`V2_GOALS` in `pack.js`), an
evidence fact (matches `V2_EVIDENCE_RE` or `V2_SPECIFIC`/`V2_AD_LEAD`), a registered terminal
(`TERMINAL_FACTS` in `tools/move-lint.js`, with a one-line reason), or the move producing it is a report
check (`severity: info`). Otherwise `move-lint` fails it — on purpose: an unconsumed, non-goal,
non-evidence, non-terminal fact is a dead-end that would pollute the ready list.

## Known, intentional nuances (not bugs)

- **Recency can briefly surface a newly-unlocked on-host move above its already-available remote twin** —
  the instant BloodHound reveals a path, `ad-acl-abuse` may sit at #1 for that render while `bloodyad-acl`
  is #2. Both co-lead; this is the "show me what just opened up" tier doing its job. Do not add a sort hack
  to fight it.
- **Report checks are offered, never headlined.** Info-severity checks live in the coach's collapsed
  "Report Checks, for the writeup" group and are excluded from every "next move" surface.

## Running the guardrails

```
node tools/build-packs.js           # regenerate the bundle after editing packs
node tools/move-lint.js             # the move contract (add --check to fail on breach)
node tools/gap-report.js --check    # decision-map graph truth (unreachable / hand-offs / parser drift)
node tests/engine/corpus-smoke.js   # the golden-path box corpus (also runs in the engine suite)
node tools/stamp-assets.js          # refresh cache-bust stamps after any asset edit
```

CI (`.github/workflows/ci.yml`) runs all of these plus the full engine suite and the browser smoke.
