# obol — direction & ideas parking lot

*Captured 2026-10-04 from the Oct 2–3 vision conversations so nothing gets lost. These are
**deferred ideas and strategic bets**, not committed work. Each got discussed and then set aside
(mostly by "we're just talking" / "write this later" / the Kali-VM setup detour), never settled.
Status is verified against the current `claude/obol-web-overhaul-local-59ttbx` tree. Nothing here
is scheduled; this is the menu we prioritize from.*

> **The throughline.** Idea #1 keeps resurfacing from every angle — the teaching pivot, gladiola's
> "buried gem," and two separate "what did we drop?" reviews. Treat it as the lead.

---

## 1. Decision graph as the explorable front door (the teaching pivot, half-built)

**The bet.** obol is a **teaching tool**, not an exam weapon. Pedagogically that means inverting the
hierarchy: **promote the concept, demote the detail.** The decision graph becomes the *spine* of the
whole tool; the specific command becomes the footnote that progressively discloses from it.

**Thesis (the organizing principle, say it out loud):**
> *Offensive security should be taught as an evidence-gated conditional decision graph, not a tool
> catalog.* → user-facing: **"know what to do, and why, from what you've found."**

**The design, as discussed:**
- **One map, two views.** *Study mode* = explore the whole methodology graph with no engagement
  loaded (a browsable curriculum). *Live mode* = your lit path across that **same** graph ("you are
  here; you proved X, so these three doors opened; this one's locked — here's what opens it").
- **Locked doors are the curriculum, not dead ends.** Each shows *why* it's locked and the exact
  move that unlocks it — a quest with a prerequisite, not a disabled button.
- **Teach the *why* on every node:** what unlocks it · what it proves · what it **rules out** · the
  common mistake. The decision logic is the lesson; the command is just execution.
- **Make the epistemology visible:** "suspected vs. proven" as an explicit, teachable distinction —
  that's the actual thesis rendered as a UI concept.
- **Scaffolding / fading:** obol fades its guidance as the learner proves mastery (also a second
  research contribution — see #4).

**Status.** Decision made; **mocked + feasibility-proven; not yet built.** The engine already *is* an
evidence-gated decision graph, and `map.js` + the per-target graph exist — but as engine detail under
the coach, not as an explorable, teach-from-it front door. Two interaction mocks are done and
approved (the **Watch** worked-example cell + the **Your turn** practice gear). A throwaway spike
(`spike-cellgen.js`) confirmed the cell generates from existing pack data.

### Feasibility verdict (2026-10-04 spike, 3 moves across AD/Linux/web)

The conditional cell is **~90% auto-generated from data we already have** — not 167 hand-written
lessons. Field coverage across all 167 moves:

| Cell field | Source (already in the pack) | Coverage |
|---|---|---|
| "What it is" | `move.hypothesis` | **100%** |
| "To be here, you'd have proved" | `requires_all` / `requires_any` + producer-move search | **100%** |
| Commands (remote-first) | `commands[]` ordered by ARSENAL `os`/`class` | **100%** |
| Per-command "why" | `commands[].note` | 87% |
| "This proves" | `produces` | 93% |
| "Common mistake / rules out" | `move.does_not_prove` | 93% |
| "What it opens" (downstream edges) | graph search `produces → requires` | 72% |
| "You'd likely see" (sample output) | parser fixture match | ~51%* |

*\*Fixture number is **optimistic** — keyword matching gives loose hits. The real "has a genuinely
relevant fixture" figure is lower and needs an explicit move→fixture map. This is the one true
authoring cost; everything else is free today.*

**Remote-first rule (locked).** Command variants in the cell are ordered
**🛰 remote → 💾 offline → 🖥 on-target**, derived from each tool's ARSENAL `os`/`class` — never
hand-ranked. Rationale: prefer the option that needs the *least* access to the box; needing a foothold
first is almost always the worse path IRL. (AS-REP demo: the derived order drops `Rubeus` — on-target
— to last, even though the pack authored it second.) This extends the engine's existing `locus`
axis (R/F/I) and remote-first ranker tiebreak down to the per-command level.

**Known gaps the spike surfaced (bounded):** (1) sample-output fixtures — the real content work,
OSCP-core-first; (2) ~28% of moves show no downstream edge (mostly terminal root/flag moves, a few
true graph gaps to close); (3) command-locus classifier needs a small refinement for `sh`-wrapped
offline handoffs (read inside the command, not just the tool name).

### Build plan

**New surface:** a `study` route (leftmost intent on the new landing), two gears — **Watch** (narrated
worked cell) and **Your turn** (retrieval-practice: masked graph + multiple-choice, teach on *every*
answer, unfold the cell as the reward). Landing = three doors: **Learn · Set up your box (Loadout) ·
Start an engagement**, skippable, first-run-aware.

- **`OBOL.study.cellFor(moveId, { profile })`** — the generator the spike prototyped. Pure function
  over the loaded packs + ARSENAL: returns `{ whatItIs, prereqs[], producedBy[], commands[] (locus-
  ordered, Loadout-invocation-aware), fixtureRef, proves[], opens[], rulesOut, refs[] }`. No new
  content for the structure; reuses `requires`/`produces`/`hypothesis`/`does_not_prove`/`commands[].note`.
- **Command locus classifier** — `remote(0) < offline(1) < on-target(2)` from ARSENAL `os`/`class`,
  with the `sh`-wrapper refinement. Shared with the live coach so ordering is consistent app-wide.
- **Graph helpers** — `producersOf(facts)` and `opensNext(move)` over the move set (spike has both);
  promote into the engine (`graph.js`) so Study and the live path share one implementation.
- **Move → fixture map** — `data/study-fixtures.json` (or a `fixture` field per move): explicit
  `moveId → fixtures/parser/outputs/<file>` + the line/signal to highlight. Author OSCP-core-first;
  reuse the parser's own known-extracted fact to pick the highlight line.
- **Study graph canvas** — branching, progressive-disclosure zoom (phase spine → technique branch →
  node), reusing/extending `map.js`. Masked-node mode for "Your turn".
- **Content pass (incremental, not blocking):** backfill `does_not_prove` on the 7% missing, close
  the real downstream-edge gaps, capture missing fixtures.

**Milestone 1 — AD vertical slice.** One lane end-to-end (anon LDAP → AS-REP roast → crack → spray →
ACL → DCSync): `cellFor` live, both gears, the branch canvas, remote-first ordering, real fixtures for
each node. Ship it, teach a real person, then decide whether to scale to all lanes.

## 2. Give obol-web "hands" (live ingestion, L0.5 seam)

**The bet.** Kill the copy-paste drudgery without crossing the category line that scared the demo
audience. The rule we settled on: **automate the *ingest* direction freely; keep a deliberate human
seam on the *inject* direction.** The human reaches out to obol; obol never reaches into the shell.
That's "L0.5" — and it's *more* legibly human-authored than a blind paste, so it's both better UX and
more defensible.

**The spectrum (all on-box, nothing leaves unless noted):**
- **Tier 1 — File System Access folder-watch / `script -f` tail.** obol holds a handle to the
  engagement dir and tails the growing session log; sees every command + output live. Zero infra,
  exam-safe, "shockingly close to what we already ship." *Observe-only (no injection).*
- **Tier 2 — stdlib Python PTY bridge on `127.0.0.1`**, rendered in xterm.js — full two-way terminal
  inside obol-web, on-box. (Must solve the localhost-RCE surface: loopback-bind + pairing token +
  strict `Origin` check.)
- **Tier 3 — E2E-encrypted relay** (sshx model) for cross-VM/NAT. Only acceptable encrypted.
- **Endgame: "obol-web *becomes* the terminal."** The paste step doesn't get automated — it ceases
  to exist. Live coach reacts keystroke-by-keystroke; workspace fills itself; flag highlights as it
  scrolls past. "An IDE for offensive operations."
- **OPSEC landmine to respect:** our users are trained never to paste a mystery blob. Any one-liner
  must be fully inline, human-readable, hashed/signed — *model good OPSEC as the product.*

**Status.** **Not built.** The arsenal paste-back loop is a distant cousin; live ingestion isn't
there. Study/practice mode is the ruleless place the seamless version can live unconstrained.

## 3. "Borrow a backend" — bundled enrichment & on-box power

**The bet.** A static site can be a client of other people's data. For obol the winning pattern is
**bundle the data in-house (zero exfil), make anything that phones out explicit + opt-in.** I ranked
bundled offensive-dataset enrichment as the #1 near-term build.

- **Bundled datasets → enrich every parsed service & move:** GTFOBins / LOLBAS / LOLDrivers /
  WADComs, EPSS scores, MITRE ATT&CK (STIX), ExploitDB index, default-cred DB. *(Only CISA **KEV**
  landed so far — `cisa_kev_2026_09.json`.)*
- **Local in-browser LLM** (WebLLM / transformers.js over WebGPU) — "explain this error / next move /
  draft the report," all on-box, nothing leaves.
- **DNS-over-HTTPS + crt.sh recon panel** — real in-browser recon, behind a clear "sends data off
  your box" opt-in.
- **Optional encrypted sync / team co-op** (Supabase or WebRTC/CRDT), client-side-encrypted.
- **One Cloudflare Worker** as the quiet enabler (dataset freshness, CORS-proxy, key-holding) — the
  one bit of real backend worth the "no longer purely static" step.

**Status.** Mostly **not built** (KEV only).

## 4. The academic paper / research track ("write this later")

**The bet.** A published, peer-reviewed piece is durable armor and credential — and the paper *falls
out of* a working, evaluated tool rather than stalling the build.

- **Thesis:** *the property that makes an offensive tool effective for an operator makes it harmful as
  a teacher* — with **obol-local as the antagonist of your own story** (the dual-use artifact you
  chose not to ship; restraint as the research contribution).
- **Venues:** security-**education** venues (USENIX ASE, IEEE FIE / Trans. Education, SIGCSE /
  ITiCSE, CISSE, J. Cybersecurity Education) or IEEE S&P **Magazine** — *not* the S&P Symposium.
- **Lit anchors:** assistance dilemma (Koedinger & Aleven), automation complacency / out-of-the-loop,
  productive failure (Kapur), desirable difficulties (Bjork), scaffolding-and-fading, expert blind
  spot.
- **The gap:** a small **learner study** (obol vs. control on understanding *when/why*). Built-in
  cohort available (your friends / the communities).
- **Guardrails:** don't inflate obol-local's capability; publish the *choice*, not a weaponization
  recipe; critique the *field*, not the vendor.

**Status.** Deferred; **nothing written.** Offered deliverables not yet made: thesis paragraph +
working abstract.

## 5. Kali distribution

**The bet.** Getting obol into Kali is the dream reach channel for a *teaching* mission — it lands
with exactly the newcomers it's for (Debian packaging, clean licensing, a maintainer). Deliciously
ironic since OffSec makes Kali; far more likely to go the poetic way now that obol is unambiguously
educational. (In-Kali ≠ exam-sanctioned — different claims.)

**Status.** Strategic goal; **not pursued.**

---

### Smaller loose ends (also parked)
- Scope lens still defaults to `oscp+`; `oscp` (core only) / `all` offered, never chosen. One-liner.
- A **"living capability map"** doc (each idea ↔ concrete feature sketch, effort, OPSEC flag) — I
  offered it twice; this file is the first cut of it.
- The OCD **top-5 OSCP gaps** (UAC bypass, targetedKerberoast move, HiveNightmare/SeriousSAM,
  crack-hash LM/NetNTLMv1/TGS-AES128, ESC3/ESC4 split) — tracked separately in `OCD-AD-COVERAGE.md`;
  "hold off for a moment," never resumed.
- AV/evasion **bypass** lane — greenlit; only the **detection** half (`defense.control`) shipped;
  bypass moves blocked by the real-time cyber-safety classifier.
