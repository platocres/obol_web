# Engagement-centered IA overhaul, build plan and preservation matrix

> Working brief for the navigation and information-architecture overhaul. Point an agent at this
> file to resume with full context. Owner-directed, discussed 2026-10. Develop on the open PR
> branch. This is additive wayfinding: routes keep working, deep links keep working, no tab loses
> functionality.
>
> _Last updated: 2026-10-05._

---

## 0. The problem

The top nav is 16 flat tabs. Only four are genuinely global (Learn, Loadout, Tools, Playbooks).
The other eleven are all views of one active engagement, yet they sit as peers of the reference
surfaces. The app already splits this way structurally: the left sidebar carries the engagement
context (selector, parameters, credentials, facts) on every route except Learn, which goes
full-bleed. The nav just does not say so. On mobile the split already exists too: a four-item
bottom bar (Home, Coach, Evidence, Tools) plus a More sheet.

The audience is largely neurodivergent and disabled learners, so reducing choice, keeping state
visible (never hidden), consistent layout, and strong responsive and accessibility behavior are
acceptance criteria, not polish.

## 1. The shape we are building

- **Top nav collapses to five globals, in this order:** Learn, Loadout, Engagements, Tools, Playbooks.
- **Everything else becomes per-engagement**, reached through the engagement: an **engagement hub**
  (all targets at a glance plus engagement-wide surfaces) and a per-box **target workspace**
  (`#/target/<ip>`) whose spine is the Next Steps and Evidence loop.
- **Global context strip** in the header: active engagement, a credential swapper, and an active
  target. It rides on every section including Learn (with graceful empty states), so any command
  copied anywhere is pre-filled. On mobile it collapses to a context chip that opens a bottom sheet.
- **Left bar kept:** Parameters and Facts stay on the left on working surfaces. The header chips are
  the quick, globally reachable face of the same state. `active target` is the `target` parameter
  wearing a hat: one source of truth, always visible, never contradicting the page you are on.
- **One additive global paste:** a header quick-paste into the existing Evidence pipeline that routes
  facts by proof (the output's own host wins), falls back to the active target for anchorless output,
  fans out across multiple hosts, always shows where it filed, and allows one-click reassign. The full
  Evidence surface and every other moved tab keep all behavior.
- **Engagement hub:** vitals, an adaptive and pinnable target board (a Show control: Pinned / Recent /
  Needs attention / All, plus a density toggle; aggregate line always present for big labs), a
  "what is blocking you" panel, the engagement-wide surfaces rail, recent activity, a persistent
  "your next move" anchor, and the connectivity panel.
- **Targets tab retained** for big labs (20+ boxes): dense, filterable, pinnable.
- **Welcome:** a gentle inline two-doors offer on first visit (New here, go to Learn / Working a box,
  start an engagement), prominent the first time only. First timers land in Learn; returning users
  with an active engagement land in the hub.
- **Pivot work:** a staging field-notes card in Next Steps for multi-stage moves (reusing the Learn
  multi-step local-and-host machinery); a glowing, reduced-motion-aware connectivity visualization on
  the hub with full text parity; and a symptom-first pivot troubleshooter that expands from the
  connectivity panel, backed by new diagnostic parsers, returning a verdict and a fix.

## 2. Accessibility and responsive contract (acceptance, every surface)

- Looks right from 4K to 1080p to phone (down to 320px, no horizontal scroll, 16px gutters,
  safe-area insets). Content caps so cards never stretch unreadably; grids reflow with `minmax()`.
- Keyboard reachable, visible focus rings, Esc closes menus, arrow keys in the cred menu.
- Screen-reader landmarks, `aria-label` on icon-only controls, `aria-expanded` on menus and sheets,
  `aria-current` on active nav and target, live regions for coach re-rank and new facts.
- Color never the sole signal; every state is also named in text. Token-based colors hold contrast on
  all seven skins (verify daylight).
- `prefers-reduced-motion` honored (connectivity flow becomes a static labeled arrow).
- 44px touch targets, text reflows at 200% zoom, 11px font floor.
- Single render per route (no double paint), deep links and the Cmd-K palette preserved everywhere,
  friendly empty states on every surface, and an opt-in focus mode that shows just the spine.

## 3. Route preservation matrix (nothing gets lost)

| Route | File | Scope | Current functionality (must be preserved) | New home |
|---|---|---|---|---|
| `#/study` | routes/study.js | global | Learn curriculum, by-port view, decision map, Atlas, cold box, scenarios | Top nav: Learn |
| `#/loadout` | routes/loadout.js | global | "Your box" tool install, machine profile sync | Top nav: Loadout |
| `#/home` | routes/home.js | engagement | Engagement manager: list, create, switch, launch | Becomes the engagement hub |
| `#/targets` | routes/targets.js | engagement | Targets list | Targets tab (enhanced: filter, pin), reached from the hub |
| `#/target/<ip>` | routes/target.js | target | Attack-chain bar, scoped path graph, access level, scoped moves, flags, fact storyline | Becomes the target workspace (Next Steps + Evidence spine) |
| `#/evidence` | routes/evidence.js | engagement | Paste to parsers, file-attach (capped), proof-screenshot gallery, parsed-fact review | Kept in full; global paste is an additive entry point |
| `#/path` | routes/path.js | target/eng | Next Steps coach, ranked moves, fillable commands, blocked-with-reasons | Kept; gains the pivot staging field-notes card |
| `#/playbooks` | routes/playbooks.js | global (aware) | Ordered command sequences, .sh export, fills from engagement | Top nav: Playbooks; contextual launcher from a target |
| `#/tools` | routes/tools.js | global (aware) | Command builders, autofill from target/creds | Top nav: Tools; contextual launcher from a target |
| `#/map` | routes/map.js | engagement | Engagement-wide overview graph | Hub surface; may host the connectivity lens |
| `#/domain` | routes/domain.js | engagement | SharpHound ingest, census, draggable attack-path graph, PlumHound cards, printable report | Hub surface |
| `#/creds` | routes/creds.js | engagement | Credential reuse matrix, one-click retarget | Hub surface; swapper promoted to the header |
| `#/checklist` | routes/checklist.js | engagement | Pack-driven tickable methodology (ticks per engagement) | Workspace surface |
| `#/findings` | routes/findings.js | engagement | Cross-host findings roll-up, severity grouping | Hub surface |
| `#/history` | routes/history.js | engagement | Run Log, activity history | Hub surface (feeds recent activity) |
| `#/scoreboard` | routes/scoreboard.js | engagement | Flags and OSCP scoring vs threshold | Hub surface |
| `#/report` | routes/report.js | engagement | Profile pipeline, redaction, md/html/PDF/docx export | Hub surface |
| `#/graph` | routes/graph.js | target/eng | Attack-path graph view | Reached from target workspace / Next Steps |

Rule: every route above keeps its hash and its render module. The overhaul changes how surfaces are
reached and arranged, and adds the hub, the target workspace, the global strip, the global paste, and
the pivot features. It does not rewrite or trim any existing route's behavior.

## 4. Phases (build straight through, commit frequently to the PR)

- **Phase 0:** this document (plan of record and preservation matrix).
- **Phase 1:** the shell. Five-item top nav, the global context strip (engagement, cred swapper,
  active target) reachable on Learn, left Parameters/Facts kept, mobile bottom bar and More sheet and
  context bottom sheet updated, deep links and Cmd-K preserved, browser-smoke nav assertions updated.
- **Phase 2:** engagement hub (`#/home` reworked), target workspace (`#/target/<ip>` built out),
  pinning (per engagement), the inline welcome and first-run routing, focus mode, empty states.
- **Phase 3:** the one additive global paste with proof-first fact routing, multi-host fan-out, visible
  destination, one-click reassign.
- **Phase 4:** the pivot staging field-notes card in Next Steps (reuses Learn multi-step machinery).
- **Phase 5:** improve the pivot parsers, the glowing connectivity visualization on the hub, and the
  symptom-first troubleshooter with new diagnostic parsers.

## 5. Build discipline

Run `node tools/stamp-assets.js` after any asset edit; keep `data/packs-bundle.js` in sync with
`node tools/build-packs.js`; keep the engine suites and `tests/browser-smoke.js` green, updating smoke
selectors deliberately when the shell changes (never silently); state in IndexedDB; the router renders
each route once. Validate each new surface at 4K, 1080p, and phone, and across skins, before moving on.
Finish by updating the PR description with the shipped work.
