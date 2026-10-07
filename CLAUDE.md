# Obol web

Read and follow [AGENTS.md](AGENTS.md), then [README.md](README.md) and
[docs/LOCAL-INHERITANCE-OVERHAUL.md](docs/LOCAL-INHERITANCE-OVERHAUL.md).

Obol web is the static-site edition of obol-local. The same contract applies to Claude and
any other coding agent. There are no separate, model-specific build instructions.

**House style:** no em dashes or en dashes anywhere (use commas, colons, or periods). Use proper
capitalization, and Title Case for UI labels, tabs, and section headings.

---

## Active build: Workbench and fact-driven utilities (in progress, PR #302)

**Plan of record.** If this chat is lost, resume from this section. Work on branch
`claude/obol-web-overhaul-local-59ttbx`. Commit frequently.

### Intention

Turn the Next Steps field notes from "one command plus a link" into a system that *answers* the
student's situation. obol already parses pasted tool output into facts; use those facts to hand the
exact, pre-filled next thing: the GTFOBins escape for the SUID binary they found, the hashcat mode
for the hash they hold, the reverse shell for their own lhost and lport, with the canonical source
one tap away. Add a global **Workbench** of client-side "borrowed back ends" (hash identifier,
reverse-shell builder, encoders or a mini CyberChef, GTFOBins browser, wordlist picker, JWT decoder)
that fill from the active engagement's credentials and parameters and also work standalone. The
audience is neurodivergent and disabled learners: clarity, continuity, and it-actually-works are
acceptance criteria, not polish.

### Non-negotiable boundaries (do not break)

- Static, browser-local, no backend, no execution, no telemetry (AGENTS.md). Everything is
  client-side JavaScript plus bundled data.
- **Pack commands stay the source of truth** (parity with obol-local; the decision map and the
  coach ranker derive from them). The Workbench and the resolver *enrich presentation* only. They
  never rewrite the move graph or change which move or command the coach ranks.
- **One store, one filler.** The Workbench is a view over `OBOL.store`, the fact ledger, and
  `OBOL.command.fillCommand`. No forked state.
- **Stay exam-legal.** OSCP is open-book (internet and notes allowed); it bans AI chatbots and
  LLMs, automated mass scanners, and sqlmap. obol is a deterministic reference and notes tool with
  no LLM, so it is on the right side of this. Keep it that way. The manual-SQLi builder is manual by
  design (the human runs every query).
- **Accessibility is acceptance.** Verify every surface with screenshots for readability and
  continuity; colour is never the sole signal; keyboard reachable; 11px font floor;
  `prefers-reduced-motion` honoured; works from 4K down to about 320px.
- **House style.** No em or en dashes. Title Case for tabs, labels, and headings.

### Owner caveats

- The reverse-shell builder must offer quick base64 encoding the way OffSec teaches for the OSCP,
  especially PowerShell `-EncodedCommand` (UTF-16LE, then base64). One click.
- Screenshot-verify everything for comprehension and continuity for this audience, and it must
  actually work: drive the real app headless and test it.
- Frequent commits so no work is lost.

### Verify each phase

`node tools/field-notes-coverage.js` · `node tools/lint-study.js --check` ·
`node tools/gap-report.js --check` · `for t in tests/engine/*.js; do node "$t"; done` ·
`NODE_PATH=/opt/node-tools/node_modules node tests/browser-smoke.js` ·
`node tools/stamp-assets.js` (after any asset edit) · drive the app headless (0 console errors) ·
screenshot the changed surface and read it for sense.

### Phases (check off as completed)

- [x] **P0.** This plan in CLAUDE.md plus task tracking.
- [ ] **P1.** Reference resolver engine (`fact -> exact, pre-filled knowledge`) plus the GTFOBins
  closed loop surfaced in Next Steps. Bundle GTFOBins data (GPL-3.0, attributed) as compact JSON.
- [ ] **P2.** Add `lport` (and a shell-type preference) to engagement params, the context and
  parameter bar, and the command filler.
- [ ] **P3.** **Workbench**: a new global section (neon glass, sub-tabs), credential and parameter
  aware, working standalone with no engagement. Tools: hash identifier, reverse-shell builder
  (including base64 and PowerShell `-EncodedCommand`), encoder or mini CyberChef (base64, url, hex,
  rot, IFS evasion), JWT decoder, wordlist picker, GTFOBins browser.
- [ ] **P4.** Stack-aware wordlist picker wired to content discovery; "run all" for *independent*
  checks and "Build in Workbench" affordances on cards (presentation only; pack commands untouched).
- [ ] **P5.** Manual-SQLi guided builder (manual, exam-legal; the parser reads each pasted result to
  fill the next query).
- [ ] **P6.** "Explain This Output" (parser annotate mode: highlight the lines that mint facts, say
  what each proves in plain language, and what it does not prove).
- [ ] **P7.** Finish the remaining field-note lanes: ad, windows, web_exploit_checks, database,
  pivot (and obol_local_pivot), creds (and credential_access), shells, cracking, findings_checks.
  Author with the new capabilities baked in.
- [ ] **P8.** Refine pass over recon, linux, and web; stretch sparks (lockout-aware spray planner,
  report-snippet generator, proof-screenshot helper, "what changed" fact diff).

Naming: the new global section is **Workbench** (distinct from Tools, the command builders, and
Loadout, your installed tools). Easy to rename.

### Status log (update per commit)

- 2026-10-07: P0, plan documented in CLAUDE.md.
