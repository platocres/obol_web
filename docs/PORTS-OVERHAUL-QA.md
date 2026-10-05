# Ports & UX overhaul — QA report

Scope of this build (one continuous pass, frequent commits on
`claude/obol-web-overhaul-local-59ttbx`): the "by-port" view redesign, a project-wide
decorative-emoji purge, eleven new port/service study modules, and parser + Next-Steps
parity so a paste of almost anything lights up the right module.

## What shipped

### Phase A — by-port redesign + emoji purge
- **by-port / "Once you are in" cards** collapse by default and expand on click; each collapsed
  card shows the service type and what it leverages. Long cards (HTTP, SMB/RPC, LDAP) group their
  moves under sub-category headers with continuous numbering. The connector arrows are gone;
  moves are a numbered list. `aria-expanded` on each header button (keyboard + screen-reader).
- **Decorative emoji removed everywhere.** New `assets/ui/icons.js` (`OBOL.ic(name)`) is a small
  monochrome inline-SVG set drawn in `currentColor`, so every glyph inherits the surrounding text
  colour and clears the per-skin contrast floor automatically. Structural/typographic glyphs
  (arrows, ticks, geometric marks, cut-here scissors) are kept. Guarded by a new regression test,
  `tests/engine/no-decorative-emoji.js`.

### Phase C — new port modules (tiers 1–3), each to the gold standard
Eleven modules, each with a bespoke `why`, a multi-route lead-up, playable field notes, a bespoke
"your turn", a coherent command/output sample, a by-port Evidence card, and ranker wiring:

| Lane | Modules |
|---|---|
| recon | Telnet (23), r-services (512/513/514), rsync (873), TFTP (69), X11 (6000), FTP→webroot (21) |
| database | Oracle TNS (1521), Elasticsearch (9200), Memcached (11211) |
| web | Tomcat AJP Ghostcat (8009), Java RMI (1099) |

Every batch was put through an **adversarial OSCP fact-review** (a separate agent checking command
syntax, tool names, output plausibility, CVE/version gating, and signal-in-output). Real findings
were fixed before and after commit, e.g.: dropped the non-existent `oracle-tns-version` NSE script
and fixed `odat --getFile` arg count; corrected the Elasticsearch RCE version gating (CVE-2015-1427
Groovy vs CVE-2014-3120 MVEL) and used the real sandbox-bypass payload; fixed `xdotool` to read
`DISPLAY` not a flag and `xwd`'s silent-on-success output; used `curl -v` for the FTP 226 reply;
and made `rmg enum` output match the real tool's prose.

### Phase B — parser + Next-Steps parity
- **Output-shape fallback** (`assets/engine/parsers/shape.js`): a final, conservative pass that
  recognizes a command-less paste by shape — a bare `N/tcp open service` table, a raw HTTP
  response, a `$krb5asrep$`/`$krb5tgs$` hash — and mints the facts it unambiguously proves.
  Strictly additive and anchored, so it only fills gaps and prose mints nothing.
- Fixed a latent newline-eating bug in the shared nmap open-port regex that silently dropped every
  other port on a simple two-column paste.
- **Next-Steps now surfaces every new port module with its command** the moment a scan shows that
  port open — wired automatically through `requires_any: port:N`, proven end-to-end by test.

## Verification (all green)

- `node tools/lint-study.js --check` → **LINT OK** (no sig-not-in-out / em-dash / backslash errors).
- Study coverage: every module carries why / lead-up / field notes / playable demo / practice / replay.
- **38/38** engine smoke tests pass, including the new `parser-shape-smoke`, `ranker-newports-smoke`,
  and `no-decorative-emoji` guards; the **79-case** parser corpus is unchanged by the regex fix.
- `tests/browser-smoke.js` → **all passed** (Playwright).
- **Accessibility** (hard gate): fg-over-bg composited per skin across all **7 skins** on the new
  by-port cards, grouped mega-cards, and move pills → **0 WCAG-AA contrast fails, 0 sub-11px text**
  (5,838 samples). Icons draw in `currentColor`, so they inherit passing text colours.
- `node tools/stamp-assets.js` → **all in sync**; `build-packs` → 19 packs, **179 actions**.

## Backport to obol-local
Tracked in `docs/PARITY-OBOL-LOCAL.md` section **E** — the 11 pack actions port as data; the
shape fallback + nmap-regex fix port to `obol/parsers/`; the by-port UI is web-only (skip).
