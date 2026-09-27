## v11.3 — Whole-session import, IP auto-route, and landing the plane after DCSync

- **Whole-session import.** Paste (or attach) an entire terminal from a run and obol splits it into per-command segments, orders them by prompt timestamp, drops duplicates, and mints facts from all of them at once — the "catch me up on the whole box" path. A non-destructive zsh prompt-stamp snippet (offered at workspace setup, pinned to your configured interface) gives every command a UTC timestamp for stitching and surfaces your VPN IP for `{{lhost}}`. `script` capture command included.
- **Per-command host auto-route.** Each imported command's facts file under the host it names (RHOST argument, else the host a tool reports on), never your Kali box: the configured VM IP, every `[tun0:…]` stamp, interface-dump addresses, loopback, link-local, and listener-flag IPs are all excluded. New hosts you touch are registered as targets; a target added by hostname-only folds into its IP card once a proven hostname ties them. A "Route facts to" selector forces a single host when you want it.
- **Attacker VM IP + interface** at engagement setup, feeding `{{lhost}}`, a new `{{iface}}` command token (Responder `-I`, mitm6 `-i`; defaults to `tun0`), and the import self-IP guard.
- **Land the plane after DCSync.** A completed NTDS dump now surfaces the built-in **Administrator (RID 500) hash as a usable credential** on the credential cards, and the coach's #1 move becomes **"Own the Domain — Pass-the-Hash as Administrator"** (☠ cash-in: `evil-winrm`/`psexec`/`wmiexec` via `-H`/`-hashes`). Owning the domain (`loot.ntds`) retires the credential-harvest and this-domain privilege-escalation routes that are now moot — coercion/relay, ADCS, Shadow Credentials, GPP, kerberoast/AS-REP, spray, gMSA/LAPS, SCCM, ACL abuse, Zerologon, WSUS/GPO/DNSAdmins (new `obsoleted_by` on pack actions) — while keeping shell access, persistence/ticket forging, cross-domain, delegation, and BloodHound mapping for larger labs. The existing profile-aware **Hunt for flags** move gains a pass-the-hash form so it reads the right proof files (HTB `user.txt`/`root.txt`, OffSec `local.txt`/`proof.txt`) straight from the dumped hash.
- **Reverted-lab IP remap.** The import panel takes an old-IP → new-IP remap (new defaults to the current target) and rewrites the old target IP across the whole capture before parsing (IP-boundary safe) — no more hand-editing a log after the box resets.

## v11.2 — Hands-on evidence, mobile app mode, first-run onboarding, and theme polish (PR #273, in progress)

- **Evidence file-attach.** Alongside the paste box, attach a tool's output file (`… | tee out.txt`) that is too big to paste. It is read locally via `FileReader` (no upload), parsed through the exact same conservative pipeline as a paste, and stored **capped** (a sample + line count, never the whole dump) — fixing the firehose (`bloodyAD`, a full `ldapsearch` subtree, wide `nxc`/gobuster sweeps) for every tool at once.
- **Web-suited commands.** An optional `web` command variant + `web_note` on a pack action, preferred by the web build (`command.js`), for commands tuned to a hands-on operator instead of a terminal reading output off disk. Additive and web-only — obol-local's mined data is untouched. The AD firehose actions now suggest a tee-to-file form with a note pointing at the attach control.
- **Mobile app mode.** A native-style shell on phones/tablets: a fixed bottom tab bar (Home · Coach · Evidence · Tools) with a slide-up **More** sheet, a compact appbar (hamburger opens the engagement drawer, search opens the command palette), safe-area insets, and no horizontal scroll down to ~320px. Fixed a grid-blowout overflow (`minmax(0,1fr)` on the app grid).
- **Theme.** Default skin returned to plain **Obol** (Neon/HTB/others stay selectable in ⚙). A new `--on-accent` token fixes unreadable buttons on light-accent skins (HTB chartreuse, amber, ghostwire) — dark text on bright fills, white on dark-accent skins.
- **Workspace directory model.** An engagement can carry a **working directory** (box-centric on labs, engagement-centric on exams; your own path or a sensible default, remembered between runs). obol never touches the filesystem — it uses the model to fill concrete output paths (`{{scandir}}` etc.) into commands, offer a one-time **scaffold command** on the coach (`mkdir -p <root>/{scans,loot,exploit,www,proof} && cd <root>`), and point the Evidence attach hint at `scans/`. Tools with native output prefer their own writes (`nmap -oN {{scandir}}/…`) — cleaner to parse — with `tee` as the fallback for the rest.
- **First-run onboarding.** A getting-started guide replaces the confusing "Untitled Run" phase bar until a run is actually set up; launching configures the default run in place (no stray empty engagement).
- **Report.** Proof screenshots embed into the `.docx` (OOXML inline pictures); Kali-style terminal emulation in the transcript, with a **target shell prompt** (`user@host:~$` / `C:\>`) for post-exploitation commands and `kali@kali` for recon.
- **Backdrop / copy.** The neon synthwave sun is styled as a giant OBOL coin (opt-in skin); the phase spine no longer pre-lights RECON/ENUM on an empty run; cleaner platform-profile names (Hack The Box CPTS, OffSec OSCP, OffSec Labs, OffSec OSWP).
- Documented the obol web ↔ obol-local split in `docs/LOCAL-INHERITANCE-OVERHAUL.md` §10.

## v11.1 — Follow-up live-review polish (PR #272)

- Block opacity defaults to 30% so the motion background shows through (adjustable in ⚙).
- Purged the stale auto-migrated "Imported engagement" (`10.129.85.48`) so a fresh visitor gets a clean run, never a prior visitor's session.
- Restored **workspace export/import** (⚙ panel): per-engagement and whole-workspace JSON; import assigns fresh ids and never clobbers.
- Checklist commands fill from facts + params + profile exactly like the coach, with a ready/needs state and copy-on-click.
- Fixed Tools card/badge spacing and uniformity (equal-height cards, tag row pinned, consistent pills).
- Report renders as clean paper with **Print / PDF** (print stylesheet) and a real **`.docx`** export (OOXML built in the engine, zipped with vendored JSZip); `.md` / `.html` kept.
- The OBOL coin spins slowly in the top-left (full-motion only, reduced-motion safe).
- Redesigned the raw "add a fact" field into a guided fact picker; self-hosted HTB-style fonts; skin options including HTB and the original indigo scheme.

## v11.0 — Local-Inheritance Overhaul: obol web becomes the static-site edition of obol-local (PR #269)

- Rebuilt obol web around obol-local's proven engine, packs, parsers, reporting, BloodHound analysis, checklist, and operator aesthetic over shared DNA — see `docs/LOCAL-INHERITANCE-OVERHAUL.md`. Not a port across foreign systems; a reunion over a 1:1 schema.
- **Engine (pure JS):** `facts`, `phases`, `pack` (planner), `command`, `graph`, `bloodhound`, `report`, `toolbuilder`, `profile`, `packs`, `parsers/*`, `playbooks`, `engmap` — verified against 157 real actions and the 79-case parser fixture corpus.
- **Surfaces (all live, route-lazy):** Engagements front door (platform profiles, scope paste, launch → seeds facts → coach); proof-gated **Next Steps** coach; **Evidence** intake; **Targets** + per-target attack-path graph; 36 **Tool Builders**; **Playbooks**; **Domain** (client-side SharpHound ingest → high-value census, interactive draggable attack-path graph, PlumHound-style query cards, printable report); **Map**; **Creds**; **Checklist**; **Scoreboard**; **Report** (OSCP/exec/technical profiles with redaction).
- IndexedDB store + deterministic single-render router + route-lazy bundles; boot-to-interactive ~200ms; perf budget enforced in CI. New CI (`.github/workflows/ci.yml`): engine node tests + headless browser smoke; old workflows removed.
- ⌘K command palette, proof-screenshot gallery on Evidence, cross-host Findings roll-up. Baggage purge trimmed the repo 24M → 11M.
- Scrubbed HTB-Forest box specifics (kept generic AD "forest" terminology); packs/playbooks are project-authored and public-safe (no raw course text, targets, flags, credentials, or private replay steps).

## v10.24 — Completes the AD/SMB/remote-access Tool Builder family repair with schema-owned surfaces, GUI command-control proof, Evidence ingestion, and corrected audit classification

- Added `data/product-hardening/ad-smb-remote-guidance-current.js` as the current owner for the AD/SMB/remote-access operator-surface repair.
- Repaired smbclient, smbmap, enum4linux-ng, ldapsearch, rpcclient, Responder, Evil-WinRM, Certipy, and Impacket psexec/wmiexec/smbexec/dcomexec/atexec as one audited family.
- Added `tests/run-tool-builder-ad-smb-command-controls-tests.js` so mode-card buttons, visible preset buttons, checkbox toggles, and option fields must generate real commands with expected flags and arguments.
- Corrected stale command shapes surfaced by that test: `ldapsearch` now emits `-H ldap://host`, and `rpcclient` exposes domain/workgroup plus authenticated/null-session command options.
- Added AD/SMB Evidence ingestion for shares, permissions, LDAP/RPC/enum facts, Responder captures, Evil-WinRM sessions, Certipy certificate workflows, and Impacket remote-exec artifacts/output/cleanup with conservative states and redaction.
- Patched current release loading and Evidence lazy loading so the family repair is available on compact Tools routes and Evidence routes.
- Corrected implemented-builder audit family classification for rpcclient, Evil-WinRM, and Impacket exec builders.
- Marked `tb-surface-ad-smb` complete and advanced Product Build Next to the network/service enumeration surface repair.

## v10.23 — This product-hardening build makes the credentials, authentication, and cracking Tool Builder family actually usable. v10.22 gave the family the operator-surface *look* but not a working tool: commands would not generate from common real inputs, a fabricated mask value was seeded, and most of the family had no Evidence ingestion. This build fixes command generation, removes fabricated seeds, adds Evidence ingestion with conservative Next Steps movement for the whole family, and adds a functional CI gate so a structurally-valid-but-unusable builder can no longer ship green

- Fixed Tool Builder command generation. The renderer's placeholder scrub is now touched-aware: a value the operator typed, loaded from a preset/snippet, or restored from a save reaches the command, while auto-seeded and programmatic values are still blocked. A hash file named `hashes.txt` — the value the field's own placeholder suggests — now builds a command instead of silently producing nothing. The anti-fabrication contract (a demo password / fake hash / `domain.local` / `user` can never fake a valid command) is preserved for seeded and programmatic input.
- Removed fabricated seed values from the live Tools route. `fallbackDefaults` no longer seeds a placeholder mask (`?u?l?l?l?d`) or other lab-looking values; the builder's own schema defaults supply safe starting values. This is what read as "mask turned on by default."
- Added Evidence ingestion for the credential/auth family in `assets/tool-builder-credential-evidence-current.js`. Hashcat, John, hashid, name-that-hash, CeWL, crunch, NetExec, secretsdump, GetNPUsers, and GetUserSPNs now turn pasted output (cracked vs exhausted, hash-type routing, generated wordlists, auth success/failure, share access, AS-REP/Kerberoast material, secret dumps, lockout and transport errors) into conservative outcome facts and a positive/negative/blocked/partial state routed to the credentials, Kerberos-roast, and credential-dump Path cards. Secrets are redacted from the stored sample. Hydra and Kerbrute remain covered by `tool-builder-evidence-current.js`.
- Added a functional command-generation gate (`tests/run-tool-builder-command-generation-tests.js`) that compiles every builder in every mode from realistic inputs, locks the touched-aware scrub in both directions, and rejects fabricated seed values on the live route. This closes the "green CI, broken tool" gap that let the v10.22 surfaces ship unusable.
- Added an Evidence-ingestion contract test (`tests/run-tool-builder-credential-evidence-tests.js`) proving recognition, honest inconclusive on unrelated output, correct tool attribution, and redaction across all ten new analyzers.
- Sharpened the Hashcat surface wording so Attack type reads as the wordlist-vs-mask switch and a mask is explained as a character pattern, removing the confusion the (now-removed) seeded mask value created.
- Marked the `tb-surface-credentials` queue item complete against the full Definition of Done and surfaced the AD/SMB/remote-access family (`tb-surface-ad-smb`) as the next build.
- Added `docs/TOOL-BUILDER-AGENT-GUIDE.md`: what "implemented" actually means for a Tool Builder and the checklist that would have caught these defects, for the agents (ChatGPT 5.5 High and Opus) that build them.

## v10.22 — This product-hardening build repairs the credentials, authentication, and cracking Tool Builder surfaces as a versioned release. It corrects the earlier shadow-surface implementation by making the repaired builders schema-owned records, restores the shared guard assertions that protect the broader Tool Builder surface, and adds live browser proof for every repaired credential/auth route

- Repaired the credential/auth/cracking Tool Builder family for Hashcat, John, Hydra, Kerbrute, CeWL, crunch, hashid, name-that-hash, NetExec, secretsdump, GetNPUsers, and GetUserSPNs.
- Added `data/product-hardening/credential-auth-guidance-current.js` as the current owner for credential/auth operator guidance and schema-record enrichment.
- Added `OBOL_TOOL_BUILDER_SCHEMA.replace(builder)` so current repair owners can replace an existing builder record through the same schema validation path used by registration.
- Moved field groups, presets, snippets, and operator guidance onto the real builder records returned by `schema.get()`, instead of synthesizing a second surface at render time.
- Preserved tool identity while adding outcome-labelled mode cards, grouped all-visible fields, useful presets, textarea snippets where appropriate, Reading-the-output proof guidance, and honest missing-field command states.
- Restored the shared Tool Builder surface guard assertions for Tools library owner behavior, DOM marker preservation, CSS surface rules, and fabricated-value rejection, including `domain.local`.
- Bumped the visible release identity to v10.22 and loads the credential/auth repair through the current compact Tool Library extension plan.

## v10.21 — This product-hardening build completes the first Tool Builder operator-surface family repair: every implemented Web discovery / HTTP builder now matches the `tb-ffuf` golden reference instead of rendering as an ungrouped wall of fields, and the surface contract test now enforces that standard across the whole family rather than ffuf alone

- Brought the Web discovery / HTTP builder family up to the `docs/TOOL-BUILDER-SURFACE-STANDARD.md` operator-surface standard: gobuster/feroxbuster, curl, sqlmap, WhatWeb, Nikto, httpx, wfuzz, ZAP, and the Burp Suite guided-workflow builder now declare grouped, all-visible `fieldGroups` with plain-language section descriptions, clickable per-field `presets` (wordlists, status/tuning values, ports, level/risk/tamper, payload lists, spider minutes, and more), and add-a-header `snippets` on the line-split header textareas — the same surface that made `#/tools/ffuf` the golden reference.
- Every non-action field in those builders now lives in exactly one described group, so no builder falls back to the ad-hoc "More options" wall; the hidden mode-driver field stays out of the groups because the outcome-labelled mode cards from `data/product-hardening/web-tool-guidance-current.js` control it.
- Fixed `assets/tool-builder-current.js` so the dynamically-injected curl `--path-as-is` field is placed into a group when it is added, instead of leaking into a leftover "More options" section. Command generation is unchanged (the `--path-as-is` token still emits).
- Strengthened `tests/run-tool-surface-contract-tests.js` so the full operator-surface standard (three or more described groups, real presets, header snippets on line-split header textareas, one heading, grouped sections, mode cards, the Reading-the-output row, and an honest missing-field state) is now enforced across the entire `web-discovery-http` family, not just ffuf. A regression on any one web builder now fails the build.
- No fabricated lab values are seeded as real command values anywhere in the repaired family; example text stays in grey field placeholders and presets carry only real tool defaults and wordlist paths.
- Advanced the Product Build Next queue: `tb-surface-web` is now `complete`, so the recommended package's next concrete entry auto-advances to the credentials/auth/cracking builder family (`tb-surface-credentials`). Added the `tb-surface-web` item test contract with acceptance criteria, validation commands, and proof files.
- Bumped the visible release identity to v10.21 and updated release history; the v8.8 browser workspace schema identity is unchanged.

## v10.20 — This product-hardening build organizes the remaining modeled Tool Builder inventory into coherent functional slices and tightens the handoff so future agents keep working the real Product Build Next queue while updating release history

- Redesigned the Tool Builder operator surface with `#/tools/ffuf` as the golden reference: one consolidated card, grouped all-visible fields with plain-language descriptions, outcome-labelled mode cards, a highlighted command hero, and clickable per-field presets plus header/cookie snippet buttons.
- Added a reusable operator-surface contract (`fieldGroups`, `field.presets`, textarea `field.snippets`) validated at registration, `docs/TOOL-BUILDER-SURFACE-STANDARD.md`, and `tests/run-tool-surface-contract-tests.js` that audits every registered builder, so future family repairs build to the same pattern.
- Stopped the Tools route seeding fabricated lab values (`10.10.10.10`, `FUZZ.corp.local`, placeholder credentials) into builder fields; commands prefill only from real workspace state.
- Added the Build 3 Web discovery/HTTP guidance repair so ffuf, Gobuster/Feroxbuster, curl, sqlmap, Burp Suite, WhatWeb, Nikto, httpx, wfuzz, and ZAP direct Tools routes expose visible action guidance, real presets, output interpretation, and proof boundaries.
- Updated the generic Tool Builder renderer to consume owner-profile guidance and render preset buttons on the Tools page instead of leaving repaired guidance invisible.

- Added the Build 2 implemented-builder audit ledger so currently registered implemented builders are grouped into pass/fail repair families, with database builders passing and older implemented builders failing visibly until their direct-route guidance is repaired.
- Clarified that direct Tools routes must not proof-gate command generation; Evidence gates proof claims and Next Steps movement after execution, not action selection or command preview generation.

- Reorganized the live Tools route's remaining Tool Builder inventory from one flat chip wall into functional implementation slices while keeping every real tool selectable.
- Exposed grouped modeled inventory through `OBOL_TOOL_BUILDER_IMPLEMENTATION_AUDIT_CURRENT.activeBatches()` and `auditSnapshot()` so future agents can burn down coherent tool families instead of random one-offs.
- Published the Tool Builder implementation audit owner as v10.20 so historical regressions can distinguish this inventory-organization build from the earlier implemented-builder audit.
- Added a focused Tool Builder inventory organization regression covering taxonomy, grouped active batches, and classic-tool classification.
- Slimmed the README back to an entrypoint with canonical linked docs, one Product Build Next block, explicit generated-block ownership, and a hard changelog rule for product-affecting builds.
- Restored the v10.20 changelog entry as a prepend to the existing release history, not a replacement for older headings.
- Added PR-template release-history fields so product-visible work cannot quietly skip `CHANGELOG.md` again.

## v10.18 — - Implements the next compact modeled-tool burn-down slice for CeWL, crunch, hashid, and name-that-hash

- Implements the next compact modeled-tool burn-down slice for CeWL, crunch, hashid, and name-that-hash.
- Adds a stable current owner, `data/product-hardening/credential-helper-tool-builders-current.js`, instead of restoring disposable release-specific Tool Library layers.
- Promotes CeWL and crunch from modeled inventory into schema-driven wordlist helper builders.
- Promotes hashid and name-that-hash from modeled inventory into schema-driven hash-identification helper builders.
- Adds conservative Evidence recognition for target-derived wordlists, bounded generation plans, hash-identification candidates, inconclusive output, blocked/failure states, and partial helper output.

## v10.17 — - Makes product-hardening extension loading route-aware so the Tool Library no longer loads the full historical v9 product-hardening layer stack on cache-clear visits to `#/tools`

- Makes product-hardening extension loading route-aware so the Tool Library no longer loads the full historical v9 product-hardening layer stack on cache-clear visits to `#/tools`.
- Keeps the compact current Tool Builder ownership live on Tools routes through `tool-builder-backlog-current.js` and `tool-builder-discovery-current.js`.
- Preserves the full historical product-hardening extension list for dashboard and non-Tools routes where older product-hardening route/card behavior may still be needed until it is separately compacted.
- Adds an explicit extension plan API so tests and future agents can tell the difference between historical release inventory and browser-live route loading.

## v10.16 — Product-hardening release v10.16 fixes the Tool Library layering regression after the modeled-tool burn-down releases. It compacts the recent Burp Suite and network/host discovery release owners into one current Tool Builder discovery owner and cleans the active Tool Builder queue so completed slices do not appear as pending work

- Added `data/product-hardening/tool-builder-discovery-current.js` as the current owner for Burp Suite plus masscan, Rustscan, naabu, fping, and nbtscan.
- Removed `data/product-hardening/burp-suite-tool-builder-v10.10.js` and `data/product-hardening/network-discovery-tool-builders-v10.15.js` from the live `data/current-release.js` extension list so the Tool Library no longer loads those release layers as part of normal startup.
- Kept Burp Suite as a first-class guided third-party GUI workflow with proxy setup, target scope, sitemap capture, Repeater, Intruder, Scanner triage, raw request/response import handoff, payload-position discipline, payload processing notes, grep/extract markers, scope/rate boundaries, and Burp Evidence ingestion.
- Kept masscan, Rustscan, naabu, fping, and nbtscan as implemented network/host discovery builders with minimum viable command generation, supplied/Evidence-derived prefill, additive controls, placeholder refusal, and network discovery Evidence ingestion.
- Cleaned the README Tool Builder queue and canonical Tool Builder queue doc so completed slices are not listed as active queue items and v10.15 is not described as the next modeled-tool build after it has merged.
- Added a current-owner hygiene rule: modeled-tool release slices must be folded into stable current owners or explicitly justified instead of accumulating live versioned Tool Library layers.

## v10.15 — Product-hardening release v10.15 implements the next modeled Tool Builder burn-down slice for network and host discovery and corrects the stale Tool Builder queue handoff so the active modeled-tool build is v10.15, not the old v10.09 web discovery slice

- Added first-class network and host discovery builders for masscan, Rustscan, naabu, fping, and nbtscan.
- Each builder starts from a minimum viable command populated from supplied workspace state, parsed Evidence-style target state, collected material, or safe defaults: masscan target plus ports, Rustscan target, naabu host/list mode, fping alive-host sweep/list mode, and nbtscan NetBIOS target.
- Optional behavior such as masscan rate/interface/router/exclusions, Rustscan batch/timeout/ulimit/Nmap handoff, naabu rate/retries/JSON/output, fping retry/timeout/IPv4/list mode, and nbtscan verbosity is additive through explicit controls.
- Added executable network discovery Evidence ingestion for open port observations, alive hosts, NetBIOS name/workgroup clues, no-hit states, partial output, and blocked/failure states.
- Kept discovery proof conservative: scan output can prove observed hosts, ports, names, or blocked discovery, but not compromise, credential validity, service exploitability, or pivot reachability without follow-up Evidence.
- Updated the Tool Builder queue handoff so v10.15 is the current network/host discovery burn-down slice and the remaining modeled tools stay active and descriptive.

## v10.14 — Is a product-hardening release that closes the operator scripts / LOTL track with a

- **Scripts UI now reflows at any width.** The `.script-usage` rows used a fixed 64px label column,
- **SQL injection is now two operator tools, not one wall of curl.**
  - New **SQLi login / auth bypass checklist** (`sqli-login`): a ready-to-fuzz list of
  - The **Manual SQLi** snippet (`manual-sqli`) is reframed as a database-navigation tool with a
- **New metadata contract validator** `tools/validate-script-metadata.js` (wired into the

## v10.13 — Is a product-hardening release that closes the operator scripts / LOTL track by making

- Added a conservative script-output Evidence analyzer, `assets/script-output-evidence-current.js`
- The analyzer recognizes the output of the path-proposable snippets and emits a fact **only** when
  - **manual SQLi** → `web.sqli_confirmed` on a SQL error / version echo / a recorded true-vs-false
  - **bash `/dev/tcp` sweep** and **PowerShell port sweep** → `scan.internal` only from an "open"
  - **LDAPSearch** and the **LDAPSearch cookbook** → `ad.user_list` from returned directory entries
- Every fact a snippet can emit is a subset of that snippet's `produces`, and each emitted fact is a
- Declared each path-proposable snippet's paste-back expectations in `data/scripts.js` as an
- Refined the v10.12 `produces` on the proposable snippets to the concrete facts the analyzer emits

## v10.12 — Is a product-hardening release that continues the operator scripts / LOTL track

- Added Next Steps path metadata to a curated set of scripts in `data/scripts.js`: `prereq`
- Marked the manual SQL-injection checklist (prereq `web.sqli_confirmed`/`web.parameterized`),
- `assets/operator-route-current.js` now proposes path-relevant scripts **additively** on
- When a ranked Orange card would recommend a rule-breaking tool (`sqlmap` and the like), the
- Script proposals and substitute offers deep-link to `#/tools/__scripts/<id>`;
- The additive script layer honors the workspace exam-safe mode flag (`state.ui.examSafe`)

## v10.11 — Is a product-hardening release that continues the operator scripts / LOTL track started in v10.06

- Added exam-safe / LOTL metadata to every script in `data/scripts.js`: `execMode` (`kali`/`target`/`pivot`), `examSafe` (rule-safe: no automated exploitation), `substitutesFor` (tool ids the snippet replaces), and a short `examSafeReason`.
- Marked LDAPSearch and the LDAP/PowerView cookbooks as substitutes for `bloodhound-python`/`netexec`, and the PowerShell port sweep as a substitute for `nmap`.
- Added a manual SQL-injection checklist (detect → UNION / error / boolean / time → extract → manual RCE) that stands in for `sqlmap`, issuing every request by hand.
- Added a bash `/dev/tcp` port and host sweep that stands in for `nmap` on a target with nothing to upload, and a LOLBIN file-transfer snippet (curl / wget / bash `/dev/tcp` / PowerShell / certutil).
- Added a Scripts / LOTL library facet, an `exam-safe · LOTL` badge, a `substitutes` label, and an `execMode` tag to the Scripts tab so operators can see and filter to exam-safe alternatives.
- Added a workspace exam-safe mode flag (`state.ui.examSafe`, default off) persisted through the same UI slice the script builders use, so a later build can offer the exam-safe alternative wherever the Next Steps path would recommend a rule-breaking tool.

## v10.10 — Is a product-hardening release that promotes Burp Suite out of legacy/example treatment and into first-class Tool Builder coverage

- Added a first-class Burp Suite guided workflow builder.
- Fixed the Burp Suite tool identity gap that made `#/tools/burp-suite` fall through as a legacy/example tool even though `burp suite` was present in the modeled inventory.
- Added guided proxy setup, browser proxying, target scope, sitemap capture, Repeater, Intruder, Scanner triage, and raw request/response import handoffs.
- Added executable Burp Evidence ingestion for Proxy history, raw HTTP request/response pairs, Repeater observations, Intruder result rows, Scanner issue details, sitemap/scope findings, vulnerability leads, and proxy/TLS failures.
- Kept Burp as a third-party GUI handoff instead of pretending Obol can drive the Burp GUI.

## v10.09 — Is a product-hardening release that burns down the first concrete slice of the remaining modeled Tool Builder backlog after the v10.08 implemented-builder audit

- Promoted WhatWeb, Nikto, httpx, wfuzz, and OWASP ZAP handoff from modeled inventory to implemented Tool Builder coverage.
- Added schema-driven web discovery/scanning builders with minimum viable commands, supplied or Evidence-derived prefill, additive GUI controls, and fake-placeholder refusal.
- Added executable web Evidence ingestion for fingerprint observations, scan findings, live endpoint probes, fuzz results, ZAP alerts/reports, failure, blocked, and partial states.
- Wired the web builder pack into current runtime loading so Tools and Card routes load it alongside the tunnel, Ligolo, authentication/enumeration, and helper builder packs.
- Kept the remaining modeled Tool Builder implementation backlog active and descriptive instead of falsely closing the full backlog.

## v10.08 — Closes the modeled Tool Builder implementation backlog with the implemented-tool Evidence and cross-surface audit

- Adds a permanent implemented-builder audit owner in `data/product-hardening/tool-builder-backlog-current.js`.
- Audits every inventory record marked `implemented` after the base, tunnel, Ligolo, authentication/enumeration, and helper builder extensions have registered.
- Requires every implemented inventory record to resolve to a real registered schema-driven builder.
- Requires every implemented builder to generate a minimum viable command for its selected mode from supplied workspace/Evidence context, collected material, or safe tool defaults.
- Blocks fake runnable placeholders such as `10.10.10.10`, `10.10.14.9`, `domain.local`, `user`, `Password123!`, fake NT hashes, and fake `hashes.txt` from satisfying command readiness.
- Preserves missing-field behavior: if required target, credential, callback, request, hash, listener, transfer, or file material is absent, the builder must show an incomplete state rather than manufacturing a command.
- Adds a Tools-route repair pass that remounts implemented builders with context derived from stored workspace/Evidence-style parameters instead of the older fake fallback values.
- Adds permanent Evidence coverage mapping for older implemented builders and keeps native/shared analyzer coverage explicit for tunnel, auth/enumeration, Ligolo, and helper builders.
- Adds `tests/run-v10.08-tests.js` and wires it into the current-product regression phase.
- Removes the final active Tool Builder implementation batch from `docs/TOOL-BUILDER-BUILD-QUEUE.md` and the README handoff.

## v10.07 — Completes the shell, payload, privilege-enumeration, listener, and transfer helper batch from the active Tool Builder implementation queue

- Adds schema-driven builders for linpeas, winPEAS, msfvenom, msfconsole, nc/Penelope, and common file-transfer helpers.
- Keeps helper commands minimal by default. Required callback, URL, target path, payload, output, listener, and transfer fields must be supplied before a command becomes valid. Optional behavior is added only through explicit GUI controls.
- Adds helper-specific Evidence ingestion for privilege-enumeration leads, payload generation, handler/listener readiness, callback/session observations, transfer success/failure/integrity, and cleanup state.
- Preserves the proof boundary: launching a helper, generating a payload, binding a listener, or serving a file is activity only. Access, execution, privilege, route reachability, credential validity, and cleanup are facts only when reviewed Evidence supports them.
- Wires the helper builders into the same current runtime loading path as the existing tunnel, Ligolo, authentication, and enumeration builders.
- Updates the Tool Builder implementation queue in README and `docs/TOOL-BUILDER-BUILD-QUEUE.md` so the completed helper batch is removed from active scope. The remaining active batch is the implemented-tool Evidence and cross-surface audit.

## v10.06 — Restores the operator **scripts** experience on the Tools route and starts the

- `assets/tools-library-current.js` now renders each script with its category, its
- Scripts now **pre-fill target-collected parameters** (target IP, `lhost`/`lport`,
- Builder control changes persist to the browser-local workspace (`C.updateScriptBuilder`)

## v10.05 — Is a product-hardening release for the authentication and enumeration Tool Builder batch

- Added schema-driven builders for Hydra, Kerbrute, smbclient, SMBMap, enum4linux-ng, ldapsearch, and Responder.
- Kept commands minimal by default. Required targets, identities, credential material, domain/base-DN inputs, or interfaces must be real before the corresponding mode becomes runnable; rate, thread, timeout, output, recursion, filter, capture, and escalation options remain explicit additions.
- Split smbclient and SMBMap into separate builders so share/session interaction and permission mapping do not collapse into one ambiguous workflow.
- Superseded legacy enum4linux with the enum4linux-ng builder rather than maintaining duplicate active command models.
- Wired the new builders into the current Tools/Card/Path runtime without adding execution. Obol continues to generate commands for human review and external execution only.

## v10.04 — - Promotes Ligolo-ng into the schema-driven Tool Builder platform for proxy, agent, interface/route, tunnel, listener, and proof/cleanup workflows

- Promotes Ligolo-ng into the schema-driven Tool Builder platform for proxy, agent, interface/route, tunnel, listener, and proof/cleanup workflows.
- Audits the existing chisel and SSH/plink tunnel builders against the v10.03 minimal-command contract so default previews stay small and optional behavior remains additive.
- Keeps tunnel creation as operator-reviewed command generation only. Route, listener, connectivity, and cleanup facts still require reviewed Evidence.
- Repairs the release handoff after the merged v10.03 command-hygiene work left the public release authority on v10.02.

## v10.02 — Product-hardening release v10.02 completes the Post-mining visual density regression pass

- Added a dedicated Playwright visual-density smoke for Path, Card, and Tools routes.
- Captured visual-density screenshots for Path on desktop and narrow layouts, representative Card routes, Tools home, ffuf, Hashcat, and Ligolo-ng.
- Failed the browser proof on reintroduced matching-card dumps, wrapper panels, internal cleanup/filler copy, hidden primary actions, missing Evidence loops, missing tool accessories, or obvious narrow-layout overflow.
- Closed the Post-mining visual density regression pass through the existing post-notes queue owner without adding another product-hardening browser runtime extension.
- Kept the modeled tool builder implementation backlog as the next concrete Build Next item after visual proof lands.
- Wired the visual-density smoke into the required browser gate so future UI cleanup regressions are caught on the same exact-head check as the normal browser smoke.
- Added focused v10.02 regression coverage for the proof ledger, queue handoff, browser smoke wiring, screenshot targets, and Path/Card/Tools density assertions.

## v10.01 — Product-hardening release v10.01 completes the Post-mining Tools builder-library cleanup

- Restored the historical `assets/app-v2-tools.js` fragment so the generated current application bundle stays stable, then moved the new Tools experience into a lazy current Tools owner.
- Replaced the tab-per-tool expanded matching-card dump with a grouped Tool Builder Library where direct `#/tools/<tool>` selection remains first-class.
- Promoted implemented schema-driven builders, generated command previews, pickable modes, and tool-specific accessories before related cards or legacy examples.
- Made ffuf-style fuzzing accessories explicit: web-content, vhost, and parameter wordlists plus filters, headers, cookies, recursion, threads, and output controls.
- Made cracking accessories explicit for Hashcat and John: rockyou.txt, hash modes, rules, masks, workload/output controls, and `--show` behavior.
- Kept related card commands available behind deliberate drilldown instead of deleting them or letting them dominate the selected tool route.
- Added focused Node and browser validation for direct tool selection, implemented-builder-first rendering, first-class accessories, hashcat/ffuf behavior, and matching-card-dump retirement.

## v10.0 — Card wrapper/decorator retirement for the post-notes product-hardening phase

- Completed the **Post-mining Card wrapper and decorator retirement audit** queue item without flattening the card system into one brittle blob.
- Retired the v9.67 visible action-first stabilizer as a no-op compatibility ledger. The card route no longer needs a corrective panel because the v9.99 integrated card owner renders why-now, primary action, and evidence loop natively.
- Converted the v9.68 note-card disposition layer from runtime route surgery into a data/canonicalizer seam. Demoted cards are preserved through merged parent guidance and card-index aliases instead of patching `viewCard`, `liveCardById`, or the URL hash.
- Kept dynamic why-now as a useful render-time compute helper while retiring the v9.71 post-render DOM injector behavior.
- Retired the v9.77 dynamic why-now route stabilizer as a no-op compatibility shim. Duplicate why-now boxes should now be structurally impossible because the card renderer owns the single visible why-now region.
- Preserved the dogfooding seams Brandon needs for lab testing: card data, action-first plan data, why-now computation, canonicalizer maps, merged supporting guidance, card-index aliases, and progressive-disclosure renderer helpers.
- Kept the build request-budget neutral by storing the v10.0 proof ledger in the repo without loading it as another browser runtime extension.
- Advanced Product Build Next to **Post-mining Tools builder-library cleanup**.

## v9.99 — Completes the **Post-mining Card progressive-disclosure cleanup** queue item. It makes the card route action-first without adding another corrective wrapper over the old card body

- The shared card renderer now emits a current card UI owner marker and renders cards in the intended operator order: why-now, primary action, evidence paste-back, outcome controls, then secondary detail.
- Dynamic why-now is consumed inside the normal card render path instead of relying on a post-render box as the source of truth.
- The old dynamic why-now injector and stabilizer now honor the integrated card owner guard, so they stop inserting or repairing duplicate visible why-now boxes when the current card UI has already rendered one.
- Raw secondary material is grouped into named disclosures: Commands and checks, Success and failure routing, Wordlists, Supporting guidance, Defender/references/reporting notes, and Recent activity.
- Recurring cards expose their recurrence scope near the top of the card so per-host and per-subnet actions make sense from the card page itself, not only from Path.
- Card-scoped Evidence remains first-class: Analyze pasted evidence, Mark tried, Mark succeeded, reset controls, and the evidence textarea stay above lower-priority references/history.
- The Product Build Next queue now advances to **Post-mining Card wrapper and decorator retirement audit**, keeping the proof-delete cleanup ahead of Tools cleanup.

## v9.97 — Continues the post-notes product-hardening phase. It completes the **Post-mining Path supporting-detail cleanup** queue item and, in the same coherent Next Steps ownership area, introduces **recurring operator capabilities** so repeatable actions like pivoting stop behaving like one-and-done checklist steps

- Audited the Next Steps / Path route (the stated intent of this build) and recorded the findings in `data/product-hardening/network-position-recurrence-v9.97.js`: the best next move now lives in its own dominant panel, the raw supporting-methodology DOM carryover is gone, and the fixes are proven rather than parked.
- Replaced the "Supporting methodology detail" drawer — which dragged up to eight arbitrary prior DOM nodes back into the prime decision view — with a compact **evidence-needs drawer keyed to the best next move**: what to paste back, the facts it produces, and how it fails, read from the card model.
- Kept Simplified, Checklist, and Live Map rendering from the one shared `nextStepsOverview34` graph; the cleanup adds no second path model.
- Added a **recurrence model**: cards can declare `recurrence` (`per-host` / `per-subnet`) and a `scopeKey`. The Path recommender expands an armed per-subnet capability into one row per open scope, so pivoting re-arms for each internal network the operator has only observed — instead of disappearing after the first tunnel.
- Shipped the first end-to-end recurring loop as the concrete proof:
  - a new per-host card, **Map the foothold's network position**, appears once you have a shell and suggests OS-routed enumeration (`ip -o addr` / `ip route` / `ip neigh` on Linux, `ipconfig /all` / `route print` / `arp -a` on Windows);
  - reachability signatures parse that pasted output and propose, for operator review, `pivot.host_multihomed` and `pivot.subnet_observed_only` when a private subnet is routed through the foothold — a single-homed host proposes neither;
  - `pivot.subnet_observed_only` is scoped to the host context and grounds the previously ungated pivot / tunnel workflow, so pivoting surfaces in Next Steps exactly when a second network is proven to exist.
- Kept proof conservative: discovering a second interface or route only proves the host is multi-homed. It produces **observed-only** reachability, never access; a subnet becomes reachable only when a listener and a connectivity check are proven.
- Proved the closed item with `tests/run-v9.97-tests.js` (the recurrence loop, the reachability signatures, and the queue closure) plus its inline acceptance criteria, and demoted the v9.96 current-release assertions to version-agnostic checks.

## v9.96 — Starts the post-notes hardening phase with an audit-first build for Next Steps, Card, and Tools clarity

- Added a post-notes clarity audit ledger that records concrete findings for README handoff posture, Path supporting-detail clutter, dense Card pages, the old Tools inventory model, and missing visual-density regression coverage.
- Marked the broad post-notes Next Steps/tool-card clarity audit item complete only after attaching findings, severity, evidence, and proposed solutions.
- Split the follow-up work into focused queued builds for Path supporting-detail cleanup, Card progressive-disclosure cleanup, Tools builder-library cleanup, and visual-density regression proof.
- Cleaned the README quickstart so source-note mining docs are reference-only after v9.95 unless Product Build Next or the user explicitly reopens note-derived work.
- Added the `Post-notes Operator UI Clarity` work package so future agents see the split plan instead of trying to land every cleanup in one vague UI patch.
- Added a v9.96 current-product test that checks release identity, audit findings, queue split, package recommendation, and README post-notes handoff wording.

## v9.95 — - Completes the final `source-note-cluster-reference-index-and-course-map-private-heavy` queue item as a terminal private-heavy disposition

- Completes the final `source-note-cluster-reference-index-and-course-map-private-heavy` queue item as a terminal private-heavy disposition.
- Keeps reference indexes, tables of contents, course maps, grading paths, flags, private targets, screenshots, and exact solution chains out of public UI.
- Folds the public-safe residue into the existing `flag-discipline` owner as source-boundary and queue-handoff guidance instead of creating reference-index or course-map wrapper cards.
- Advances source-note accounting to 556/556 reviewed and 0 pending.
- Clears the generated Product Build Next note batch handoff so the README and dashboard no longer imply more source-note review remains.
- Pivots the visible queue to post-notes product hardening: Next Steps/tool-card clarity, old-layer retirement, regression-speed cleanup, and browser/offline work.

## v9.94 — - Mines the `source-note-cluster-exam-skills-assessments-private-heavy` queue item as a private-heavy disposition boundary instead of copying walkthrough or assessment material into public UI

- Mines the `source-note-cluster-exam-skills-assessments-private-heavy` queue item as a private-heavy disposition boundary instead of copying walkthrough or assessment material into public UI.
- Folds the public-safe residue into the existing `flag-discipline` primary owner so exam flags, solution chains, private targets, and assessment-specific steps remain out of product text.
- Keeps `report-discipline`, session, route, Metasploit, and AD cards as context only; they receive no duplicate skills-assessment or walkthrough wrapper cards.
- Adds a private-boundary analyzer that recognizes assessment, walkthrough, exact-solution-chain, grading-objective, flag, credential, host, and screenshot/prose leakage signals while redacting sensitive material.
- Adds three public Field Notes covering generalized skill extraction, private-only walkthrough disposition, and exam/report redaction gates.
- Advances Product Build Next to the final private-heavy reference index and course-map cluster, leaving 1 pending note.

## v9.93 — - Mines the `source-note-cluster-reporting-cleanup-and-remediation-guidance` queue item into public-safe reporting, cleanup, mitigation, redaction, and retest guidance

- Mines the `source-note-cluster-reporting-cleanup-and-remediation-guidance` queue item into public-safe reporting, cleanup, mitigation, redaction, and retest guidance.
- Folds the cluster into the existing `report-discipline` primary owner instead of creating duplicate finding, report-writing, remediation, screenshot, cleanup, or retest wrapper cards.
- Keeps technical proof cards as context only so exploit/session/tunnel details remain owned by their existing cards while report readiness is handled in one clear place.
- Adds a report-readiness analyzer for finding narrative, evidence chain, root cause, mitigation mapping, cleanup ledger, retest signal, and redaction review evidence.
- Adds four public Field Notes covering complete finding chains, cleanup ledgers, root-cause-bound mitigation, and redaction/retest gates.
- Advances Product Build Next to the private-heavy skills-assessment and walkthrough-heavy note cluster, leaving 34 pending notes across two private-heavy cluster review items.

## v9.92 — - Mines the `source-note-cluster-metasploit-resource-post-exploitation-and-cleanup` queue item from the complete private review-packet route into public-safe Metasploit resource-script, session-state, post-module, loot-triage, and cleanup mechanics

- Mines the `source-note-cluster-metasploit-resource-post-exploitation-and-cleanup` queue item from the complete private review-packet route into public-safe Metasploit resource-script, session-state, post-module, loot-triage, and cleanup mechanics.
- Folds the cluster into the existing `metasploit-resource-pivot-workflow` primary owner instead of creating duplicate msfconsole, resource-script, Meterpreter, loot, or cleanup wrapper cards.
- Keeps Metasploit as a reviewable operator aid: resource scripts, global options, jobs, sessions, routes, post modules, loot tables, and cleanup all need visible Evidence before the path advances.
- Adds an Evidence analyzer for resource scripts, workspace/scope options, jobs, sessions, route state, post-module inventory, artifacts, loot triage, and cleanup while redacting hosts, secrets, flags, hashes, tickets, and token-like values.
- Adds four public Field Notes covering resource-script review, session-bound post-module evidence, loot/artifact triage, and framework cleanup/report proof.
- Advances Product Build Next to `source-note-cluster-reporting-cleanup-and-remediation-guidance`, leaving 44 pending notes in three public-safe cluster review items.

## v9.91 — - Mines the `source-note-cluster-pivoting-tunneling-and-route-proof` queue item from the complete private review-packet route into public-safe pivoting, tunneling, proxying, and route-proof mechanics

- Mines the `source-note-cluster-pivoting-tunneling-and-route-proof` queue item from the complete private review-packet route into public-safe pivoting, tunneling, proxying, and route-proof mechanics.
- Folds the cluster into the existing `rdp-socks-tunnel-workflow` primary owner while keeping `metasploit-resource-pivot-workflow` as contextual support instead of a duplicate pivot wrapper card.
- Adds route-proof guidance for SSH local, remote, and dynamic forwarding; Windows `plink.exe` and OpenSSH tunnel syntax; chisel reverse SOCKS; proxychains service checks; socat relays; Windows `netsh interface portproxy` plus firewall cleanup; sshuttle subnet pivots; DNS tunneling handoff; and teardown proof.
- Adds an Evidence analyzer for route tables, interface output, forwarding modes, chisel output, Windows portproxy/firewall state, proxied tooling, service connectivity, and cleanup signals while redacting hosts, secrets, flags, and lab-specific names.
- Adds four public Field Notes covering route-state proof, SSH forwarding mode selection, Windows and HTTP pivot boundaries, proxychains service checks, and cleanup proof.
- Advances Product Build Next to `source-note-cluster-metasploit-resource-post-exploitation-and-cleanup`, leaving 57 pending notes in four public-safe cluster review items.

## v9.90 — Mines the active Product Build Next cluster, `source-note-cluster-ad-credential-attacks-and-ticket-material`, from the complete private review-packet route into public-safe credential-attack mechanics

- Folded AD credential-attack and ticket-material guidance into the existing `ad-password-spray-safety-workflow` owner card instead of creating duplicate Kerberoast, AS-REP, spray, or ticket wrapper cards.
- Added a public-safe action spine for password policy proof, target-list provenance, Kerberos user enumeration, AS-REP material capture, Kerberoast ticket capture, offline cracking status, scoped validation, and ticket/cache review.
- Added field notes for lockout policy, target provenance, hash and ticket classification, cracking versus validation, redaction, and report boundaries.
- Added an analyzer and intake routing for pasted AD credential-attack evidence while redacting raw hashes, tickets, passwords, flags, lab names, and host IPs.
- Advanced the source-note cluster queue to pivoting, tunneling, proxying, and route proof with 76 pending notes remaining.

## v9.89 — - Mined `source-note-cluster-ad-enumeration-ldap-kerberos-bloodhound` into public-safe AD enumeration, LDAP/Kerberos discovery, BloodHound, and domain-context mechanics

- Mined `source-note-cluster-ad-enumeration-ldap-kerberos-bloodhound` into public-safe AD enumeration, LDAP/Kerberos discovery, BloodHound, and domain-context mechanics.
- Folded the cluster into the existing `ad-enumeration-bloodhound-collection` owner card instead of adding duplicate LDAP, Kerberos, BloodHound, or domain-context wrapper cards.
- Added action-spine command guidance for DC service fingerprinting, SMB/domain fingerprinting, LDAP naming contexts and scoped queries, Kerberos user enumeration, AS-REP/SPN boundary discovery, BloodHound.py, PowerView, and SharpHound.
- Added public-safe field notes for domain baselines, DC service surface, LDAP naming-context proof, user/group enumeration provenance, Kerberos identity boundaries, BloodHound collection proof, Windows-side AD context, and report redaction.
- Added `ad-enumeration-ldap-kerberos-bloodhound-v989` analyzer logic for pasted AD, LDAP, Kerberos, BloodHound, PowerView, SharpHound, SMB/domain fingerprint, and boundary/failure evidence.
- Advanced the source-note ledger to 458/556 reviewed, 98 pending, and 6 remaining public-safe cluster review items.
- Generated the next cluster queue so Product Build Next advances to `source-note-cluster-ad-credential-attacks-and-ticket-material`.

## v9.88 — - Mined `source-note-cluster-windows-privesc-services-and-local-admin` into public-safe Windows local privilege-escalation mechanics

- Mined `source-note-cluster-windows-privesc-services-and-local-admin` into public-safe Windows local privilege-escalation mechanics.
- Enriched the existing Windows privesc owner cards rather than creating duplicate wrapper cards.
- Added service-control, unquoted-path, scheduled-task, registry-policy, credential-trail, token/local-admin, cleanup, and report-boundary guidance.
- Added public-safe field notes for Windows identity baselines, service boundaries, unquoted path proof, scheduled task chains, registry policy checks, credential trails, token capability review, and cleanup/reporting.
- Added `windows-privesc-services-local-admin-v988` analyzer logic for pasted Windows service, task, registry, token, local-admin, credential-candidate, elevated-effect, and cleanup evidence.
- Advanced the source-note ledger to 428/556 reviewed, 128 pending, and 7 remaining public-safe cluster review items.
- Generated the next cluster queue so Product Build Next advances to `source-note-cluster-ad-enumeration-ldap-kerberos-bloodhound`.

## v9.87 — - Mined `source-note-cluster-linux-privesc-enumeration-and-proof` into public-safe product mechanics

- Mined `source-note-cluster-linux-privesc-enumeration-and-proof` into public-safe product mechanics.
- Added `linux-privesc-signal-router` as a real primary product-hardening card, not a wrapper.
- Enriched `linux-privesc-boundary-sweep` so Linux service, sudo, SUID, capability, scheduled-execution, and kernel-risk lessons stay inside the canonical privilege-escalation boundary instead of becoming duplicate cards.
- Added public-safe field notes for signal routing, sudo rule proof, SUID/capability candidate handling, service/scheduled execution proof, kernel/local-exploit risk, and cleanup/report boundaries.
- Added `linux-privesc-signal-router-v987` analyzer logic for pasted sudo, SUID, capability, systemd/cron, kernel, enum-script, cleanup, and identity evidence.
- Added a downstream cluster queue refinement so the next Product Build Next item advances to `source-note-cluster-windows-privesc-services-and-local-admin` and the remaining eight cluster items stay explicit.
- Advanced the source-note ledger to 404/556 reviewed, 152 pending, and 8 remaining public-safe cluster review items.

## v9.86 — - Mined `source-note-cluster-shells-payloads-and-file-transfer-stabilization` into public-safe product mechanics

- Mined `source-note-cluster-shells-payloads-and-file-transfer-stabilization` into public-safe product mechanics.
- Added `listener-and-shell-stabilization-card` as a real primary product-hardening card, not a wrapper.
- Added card taxonomy metadata so the new card is clearly marked as `cardKind: primary`, `cardOrigin: product-hardening`, `introducedIn: v9.86`, and `currentOwner: true`.
- Enriched `metasploit-resource-pivot-workflow` with tunnel, route, SOCKS, proxychains, and internal-service proof handling.
- Enriched `web-upload-inclusion-proof-chain` with file-transfer source, destination, integrity, permissions, execution, and cleanup handling.
- Enriched `ad-enumeration-bloodhound-collection` with SharpHound, share, ACL, and AD collection-output transfer handling from the mixed packet window.
- Added public-safe field notes for listener receipt, payload/handler matching, PTY stabilization, file transfer, tunnel route proof, AD artifact transfer, and cleanup/report boundaries.
- Added `shell-payload-transfer-evidence-analyzer-v986` for pasted listener, payload, transfer, tunnel, proxychains, and AD artifact evidence.
- Advanced the source-note ledger to 386/556 reviewed, 170 pending, and 9 remaining public-safe cluster review items.
- Advanced Product Build Next to `source-note-cluster-linux-privesc-enumeration-and-proof`.

## v9.85 — - Mined `source-note-cluster-pass-the-hash-and-remote-exec-artifacts` from the cluster queue

- Mined `source-note-cluster-pass-the-hash-and-remote-exec-artifacts` from the cluster queue.
- Enriched existing `pass-the-hash-proof-chain`, `pth-remote-exec-artifacts`, and `pth-token-filtering-check` instead of creating a new wrapper card.
- Added public-safe field notes for NT hash material scope, channel-scoped validation, Windows process-context PtH, SMB/admin-share/SCM proof separation, remote-exec artifacts, WinRM/RDP boundaries, token filtering, failure disposition, report redaction, and dashboard handoff.
- Added `pass-the-hash-remote-exec-evidence-analyzer-v985` for pasted PtH, remote execution, token-filtering, and cleanup evidence.
- Advanced the source-note ledger to 362/556 reviewed, 194 pending notes, and 10 remaining public-safe cluster queue items.
- Moved Product Build Next to `source-note-cluster-shells-payloads-and-file-transfer-stabilization`.

## v9.84 — - Mines the queued `source-note-cluster-credential-dumping-lsass-and-windows-secrets` cluster from the complete private review packet route and converts it into public-safe credential dumping, secret-source triage, parser-output classification, validation, cleanup, and dashboard handoff mechanics

- Mines the queued `source-note-cluster-credential-dumping-lsass-and-windows-secrets` cluster from the complete private review packet route and converts it into public-safe credential dumping, secret-source triage, parser-output classification, validation, cleanup, and dashboard handoff mechanics.
- Adds `windows-secret-source-triage-workflow` as a real action-spine card because selecting among LSASS memory, registry hives, DPAPI/vault material, application configuration, database rows, and copied secret files is its own operator decision point.
- Enriches `credential-dump-proof-chain` with LSASS PID/dump lineage, registry hive pairing, offline parser output, hash/crack boundaries, scoped validation, and cleanup evidence.
- Enriches `pass-the-hash-proof-chain` only as a downstream handoff, not as a duplicate credential-dump card.
- Adds `windows-credential-dumping-secrets-analyzer-v984` for pasted LSASS, hive, parser, DPAPI/vault, app-config, database-hash, cracking, validation, blocked-control, and cleanup evidence.
- Adds public-safe field notes for secret-source triage, LSASS lineage, hive pairing, parser material classification, DPAPI/vault context, application/database secret provenance, cracking/reuse boundaries, blocked-control evidence, cleanup/redaction, and dashboard handoff.

## v9.83 — - Mines the queued `source-note-cluster-web-content-discovery-and-technology-fingerprinting` item from the complete private review packet route

- Mines the queued `source-note-cluster-web-content-discovery-and-technology-fingerprinting` item from the complete private review packet route.
- Adds the new `web-content-discovery-fingerprinting-workflow` card because DNS/domain recon, resolver baselines, content discovery, technology fingerprinting, exploit-candidate review, and command-execution proof form a distinct operator action spine.
- Enriches `web-upload-inclusion-proof-chain` and `burp-intruder-fuzzing-workflow` with web-discovery handoff evidence instead of creating upload, fuzzing, or proxy wrapper cards.
- Adds public-safe field notes for DNS/cloud recon boundaries, resolver baselines, recursive subdomain discovery, content enumeration deltas, technology/version confidence, exploit-candidate review, authenticated web-exploit proof boundaries, OSINT metadata, route unlock logic, and reproducible request notes.
- Adds `web-content-discovery-fingerprinting-analyzer-v983` for pasted DNS, resolver, content-discovery, technology-fingerprint, exploit-candidate, command-execution, and OSINT metadata evidence.
- Advances the notes burn-down to 333/556 reviewed, leaves 223 pending notes in 12 clusters, and moves Product Build Next to `source-note-cluster-credential-dumping-lsass-and-windows-secrets`.
- Keeps the Product Hardening Dashboard and README on the same queue source by patching the source-cluster ledger and Product Build Next handoff together.

## v9.82 — - Corrects the queued `source-note-cluster-web-proxy-fuzzing-and-transform-workflows` item after complete packet review showed the assigned source window was AD, Kerberos, LOTL, credentialed enumeration, password policy, password spraying, Inveigh, and RDP SOCKS workflow material rather than Burp/ZAP proxy fuzzing

- Corrects the queued `source-note-cluster-web-proxy-fuzzing-and-transform-workflows` item after complete packet review showed the assigned source window was AD, Kerberos, LOTL, credentialed enumeration, password policy, password spraying, Inveigh, and RDP SOCKS workflow material rather than Burp/ZAP proxy fuzzing.
- Records the corrected completed cluster identity as `ad-initial-enum-credential-spray-rdp-socks-workflows`.
- Enriches the existing `ad-enumeration-bloodhound-collection` card with Kerberoast-from-Linux boundaries, LOTL host/domain enumeration, credentialed Linux enumeration, security-control posture review, LAPS posture, Inveigh boundary handling, and passive/active domain discovery staging.
- Adds the new `ad-password-spray-safety-workflow` card because password policy, target-list provenance, spray cadence, result validation, and lockout safety form a distinct operator action spine.
- Adds the new `rdp-socks-tunnel-workflow` card because RDP dynamic virtual channel setup, plugin load, server start, local SOCKS listener proof, Proxifier routing, and final reachability form a distinct operator action spine.
- Adds public-safe field notes for Kerberoasting boundaries, LOTL enumeration, credentialed Linux enumeration, security controls, RDP SOCKS double pivots, password-policy review, spray target-list provenance, spray result validation, Inveigh/LLMNR boundaries, and staged initial domain enumeration.
- Adds `ad-initial-enum-spray-rdp-socks-analyzer-v982` for pasted Kerberoast, LOTL, CME/SMBMap/RPC/BloodHound, Defender/AppLocker/LAPS, RDP SOCKS, password policy, spray, Inveigh, and passive/active discovery evidence.
- Advances notes burn-down to 317/556 reviewed, leaves 239 pending notes in 13 clusters, and moves Product Build Next to `source-note-cluster-web-content-discovery-and-technology-fingerprinting`.

## v9.81 — Corrects the next notes-cluster handoff before product work drifts into the wrong surface

- Corrects the mislabeled `source-note-cluster-browser-client-cookie-transform-workflows` queue item after complete packet review showed the assigned source window was AD, SMB, pivoting, trusts, DCSync, privileged access, and Kerberos workflow material.
- Records the corrected completed cluster identity as `ad-pivot-smb-trust-kerberos-workflows` without creating a browser-cookie, SMB, DCSync, trust, Kerberos, or pivot wrapper card.
- Enriches the existing `ad-enumeration-bloodhound-collection` card with SMB, RPC, trust, SPN/Kerberoast, replication-rights, remote-access, and bounded DCSync proof guidance.
- Enriches the existing `metasploit-resource-pivot-workflow` card with SSH local forwarding, dynamic SOCKS, proxychains scan, and Metasploit route proof boundaries.
- Adds public-safe field notes and the `ad-pivot-smb-trust-evidence-analyzer-v981` analyzer for SMB, pivot, trust, DCSync, remote-access, Kerberos, and ACL evidence.
- Advances the notes burn-down to 307/556 reviewed, leaves 249 pending notes in 14 clusters, and moves Product Build Next to `source-note-cluster-web-proxy-fuzzing-and-transform-workflows`.

## v9.80 — Obol v9.80 mines the next Product Build Next source-note cluster, `source-note-cluster-xss-client-session-and-csp`, covering XSS context classification, client-side session behavior, CSP and browser controls, scanner triage, and browser-proof boundaries

- adds a command-bearing `xss-browser-proof-boundary` card for inert reflection checks, context classification, safe browser proof, Burp/ZAP replay, DOM source/sink review, CSP/header checks, and cookie/session impact boundaries;
- adds contextual field notes for XSS context classification, browser proof, DOM source/sink evidence, cookie/session boundaries, CSP/browser controls, scanner triage, report/remediation language, and cluster reconciliation;
- adds the `xss-client-session-csp-analyzer-v980` analyzer for browser execution signals, DOM source/sink clues, CSP and browser-control behavior, cookie/session material, scanner leads, and encoding/sanitization boundaries;
- keeps reflected/stored/DOM XSS, session exposure, CSRF/state-change impact, and browser controls separate so a reflected marker or scanner alert does not become an overstated execution claim;
- completes the XSS/client/session/CSP cluster queue item and reconciles the downstream queue by splitting browser cookie/session transform fuzzing out of the broader proxy/fuzzing cluster.

## v9.79 — Obol v9.79 mines the next Product Build Next source-note cluster, `source-note-cluster-sql-injection-discovery-and-extraction`, covering SQL injection discovery, UNION and error/blind proof boundaries, database enumeration, and sqlmap handoff

- adds a command-bearing `sqlmap-request-proof` card for SQLi triage, column-count probing, visible UNION placement, request-file sqlmap handoff, database enumeration, narrow dump proof, and gated file-read branches;
- adds contextual field notes for SQLi hypothesis triage, UNION column/visibility proof, database enumeration order, sqlmap request handoff, blind/error/time technique separation, file/shell risk boundaries, and report/remediation language;
- adds the `sql-injection-evidence-analyzer-v979` analyzer for syntax/error clues, UNION and column probing, database metadata enumeration, sqlmap output, blind/time evidence, data extraction, and file/shell branch evidence;
- keeps authorization and SQL injection adjacent but separate so SQLi data access does not accidentally become object/role authorization proof;
- completes the SQLi cluster queue item and advances the next notes-first queue item to the XSS/client/session cluster.

## v9.78 — Obol v9.78 mines the next source-note cluster, `source-note-cluster-web-authz-idor-verb-tampering`, covering IDOR, HTTP verb tampering, and authorization replay boundaries from the complete private review packet route

- re-reads the assigned complete packet window from `platocres/obol-source-notes@agent/review-packets:data/review-packets/htb-penetration-tester-01.json`;
- extracts generalized authorization, object-reference, method-replay, and role-differential mechanics without publishing course prose, flags, targets, credentials, screenshots, or exact solution chains;
- enriches the existing `web-authz-boundaries` card instead of creating duplicate IDOR or verb-tampering cards;
- adds public field-note guidance for object-reference discovery, authorization-differential proof, method replay, bounded enumeration, and report wording;
- adds analyzer facts for pasted IDOR, role-comparison, encoded-reference, mass-enumeration, and HTTP-method replay evidence;
- advances the source-note cluster ledger from 341 pending notes in 17 clusters to 323 pending notes in 16 clusters.

## v9.77 — Mines the active source-note cluster `source-note-cluster-web-upload-file-inclusion-001` for `web-upload-file-inclusion-expansion` from the complete private review-packet windows. The build keeps the output public-safe, extracts reusable operator mechanics, enriches the existing upload/inclusion proof-chain card, advances the cluster queue instead of resuming blind pending-note batches, and makes the Product Hardening Dashboard show that cluster progress directly

- Adds `data/product-hardening/web-upload-inclusion-cluster-v9.77.js` as the public-safe product integration for this cluster.
- Enriches the existing `web-upload-inclusion-proof-chain` card instead of creating a duplicate primary card.
- Adds field-note guidance for file-handling impact ladders, file-read versus execution boundaries, canary and negative-control use, report evidence wording, and cluster-window split rationale.
- Adds analyzer rules that recognize upload acceptance, serving behavior, inclusion transforms, fuzzing deltas, control pairs, and execution claims as separate Evidence facts.
- Records completion metadata for the active cluster queue item and advances the source-note cluster ledger from 381 pending notes in 18 clusters to 341 pending notes in 17 clusters.
- Updates the Product Hardening Dashboard so cluster-review progress, the last mined cluster, the next cluster, and the no-blind-batches handoff are first-class status instead of being hidden behind old-rubric or first-pass note counts.
- Keeps adjacent XSS, credential, cracking, and SQLMap neighbor notes out of the upload/inclusion card instead of forcing packet-window neighbors into the wrong product surface.
- Registers v9.77 in `data/current-release.js`.
- Adds `tests/run-v9.77-tests.js` and updates source-cluster validation for the post-v9.77 ledger state.

## v9.76 — Repairs the Product Build Next handoff after v9.75 so the generated README and dashboard queue follow the active source-note cluster ledger instead of falling back to stale blind old-rubric batch language

- Makes the Build Next queue hygiene owner aware of the v9.75 source-note cluster ledger.
- Promotes `source-note-cluster-web-upload-file-inclusion-001` as the concrete next notes item when the cluster ledger is complete.
- Keeps the note disposition burn-down gate active while routing the next work through whole-cluster mining.
- Updates generated Product Build Next rendering so cluster-review batches use `targetCount`, `sourceSelector`, and whole-cluster acceptance text.
- Adds a v9.76 regression test that fails if Product Build Next regresses to blind old-rubric or pending slices after clustering.

## v9.75 — Completes the global source-note clustering pass requested after v9.74. Instead of continuing with blind 20-note pending batches, the remaining pending source-note work is now organized into cluster review queue items

- Updates `data/product-hardening/source-note-clusters-current.js` from a seeded handoff into the active global cluster ledger.
- Adds `data/product-hardening/global-source-note-clustering-v9.75.js`.
- Adds `tools/validate-source-note-clusters.js`.
- Adds `tests/run-v9.75-tests.js`.
- Updates `docs/SOURCE-NOTE-CLUSTERING.md`.
- Updates README Product Build Next from the global clustering pass to the first cluster-driven review item.

## v9.70 — Continues the notes-first Product Build Next queue by completing the second full 20-note old-rubric reviewed source re-mining batch

- Added `data/product-hardening/client-session-remine-batch-v9.70.js`.
- Re-read the selected path-transport, XSS, browser-side, session, CSRF, and client-cleanup notes from the complete private review-packet route.
- Published public-safe field notes for:
  - browser/client findings as staged session-impact proof chains;
  - reflected, stored, and DOM execution context boundaries;
  - cookie, storage, CSRF, origin, and authenticated state-change boundaries;
  - exact request transport and path-normalization proof;
  - client-side cleanup and reporting boundaries.
- Added the `web-client-session-proof-chain` card so the re-mined value appears as a normal operator-facing card rather than as loose note metadata or a corrective overlay.
- Added the conservative `client-session-evidence-analyzer` for pasted Evidence that mentions browser execution signals, cookies, storage, CSRF/origin controls, server acceptance, browser blocking controls, or cleanup needs.
- Advanced full-spectrum source re-mining from 87/135 to 107/135 reviewed notes, leaving 28 old-rubric-only reviewed notes before fresh pending-note disposition work can become next.
- Updated the queue handoff so the next generated batch advances to `notes-batch-old-rubric-reviewed-remine-003`.

## v9.69 — Continues the notes-first Product Build Next queue by completing the first full 20-note old-rubric reviewed source re-mining batch

- Added `data/product-hardening/web-upload-inclusion-remine-batch-v9.69.js`.
- Re-read the selected web upload, file inclusion, web shell, and temporary transfer notes from the complete private review-packet route.
- Published public-safe field notes for:
  - staged upload/inclusion proof chains;
  - upload serving and interpretation boundaries;
  - file-inclusion source and transform boundaries;
  - temporary transfer endpoint scope and cleanup.
- Added the `web-upload-inclusion-proof-chain` card so the re-mined value appears in the normal operator path instead of remaining as loose note metadata.
- Added the conservative `upload-inclusion-evidence-analyzer` for pasted Evidence that mentions upload acceptance, serving behavior, file-inclusion transforms, fuzzer signals, execution claims, or cleanup needs.
- Advanced full-spectrum source re-mining from 67/135 to 87/135 reviewed notes, leaving 48 old-rubric-only reviewed notes before the fresh pending-note disposition work can become next.
- Updated Build Next queue hygiene so the next generated batch advances to `notes-batch-old-rubric-reviewed-remine-002` instead of repeatedly showing batch 1.

## v9.68 — Is a corrective card-disposition release for the recent note-derived card work

- Added `data/product-hardening/note-card-disposition-reconciliation-v9.68.js`.
  - Keeps only distinct operator actions as primary cards.
  - Demotes supporting proof-chain fragments into their proper parent cards.
  - Removes the visible v9.67 action-first patch panel from the current release path.
  - Rebinds supporting field notes to the retained parent cards where runtime data is available.
  - Canonicalizes old direct card routes to the retained parent cards instead of showing duplicate conceptual cards.
- Removed `data/product-hardening/action-first-card-cleanup-stabilize-v9.67.js` from the current-release extension list.
  - The historical file remains in the repository as release history.
  - The current product no longer loads the panel injector.
- Added `tools/validate-note-card-disposition-reconciliation.js`.
  - Fails if the current release re-loads the visible v9.67 patch-panel stabilizer.
  - Requires kept-vs-demoted card disposition to be explicit.
  - Requires every demoted card to merge into a retained primary card.
- Updated current validators and browser smoke.
  - Primary path-visible note-derived cards are validated as normal Obol cards.
  - Demoted card URLs are treated as aliases to their retained parent cards.
  - Browser smoke fails if the old action-first patch panel appears again.
- Updated docs so future notes work follows this order:
  - enrich an existing Orange-map card first;
  - create a new card only for a distinct operator action;
  - never ship a visible corrective overlay as the final UI.

## v9.67 — Is a slop cleanup build for the recent note-derived cards

- Added `data/product-hardening/action-first-card-cleanup-v9.67.js`.
  - Audits the recent note-derived card set.
  - Overlays each card with an action-first operator plan.
  - Adds terminal commands or concrete GUI workflow steps.
  - Adds paste-back evidence, decision guidance, and next-step movement.
  - Marks field notes as supporting context instead of the primary action.
- Added `tools/validate-action-first-card-cleanup.js`.
  - Fails the cleanup if any recent note-derived card lacks an operator goal, commands or GUI steps, evidence to paste back, decision guidance, or next-step guidance.
- Added `tests/playwright-action-first-card-ui.js`.
  - Opens the same live-style card routes a user would open.
  - Fails if the page lacks the v9.67 action-first panel.
- Added `docs/NOTE-MINING-SLOP-CLEANUP.md`.
  - Documents the rule that source notes should usually enrich existing Orange-map cards and should become new cards only when they add distinct operator actions.

## v9.66 — Is a product-correction build for recent note-derived cards

- Added `data/product-hardening/actionable-card-contract-v9.66.js`.
  - Overlays note-derived cards with terminal commands or concrete GUI workflow steps.
  - Adds expected evidence to paste back into Obol.
  - Adds failure modes so a stuck operator can interpret bad or ambiguous output.
  - Adds next-step guidance so the card moves the path forward instead of becoming a conceptual dead end.
- Added `data/product-hardening/actionable-card-contract-dashboard-settle-v9.66.js`.
  - Re-applies the actionability overlay before dashboard rendering when load order is slow.
- Added `data/product-hardening/actionable-card-contract-queue-note-v9.66.js`.
  - Leaves a Product Build Next note explaining that future note-mined cards must be practical operator cards, not conceptual buckets.
- Added `tools/validate-actionable-next-step-cards.js`.
  - Fails path-visible note-derived cards that lack commands or concrete GUI steps.
  - Requires expected evidence, failure modes, and next-step guidance.
- Added `docs/ACTIONABLE-CARD-CONTRACT.md` and `docs/NOTE-MINING-ACTIONABILITY.md`.
  - Documents that a source note does not automatically become a card.
  - Directs future agents to enrich existing Orange-map cards first.
  - Keeps purely conceptual lessons in field notes unless they become real operator actions.

## v9.65 — Continues the notes-first Product Build Next queue after the v9.64 card-route repair. This build re-mines the next selected old-rubric note into public-safe web-fuzzer workflow behavior without copying private lab hosts, ports, discovered paths, answer strings, screenshots, or exact solution chains

- Added `data/product-hardening/burp-intruder-remining-v9.65.js`.
  - Adds public-safe Field Notes for payload positions, payload processing, response-delta triage, and proxy-integrated fuzzer scope/rate tradeoffs.
  - Adds the conservative `web-fuzzer-output-analyzer` for pasted Evidence.
  - Adds real live cards with path-engine shape:
    - `#/card/burp-intruder-fuzzing-workflow`
    - `#/card/fuzzer-payload-position-review`
    - `#/card/fuzzer-result-delta-review`
- Added `data/product-hardening/burp-intruder-route-guard-v9.65.js` so direct card routes recover from load-order races instead of showing `Unknown card`.
- Added `tests/run-v9.65-tests.js`.
  - Validates source confidence, 16-dimension audit coverage, public notes, live card shape, analyzer behavior, redaction, Evidence activity, queue/progress updates, and private-boundary safety.
- Extended `tests/playwright-note-card-routes.js` to open the v9.65 card routes in a browser.
- Extended route and path-placement validators so the v9.65 cards are required to be both clickable and reachable through Evidence/Next Steps logic.

## v9.64 — The next selected note in `notes-batch-old-rubric-reviewed-remine-001` is the Pass-the-Hash note from the first HTB review packet

- `note-pth-is-protocol-scoped-auth-material`
- `note-pth-success-is-host-and-privilege-scoped`
- `note-pth-remote-exec-leaves-artifacts`
- `note-pth-local-admin-token-filtering-check`

## v9.63 — And v9.62 added useful source re-mining output, but the new card IDs used by those releases were not registered as normal live cards. Opening routes such as `#/card/web-proxy-transform-proof-chain` therefore produced `Unknown card`

- `credential-dump-proof-chain`
- `web-proxy-transform-proof-chain`
- `web-client-controls`
- `encoded-parameter-review`
- `tool-generated-http-review`

## v9.62 — - Continued the generated `notes-batch-old-rubric-reviewed-remine-001` work with the next selected old-rubric reviewed source note after v9.61

- Continued the generated `notes-batch-old-rubric-reviewed-remine-001` work with the next selected old-rubric reviewed source note after v9.61.
- Re-mined the web-proxy skills-assessment source from the complete private review-packet route instead of relying on the old public rationale.
- Added `data/product-hardening/web-proxy-transform-remining-v9.62.js` as a live Product Hardening extension.
- Added three public-safe field notes for client-side control boundaries, reversible transform order, and generated HTTP capture before tool debugging.
- Added a conservative pasted-output analyzer for browser/proxy/request-mutation evidence.
- Updated progress without closing `notes-mechanic-backfill`; this is the second selected note of the generated 20-note batch, not completion of the full gate.

## v9.61 — - Began the generated `notes-batch-old-rubric-reviewed-remine-001` work with the first selected old-rubric reviewed source note

- Began the generated `notes-batch-old-rubric-reviewed-remine-001` work with the first selected old-rubric reviewed source note.
- Re-mined the LSASS/offline credential-extraction source from the complete private review-packet route instead of the old public summary.
- Added `data/product-hardening/credential-dump-remining-v9.61.js` as a live Product Hardening extension.
- Added three public-safe field notes for credential-dump artifact lineage, offline parser output classification, and hash-crack validation boundaries.
- Added a conservative pasted-output analyzer for LSASS dump, offline parser, NT material, hash-crack, and scoped-authentication signals.
- Updated progress without closing `notes-mechanic-backfill`; this is one selected note of the generated 20-note batch, not completion of the full gate.

## v9.60 — - Completed the next Product Build Next item after v9.59: `notes-remine-private-only-superseded`

- Completed the next Product Build Next item after v9.59: `notes-remine-private-only-superseded`.
- Re-mined old `private-reference-only` and `superseded` note dispositions as a source-boundary class instead of leaving them as discarded private references.
- Added `data/product-hardening/private-only-superseded-remining-v9.60.js` to publish public-safe extraction mechanics without copying raw private note bodies, flags, exact targets, payload catalogs, screenshots, or walkthrough chains.
- Added four public-safe field-note mechanics for private-source redaction, recipe-catalog conversion, lab-outcome proof templates, and volatile tool-reference criteria.
- Marked `notes-remine-private-only-superseded` complete only through live queue/progress integration with a `private-only-superseded-remine` packet review marker.

## v9.58 — - Re-mined the reviewed credentials/auth source lane into public-safe live guidance cards for provenance, protocol scope, challenge-response proof boundaries, validation safety, and protected-secret lineage

- Re-mined the reviewed credentials/auth source lane into public-safe live guidance cards for provenance, protocol scope, challenge-response proof boundaries, validation safety, and protected-secret lineage.
- Added `data/product-hardening/credentials-auth-remining-v9.58.js` with per-source findings, 16-dimension re-mining audit rows, field-note outputs, queued product gaps, and live integration hooks.
- Updated the current release identity to `v9.58` and advertised the credentials/auth Product Hardening extension so the release can load the new integration without creating another historical runtime layer.
- Added `tests/run-v9.58-tests.js` to prove the release identity, extension loader, source metadata, live card IDs, per-dimension audit coverage, queue mutation, note helper behavior, progress update, and obvious unsafe-public-material guardrails.
- Queued follow-up UI/analyzer work for credential validation safety and authentication-material scope recognition rather than burying those findings as loose PR-body gap text.

## v9.57 — Completes the `notes-remine-xss-session` lane from the README build queue with a public-safe, live-integrated XSS/session re-mining artifact. The work re-mines XSS and session-impact notes from the private source-review packet route without copying raw course text, payload strings, target values, flags, credentials, cookies, listener recipes, or reusable exploit mechanics into the public repository

- Re-mined the reviewed XSS/session source lane into three public-safe, live-integrated path/card notes for delivery context, browser execution proof, and session-impact boundaries.
- Wired the v9.57 artifact into the Product Hardening runtime before notes-impact/dashboard projection so the new cards update live note surfaces and progress data.
- Marked `notes-remine-xss-session` complete only after live integration existed and recorded the source-confidence metadata from the private review-packet route.
- Added the proof-mode selector and cleanup-reminder follow-ups as queued Product Build Next `ui-ux` items instead of leaving them as loose audit gap IDs.
- Added the Live Integration Done Gate, PR template requirements, and validator coverage to stop future Product Build Next work from shipping as orphaned artifacts.
- `platocres/obol-source-notes@agent/review-packets`
- `data/review-packets/manifest.json`
- `data/review-packets/htb-penetration-tester-03.json`
- `data/review-packets/htb-penetration-tester-04.json`
- `schemaVersion: 2`
- `reviewTextPolicy: complete_cleaned_text`
- `noteCount: 556`
- `uniqueNoteCount: 556`
- `packetCount: 29`
- `truncatedNoteCount: 0`
- `windowMarkerCount: 0`
- `reviewTextChars: 8725188`
- `resourceCount: 1326`

## v9.56 — Product-hardening release for note re-mining dashboard schema tracking and dashboard readability

- old-rubric reviewed count;
- full-spectrum re-mined count;
- old-rubric-only remaining count;
- negative finding outcome counts;
- invalid or missing negative-proof red flags;
- extraction dimensions for Path bindings, tool cards, GUI controls, scripts, one-liners, command templates, terminal analyzers, Evidence expectations, path movement, lesson boxes, examples, troubleshooting, cleanup, report guidance, product mechanics, product gaps, and additive Orange-baseline preservation.
- a wider dashboard shell that uses available desktop width instead of trapping everything in a narrow centered column;
- a compact top summary for release, product-hardening progress, source re-mining, red flags, first-pass pending notes, mechanic conversion, and queued work;
- a Build Next section that stays near the top and remains synchronized with the README;
- drill-down sections for re-mining schema details, queue/package details, source-note impact, runtime/QA appendix data, and full ledgers;
- long tables moved into contained scroll areas instead of making the whole dashboard feel endless.

## v9.55 — Product-hardening release for the Notes Impact and Source Re-mining package

- `ad-sharphound-collection-review`
- `ad-bloodhound-edge-proof-review`
- `ad-domain-share-secret-triage`
- `ad-kerberoast-proof-boundary`
- `pivot-reachability-map-review`
- `pivot-socks-proof-chain`
- `pivot-traffic-confirmation`
- `winrm-lateral-validation`
- SharpHound collection is a scoped graph snapshot, not proof that a BloodHound path is exploitable.
- BloodHound edges become proof tasks with a required identity, right, target object, and cleanup boundary.
- Domain shares produce access, file, and candidate-secret facts separately.
- Kerberoasting separates SPN discovery, TGS capture, offline cracking, and validated service access.
- Pivoting separates route discovery, tunnel-up state, scan-through behavior, traffic confirmation, and authenticated internal service use.
- WinRM validation separates credential validity from useful lateral Windows control.
- No fake card fallback rendering.
- No developer-facing route explanation boxes.
- No source-mining provenance shown as operator card copy.
- Every command has a useful explanation, not a generic authorization warning.
- Card-originated evidence remains card-scoped through Intake.
- OS-scoped local privilege cards remain separated from cross-platform AD and pivot cards.

## v9.54 — Begins Linux privilege-escalation source re-mining from the complete sequential private-note packets

- Added the first Linux privilege-escalation re-mining batch to the current note-progress projection without claiming raw Git LFS access from this agent runtime.
- Re-read four already-reviewed Linux privilege-escalation sources from the complete packet fallback and published per-note, per-dimension audit rows for service-footprint review, user-trail secret hunting, cron execution chains, and sudo authorization.
- Queued concrete public-safe product gaps for Linux terminal-output analyzers: process/traffic secret observations, user-trail secret extraction, cron proof-chain reconstruction, sudo `-l` interpretation, Hydra credential-validation builder support, and credential-pattern wordlist generation.
- Preserved existing Linux Field Notes and Orange-derived path bindings additively rather than replacing the v9.50 Linux packet or publishing private recipe material.
- Added `tests/run-v9.54-tests.js` to assert the expanded 19-row re-mining projection, complete-packet lineage, allowed negative-proof outcomes, and the permanent audit validator.

## v9.53 — Fixes the private source-note handoff so future agents stop relying on incomplete themed review artifacts

- Added complete private source-packet metrics through `data/product-hardening/source-review-packets-current.js`.
- Added a Product Hardening Dashboard card for complete private review packet coverage.
- Updated the README generated Product Build Next block to show the complete packet source, 556/556 note coverage, zero truncation, and raw ENEX proof metrics.
- Added `docs/RAW-NOTES-LFS.md` to document direct Git LFS verification, the complete sequential packet fallback, and why the old themed artifact is not source of truth.
- Updated `docs/AGENT-WORKFLOW.md` so agents know to use raw ENEX when possible and complete sequential packets when connector/runtime limits block direct LFS access.
- Added `.github/workflows/sync-release-artifacts.yml` so release branches can regenerate README, `index.html`, and `assets/obol-app-current.js` from the release authority instead of hand-editing generated runtime output.
- Added regression coverage in `tests/run-v9.53-tests.js` and hardened the v9.52 source-handoff checks.

## v9.52 — Windows privilege-escalation source re-mining and release-identity synchronization

- Began actual full-spectrum source re-mining: re-read all 15 already-reviewed Windows privilege-escalation notes from the original private ENEX sources (not the public Field Note or prior rationale) and published per-note, per-dimension audit rows in `data/product-hardening/note-progress-current.js` (`remining.auditRows`). Outcomes: 7 added, 114 covered, 16 queued, 17 private-only, 86 not-applicable, computed rather than hand-maintained.
- Added the operator-facing Field Note `note-windows-service-trigger-tool-proof` on the Windows local-privilege path node: a writable service binary, unquoted service path, modifiable scheduled task, or hijackable DLL location is only a lead until trigger capability (restart rights, or auto-start plus a reboot privilege) and ACL intent are proven, and automated helpers (PowerUp, WinPEAS, Seatbelt) are leads that can be AV-blocked or false-negative. Wired additively to the existing Orange path; the frozen v9.35 Windows packet and its milestone are unchanged.
- Filed the analyzer and operator-logging-exposure product gaps surfaced by re-mining as queued outcomes; the Product Hardening Dashboard now renders real re-mining counts instead of the placeholder zero copy.
- Hardened the release-identity demotion contract that v9.51 shipped stale: demoted the v9.50 test's hard-coded README token and the v9.51 test's README/`index.html`/`data/current-release.js` literals to a version-agnostic synchronization invariant, regenerated the stale `assets/obol-app-current.js`, and extended `tools/validate-historical-tests.js` to also reject hard-coded `index.html` release-shell tokens in historical suites.
- Decluttered the README into an action-first handoff and moved the detailed build loop, including raw-source re-mining mechanics (`git lfs pull` of the private ENEX), into the new `docs/AGENT-WORKFLOW.md`. README and dashboard stay sourced from the same queue data.

## v9.51 — Source re-mining handoff, dashboard, and negative-proof enforcement

- Turned source re-mining into the visible queue and dashboard priority: already-reviewed notes must be re-mined from the original private sources under the full-spectrum rubric before fresh pending-note packets. Documented the rubric in `docs/NOTE-MINING-RUBRIC.md`.
- Required auditable negative-finding proof for every extraction dimension (`added`, `covered`, `queued`, `private-only`, `not-applicable`, or `blocked`) and published the re-mining schema, dashboard metrics, and red flags. Added `tools/validate-note-remining-audits.js` (permitting an empty audit list until re-mining resumed).
- Tiered CI so `[full-regression]` is the explicit historical/deep-browser trigger, split the fast browser route smoke from the deep browser proof, and locked release-identity synchronization in the v9.51 tests.

## v9.50 — Linux privilege-escalation notes packet

- Completed the Linux privilege-escalation subject packet with eight curated private-source candidates: seven modeled into public-safe guidance and one exploit-specific walkthrough retained as private-reference-only.
- Advanced the current notes ledger to 135/556 reviewed: 102 modeled, 28 private-reference-only, 5 superseded, 0 rejected, and 421 pending.
- Added normalized guidance for Linux privilege-enumeration triage, privileged process/service observation, user-trail secret hunting, cron execution preconditions, sudo authorization, SUID/capability proof boundaries, and kernel-exploit compatibility/stability proof.
- Required an explicit guidance-only decision for every newly modeled source. The reviewed packet exposed no missing Tool Builder, Path primitive, Evidence parser, report-generator, or workflow mechanic that justified redundant code-level behavior.
- Extended current Field Note delivery so Card, Tool, and Path routes load the current Linux packet projection, and added item-specific v9.50 proof plus future-safe preservation of the frozen v9.35 Windows packet milestone.
- Closed `notes-packet-linux-privesc` while leaving the 556-note umbrella, the pre-v9.29 mechanics backfill, and AD/pivoting packet live. Raw course prose, targets, flags, credentials, screenshots, and exploit recipes remain outside public Obol.

## v9.49 — Next Steps style delivery repair and design-token integrity

- Fixed the Next Steps formatting regression left by runtime layer consolidation. Inlining `assets/operator-route-current.js` into the startup application owner made it publish `OBOL_OPERATOR_ROUTES` at startup, so `ensureOperatorRoutes88()` short-circuited before it could inject `assets/operator-route-current.css`; the operator hero, metric tiles, mode bar, and recommendation cards rendered completely unstyled.
- Made current route owners deliver their own presentation: `operator-route-current.js` now injects its companion stylesheet itself (idempotent, Node-safe), the way the current dashboard route owner already injects `assets/product-hardening-dashboard.css`, so inlining/flattening can never orphan it again. `assets/obol-app-current.js` is regenerated from source through `tools/sync-app-current.js`.
- Defined the role tokens the flattened cascade references but never defined — `--muted` (~140 uses), `--card`, `--surface`, `--hover`, `--bad`, `--ok`, `--green`, `--gold`, `--warn` — once in the always-loaded current-owner sheet `assets/responsive-current.css`, each mapped to an existing base token. Muted captions and role-colored surfaces regain their intended hierarchy app-wide. The frozen historical cascade and its equivalence proof are untouched.
- Ran a consistency pass toward the North Star dashboard: the operator route surfaces adopt the dashboard's card language (panel-gradient backgrounds, rounded corners, soft shadow) and its green accent replaces one-off cyan for primary/active states, so Next Steps reads as part of the same system as Home, Report, and the dashboard at 1920×1080.
- Added `tools/validate-current-owner-styles.js`, a deterministic anti-drift guard wired into scope-check and release preflight: it proves every current route owner injects its own companion stylesheet, every design token used without a fallback in the delivered stylesheet set is defined, and every class the current operator route emits has a backing rule. `tests/run-v9.49-tests.js` includes the anti-regression proof that the guard rejects the pre-fix state.
- Recorded the work in the queue additively: closed `ux-current-owner-style-delivery` (UI / UX repair → 10/11) and `qa-current-owner-style-guard` (Testing / visual QA → 8/12) with item-specific test contracts; README Product Build Next and the Product Hardening Dashboard re-synced from the same queue data. Added no versioned runtime layer.

## v9.48 — Evidence overlay chain restoration

- Closed `cc-evidence-chain-restore`: the conservative Evidence that `intake-v7.7`/`v7.8`/`v7.9`/`v8.2` were written to add — no-credentials poisoning/coercion beyond v7.6, relay-SOCKS, certificate movement, Windows local-exploit conditions, WebDAV coercion, and offline cracking — again reaches production.
- Root cause: those overlays hooked a predecessor `OBOL_INTAKE_*` global that only ever published helper functions, never `analyzeTerminal`, so each returned at its guard and broke the next link; they never ran in any load order the runtime produces.
- Re-homed the same overlay logic verbatim onto the live `OBOL_INTAKE_V21` decorator chain through a stable current owner `assets/intake-evidence-restore.js`, loaded route-lazily after the Evidence bundle so it wraps `analyzeTerminal` last. Proof boundaries and conservative interpretation are unchanged.
- Kept the four historical overlays retired in the frozen ledger: the v9.44 retirement stays observably inert and its reachability/differential proof is preserved. The frozen 327-fragment ledger and the 37-fragment Evidence bundle are unchanged.
- Extended `tools/validate-evidence-current-equivalence.js` with a restoration proof — reachability that the current owner decorates `analyzeTerminal` (the step the broken subchain skipped) while the dead `intake-v7.7.js` still cannot, plus a per-family differential — and added `tests/run-v9.48-tests.js` as the regression that would have caught the broken link.
- Moved Critical correctness to 5/5 and overall Product Hardening additively; added the `cc-evidence-chain-restore` item test contract.

## v9.46 — Single-paint current application boot

- Added a current-route boot visibility barrier so historical application compatibility can initialize without replaying old Home/UI generations to the operator.
- Added a throttled Chromium first-visible-paint regression that delays the current workflow and requires every visible Home frame to be the current user-first interface.
- Extended current-release synchronization to the static browser title/tagline.
- Retroactively clarified v9.43 application flattening as request/stale-overlay consolidation and added `runtime-app-single-paint` as a separate completed metric, moving Architecture/runtime to 18/21 and overall Product Hardening to 207/650 without rewriting prior completion history.
- Preserved truthful runtime fragment accounting: the app area remains 43 exact-owned compatibility fragments; v9.46 changes visibility ownership, not semantic fragment retirement.

# Obol Changelog

## v9.47 — Semantic application ownership

- Replaced the exact-concatenation application runtime with a generated semantic current application/router owner while preserving all 43 surviving historical fragments as the frozen semantic/equivalence ledger.
- Retired autonomous historical application timers, intervals, hashchange listeners, MutationObservers, and delayed route repaint scheduling; current workflow/operator renderers now commit last behind one current navigation owner.
- Added long-horizon Chromium proof spanning the former 5.2-second historical timer window plus forced reroutes and Home → Next Steps → Home navigation, and forbade direct versioned application requests.
- Preserved v9.43 request/stale-overlay retirement and v9.46 first-paint protection as separate completed historical milestones; added `runtime-app-semantic-retirement` so Architecture/runtime and overall Product Hardening metrics advance additively instead of being rewritten.

This file is the release-history source for Obol. Future build work should review this changelog together with the current README before changing architecture or methodology.

The README is intentionally reserved for current product purpose, permanent operating and build requirements, current architecture/state, and forward priorities. Release narratives and historical implementation summaries belong here, not in README.

## v9.45 — Stylesheet ownership area flattening

- Replaced the live 69-fragment exact CSS concatenation with a generated semantic cascade snapshot in `assets/obol-current.css` while retaining every historical stylesheet file and the frozen v9.5 order fingerprint as the compatibility ledger.
- Added `tools/style-cascade-current.js`; the conservative reducer removes only declarations superseded under exact selector/property/grouping-context identity, taking 1,817 source style rules / 5,524 declarations to 1,809 rules / 5,496 declarations while preserving important precedence, fallback-sensitive chains, unknown at-rules, and non-identical contexts.
- Added `tools/validate-style-current-equivalence.js` for deterministic regeneration plus mutation-tested cascade safety boundaries, and `tools/validate-style-visual-equivalence.js` for an independent Chromium comparison against the exact historical cascade across seven routes at desktop and mobile widths.
- Currentized the v9.40 historical stylesheet assertion so it keeps protecting the frozen ledger and one-request owner without forcing exact-fragment delivery shape back into the current runtime.
- Closed `runtime-style-flattening`, completing the Runtime Layer Consolidation package and advancing Product Build Next to `cc-evidence-chain-restore`.

## v9.44 — Evidence parsing ownership area flattening

- Retired four Intake parser overlays (`assets/intake-v7.7.js`, `assets/intake-v7.8.js`, `assets/intake-v7.9.js`, `assets/intake-v8.2.js`) from the live runtime, shrinking the route-lazy Evidence ownership area from 41 exact-owned fragments to 37 while keeping every retired file in the frozen historical ledger. `assets/obol-evidence-current.js` drops from ~355 KB to ~339 KB, so the first Evidence/Artifacts open parses ~16 KB less JavaScript.
- These four were not superseded, they were dead code: `intake-v7.7.js` hooks `OBOL_INTAKE_V76`, which only ever publishes helpers, so its `!T.analyzeTerminal` guard returns and the chain breaks for the three overlays after it. They never ran in production in any load order the runtime produces.
- Added `tools/validate-evidence-current-equivalence.js`, which proves the retirement two independent ways: a reachability pass executes the whole frozen Intake chain and confirms the four retired overlays never publish their global or touch `OBOL_INTAKE_V21.analyzeTerminal`; a differential pass builds the Evidence runtime from the frozen and surviving fragment sets and requires byte-identical globals and `analyzeTerminal` output over a fixed operator corpus.
- Filed `cc-evidence-chain-restore` (critical correctness): the Evidence the four overlays were written to add — no-credentials poisoning/coercion beyond v7.6, relay-SOCKS, WebDAV coercion, Windows local-exploit, and offline-cracking Evidence — never reached production because of the broken link, so it is tracked as its own defect rather than silently written off.
- Exported the equivalence helpers (`chainReachability`, `loadEvidenceRuntime`) so `tests/run-v9.44-tests.js` can drive the proof with mutated inputs — an unreachable-marked overlay and a dropped reachable overlay — and require it to reveal the difference, without editing a tracked file the concurrent historical-contract runner would observe.
- Updated the runtime manifest, consolidation projection, dashboard matrix, and README so the retired ledger reports 55 fragments and the Evidence owner reports its post-retirement fragment count.

## v9.43 — Application ownership area flattening

- Retired the 21 superseded release-wave application overlays (`assets/app-v6.7.js` … `assets/app-v8.7.js`) from live startup, shrinking the application ownership area from 64 exact-owned fragments to 43 while keeping every retired file in the frozen historical ledger. `assets/obol-app-current.js` drops from 412 KB to 361 KB, so every operator page load parses ~50 KB less JavaScript.
- Added `tools/validate-app-current-equivalence.js`, which proves each retired overlay is structurally inert under the shipped runtime: its entire contribution is gated on a stale `C.VERSION`, and its only top-level effects are a pass-through `route` wrapper plus schedules of that permanently short-circuited decorator.
- Added `tools/validate-app-dom-equivalence.js`, a browser-level proof that every operator route renders byte-identical DOM with and without the retired overlays; the browser smoke workflow now runs it alongside the request-budget smoke.
- Updated the runtime manifest, consolidation projection, dashboard, and README so the retired ledger reports 51 fragments and the application owner reports its post-retirement fragment count.
- Exported the per-overlay proof as a pure `proveOverlayInert(rel, source, liveVersion)` so `tests/run-v9.43-tests.js` can mutate a retired overlay in memory and require the shipped proof to reject it, without editing a tracked file that the concurrent historical-contract runner would observe.

## v9.42 — Core ownership flattening

- Replaced the live core owner’s 69-fragment ordered execution chain with a generated semantic delta replay in `assets/obol-core-current.js`, while preserving the historical files as the frozen equivalence ledger.
- Added `tools/sync-core-current.js`, which keeps the shared v2 core base scope intact and replays each surviving release delta in an isolated lexical block instead of embedding exact runtime-fragment concatenation markers.
- Added `tools/validate-core-current-equivalence.js`, proving the generated owner exposes the same `OBOL_CORE` roots, `C.*` surface, helper globals, migration helpers, workspace migration/coercion, Evidence application, recommendation ranking, report readiness, project-model, search, network, sanitized-export, and Nmap-builder behavior as the historical chain.
- Updated runtime manifest/projection metadata so browser and Node current runtime paths load the semantic core owner directly, while keeping the 69 historical core fragments available only as the frozen regression ledger.
- Updated the Product Hardening Dashboard, README Product Build Next block, runtime docs, and queue contracts to report 172 semantically flattened fragments, 125 still exact-owned fragments, and 30 retired Dashboard fragments.
- Closed `runtime-core-flattening` with an item-specific proof contract and v9.42 regression suite, while leaving application, Evidence, and stylesheet flattening queued as separate ownership-area passes.
- Preserved the v8.8 workspace/runtime schema identity, browser-local and human-run constraints, conservative Evidence/report proof semantics, request budget, frozen v9.5 ledger, and exact-head release validation model.

## v9.41 — Domain ownership flattening

- Replaced the live domain owner’s 103-fragment ordered execution chain with an authored semantic graph snapshot in `assets/obol-domain-current.js`, while preserving the historical files as the frozen equivalence ledger.
- Added `tools/sync-domain-current.js`, which deterministically executes the v9.40 domain ledger at build time and emits the current owner graph with shared identity, cycles, RegExp metadata, mutability flags, and six authored function implementations.
- Added `tools/validate-domain-current-equivalence.js`, proving the semantic owner exposes the same `OBOL_*` root order, complete enumerable graph, object identity/cycle topology, RegExp metadata, mutability flags, and function signatures as the historical chain, then exercising the authored functions against live and synthetic fixtures.
- Updated runtime ownership metadata from a single exact-concatenation schema to per-area owner strategies: domain is `semantic-snapshot`; core, app, Evidence parsing, Nmap, report overlays, and tool reference data remain exact ordered concatenations.
- Updated the Product Hardening Dashboard, runtime consolidation projection, README Product Build Next block, and runtime docs to report 103 semantically flattened historical fragments, 194 still exact-owned fragments, and 30 retired Dashboard fragments.
- Extended the Tool Builder inventory with explicit modeled dispositions for runnable identities surfaced by the semantic domain graph, keeping the permanent inventory validator green without adding new builders in this release.
- Closed `runtime-domain-flattening` with an item-specific proof contract and v9.41 regression suite, while leaving core, application, Evidence, and stylesheet flattening queued as separate ownership-area passes.
- Preserved the v8.8 workspace/runtime schema identity, browser-local and human-run constraints, conservative Evidence/report proof semantics, request budget, frozen v9.5 ledger, and exact-head release validation model.

## v9.40 — Runtime layer consolidation

- Gave every historical runtime ownership area one stable, non-versioned owner that is the exact ordered concatenation of its fragments: `assets/obol-domain-current.js` (103), `assets/obol-core-current.js` (69), `assets/obol-app-current.js` (64), plus route-lazy owners for Evidence parsing (41), Nmap (3), report overlays (14), and tool reference data (3).
- Flattened `assets/obol-current.css` from a 69-deep `@import` chain into one cascade, so the stylesheet costs one request instead of seventy.
- Measured in Chromium against a served checkout: Home 321→19, Next Steps 329→27, Evidence 365→21, Report 335→20 JavaScript/CSS requests. Operator startup drops from 307 requests to 5.
- Added `tools/sync-runtime-bundles.js` (generator) and `tools/validate-runtime-bundles.js` (equivalence proof). The validator rules out the three hazards that make classic-script concatenation unsafe — strict-mode prologue leakage, automatic semicolon insertion across fragment boundaries, and lost parse isolation — proves each owner is nothing but generated banners around verbatim fragment bodies, and diffs the global surface produced by 173 fragment loads against 3 owner loads in isolated VM contexts.
- Nothing is minified, reordered, or rewritten. The frozen v9.5 fragment ledger, its order fingerprints, and every fragment file are untouched and remain the regression reference.
- Extended `tests/playwright-smoke.js` with per-route JavaScript/CSS request budgets and a hard failure when any historical fragment is fetched directly instead of through its consolidated owner. Confirmed the gate is real by running it against the pre-consolidation runtime, where every route fails.
- Added `data/runtime-consolidation-current.js` as the single projection for consolidation figures, read by both the Product Hardening Dashboard and the generated README Product Build Next block, with `tools/validate-runtime-consolidation-sync.js` failing when they disagree.
- Repaired two Product Hardening Dashboard layout defects: the at-a-glance strip was rendering inside `.ph-hero`'s fixed 240px first column, which wrapped every tile mid-word, and the hero score panel stretched to the full height of the taller track grid, leaving a large empty box.
- Retired the v9.7 `@import`-shape assertions in favor of the flattened-cascade contract. The protected behavior — one stable non-versioned stylesheet owner that is a pure generated projection of the frozen order and adds no rules of its own — is unchanged and still enforced.
- Product Build Next now leads with the Runtime Layer Consolidation package: one queued item per remaining ownership area (domain, core, application, Evidence parsing, stylesheet) for semantic flattening, which request consolidation does not do.
- Repaired the release-PR contract for releases that ship from an agent working branch. `tools/validate-release-pr.js` now accepts `claude/…`, `codex/…`, `agent/…`, and `hardening/…` heads alongside `release/obol-vX.Y`, and recognizes release intent from either an `Obol vX.Y` or a `Release vX.Y` title — so such releases are validated rather than skipped by title convention. Because a working branch carries no version to cross-check, its title's version must now match the release the repository ships. `tools/validate-open-pr-uniqueness.js` recognizes the same title shape so the one-open-release-PR rule still covers them.

## v9.39 — Faster regression gate and dashboard at-a-glance

- Parallelized `tools/run-historical-contracts.js`: the syntax-check phase and the full suite/validator set now run through a bounded worker pool of isolated processes. Identical coverage (every file syntax-checked, every `run-v*-tests.js` suite run), but the complete gate finishes far faster — measured ~64s vs the prior sequential run that had not finished at 120s. Safe because historical suites write only to unique `os.tmpdir` paths and the validators are read-only.
- Led the Product Hardening Dashboard with an at-a-glance summary strip (release, product-hardening percent, notes reviewed, mechanic conversion, guidance-only backlog) above the detailed ledgers.
- Surfaced the v9.36 notes conversion rubric in the dashboard's Notes Integration detail: mechanic conversion (the primary notes metric), the ratcheted guidance-only backlog, and script-bound guidance counts. README and dashboard continue to read the same queue and notes-impact data.
- Physical historical-layer retirement remains per-area lifecycle work tracked by the `architecture-runtime` items and the dashboard retirement matrix; this release adds no layer deletions, so no coverage is lost.

## v9.37 — Path three-mode rendering

- Completed `ux-path-three-mode`: Next Steps now renders Simplified, Checklist, and Live Map views from one normalized `C.nextStepsOverview34(...)` model.
- Added browser-local view-mode persistence plus SVG Live Map pan/zoom controls, pointer drag, wheel zoom, action links, and planned-work actions without adding a versioned runtime layer.
- Added `tools/validate-path-views.js`, wired it into current workflow validation, scope check, release preflight, and the v9.37 regression suite.

## v9.36 — Notes conversion rubric and script disposition

- Enforced the notes conversion rubric (`notes-conversion-rubric`): the notes-impact projection exposes a `rubric` over modeled notes (mechanic-backed, justified guidance-only, unjustified guidance-only, compliant, and `mechanicConversionPct`), and `tools/validate-notes-impact.js` ratchets the unjustified guidance-only backlog against a frozen ceiling so it can only shrink. Mechanic conversion, not review count, is the primary notes metric (current state: 1/95, backlog 43/43).
- Added the script-bound note disposition (`notes-script-category`): a first-class `script` kind now runs end to end across the note-integration atom kinds, the public field-notes contract, the notes-impact `script-guidance` impact type and count, and the field-notes UI validator.
- Encoded the corrective-plan queue (`docs/CORRECTIVE-PLAN.md`) into Product Build Next: conversion rubric, re-audit backfill, script category, Path three-mode, and a UI audit rubric; de-brittled the v9.31 queue-total and v6.6 README-size assertions.
- Established the release cadence rule: every build bumps `data/current-release.js`, adds a `docs/vX.Y.md` and `tests/run-vX.Y-tests.js`, records a CHANGELOG entry, and syncs the README.

## v9.35 — Windows privilege-escalation notes and README history ownership

- Completed the Windows privilege-escalation notes packet after substantive review of 32 private metadata candidates and 95 private full-text candidates, curating 16 reusable subject sources.
- Advanced the public-safe ledger to 127/556 reviewed: 95 modeled, 27 private-reference-only, 5 superseded, 0 rejected, and 429 pending.
- Added normalized guidance for Windows privilege-enumeration triage, access-token and integrity proof, privileged service/task/DLL execution preconditions, secret-hunting boundaries, and local-exploit risk/proof.
- Kept the packet guidance-only at the mechanics layer because the reviewed sources did not expose a missing command-builder, Path, Evidence parser, report-generator, or workflow primitive that justified new code-level behavior.
- Restored README to current-state handoff ownership, moved recent release narratives into CHANGELOG, and added a permanent README-history ownership validator to preflight and the historical contract runner.

## v9.34 — Dashboard freshness and self-update hardening

- Made Dashboard activation freshness-aware across current release, queue, work-package, notes-impact, renderer, and stylesheet owners.
- Added cache-busted current-owner reloads, generation isolation, standalone/embedded convergence, stale-global browser regression coverage, and a permanent Dashboard freshness validator.
- Preserved the stable current Dashboard owner instead of adding another versioned runtime layer.

## v9.33 — credentials and authentication notes packet

- Completed the credentials/authentication subject packet with 24 curated candidates: 2 previously terminal and 22 newly terminal.
- Advanced the cumulative notes ledger to 112 reviewed, 82 modeled, 25 private-reference-only, 5 superseded, and 444 pending.
- Added normalized guidance for credential material/protocol scope, hash classification, lockout-aware testing, protected secret containers, Basic-auth transport, Windows credential-source proof, reuse validation, and the NetNTLM/pass-the-hash distinction.
- Confirmed existing Credential Material and credential-mode mechanics covered the reviewed operational needs, so the packet added no redundant runtime or builder layer.

## v9.32 — XSS and session notes packet

- Completed the XSS/session subject packet with explicit browser-execution, delivery/trigger, session-impact, and remediation proof boundaries.
- Advanced the cumulative ledger to 90 reviewed, 63 modeled, 23 private-reference-only, 4 superseded, and 466 pending.
- Preserved raw private payload and walkthrough material outside the public repository while binding rewritten guidance to current Tool, Path, Evidence, and Report surfaces.

## v9.31 — operator route ownership and tool declutter

- Added a stable current operator-route owner for Path, Card, and Tools instead of adding another versioned app layer.
- Replaced the visible Path route stack with a compact current decision screen showing best next move, unlocks, queued intent, blockers, and ranked recommendations.
- Made current schema-driven builders the primary Card/Tools surface and collapsed raw historical command blocks behind one supporting-detail disclosure.
- Added Product Hardening queue/work-package entries and item-test contracts for operator route ownership, Next Step declutter, compact card tool presentation, and the focused UX regression.
- Preserved the v9.30 notes ledger state while keeping notes burn-down as the highest-priority live Product Build Next item.

## v9.30 — themed notes packet burn-down

- Replaced anonymous note-review waves with explicit subject packets under the 556-note disposition umbrella.
- Completed the web upload/file-inclusion packet, advancing the ledger to 76 reviewed and adding normalized proof, troubleshooting, cleanup, and remediation guidance.
- Added the first declared note-driven code-level product change: curl path preservation for traversal hypotheses where client normalization would otherwise alter the request.

## v7.6 — admin source-depth completion

- Atomized the pinned `admin.md` methodology family into twenty-five meaningful source-fidelity units spanning LSASS, SAM, LSA, DPAPI, token/session impersonation, RDP session transfer, user-profile discovery, KeePass credential recovery, and AD Connect synchronization-account recovery.
- Modeled twenty-four units end to end and preserved the pinned pre-July-2022 PPLdump route as an explicitly superseded historical source branch rather than presenting it as a preferred current workflow.
- Reused mature LSASS, credential-dumping, DPAPI, token-impersonation, and SeImpersonate owners while adding focused v7.6 owners for protected LSASS handling, logged-on/RDP session impersonation, AD CS-backed impersonation, user-profile discovery, KeePass recovery, and AD Connect MSOL credential recovery.
- Preserved strict separation between protection/configuration changes, dump and registry artifacts, DPAPI masterkeys, session inventory, plugin/trigger preparation, certificate/hash/password material, authenticated access, execution, administrator/SYSTEM context, DCSync capability, privilege, and cleanup.
- Advanced only `admin.misc`, the one `admin.md` parent still partial in the frozen v6.2 source-depth baseline. `admin.lsass`, `admin.sam`, `admin.lsa`, `admin.dpapi`, and `admin.impersonation` retain their historical canonical completion milestones while gaining complete atomic accounting.
- Raised canonical methodology from **117 implemented / 10 partial / 0 gaps / 0 stale** to **118 implemented / 9 partial / 0 gaps / 0 stale**, **93% fully implemented**, and **100% represented**.
- Expanded source inventory from **6/17** to **7/17** methodology files atomized, from **24/34** to **25/34** frozen partial baselines decomposed, and from **93/93** to **118/118** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **10** to **9** broad source-inventory/decomposition items, moving the active priority into `no_creds.md` with zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel76(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, retained the overview-first Dashboard owner, and added no no-op Dashboard metadata layer.
- Added v7.6 browser/runtime wiring, admin terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, future-safe v7.5 regression coverage, and a dedicated v7.6 regression suite under the exact-head release workflow.

## v7.5 — SCCM source-depth completion

- Atomized the pinned `sccm.md` methodology family into twenty-three meaningful source-fidelity units spanning reconnaissance, PXE/NAA routing, site-system relay, forced and automatic client push, distribution-point credential recovery, site-database takeover, MSSQL-server relay, policy-request credentials, local/client secret recovery, site-database credentials, administrative execution, cleanup, and SCCMHound post-exploitation mapping.
- Modeled all twenty-three units end to end, reusing mature SCCM reconnaissance, PXE, credential-recovery, takeover, execution, cleanup, and post-mapping owners where they already satisfy the operator contract.
- Added focused v7.5 owners for site-system relay, forced client push, automatic client push, MSSQL-server relay, policy-request credentials, and site-database credential recovery, with explicit Kali/Windows execution context, semantic controls, conservative Evidence profiles, cleanup obligations, Next Steps integration, and reporting contracts.
- Preserved strict separation between SCCM discovery, temporary DNS/SPN/device state, coercion, inbound authentication, relay success, machine-account hashes, SQL authentication, encrypted database values, decrypted credentials, authenticated service access, execution, administrator/SYSTEM context, privilege, and cleanup.
- Advanced only the six SCCM parents that remained partial in the frozen v6.2 source-depth baseline: `sccm.elevate1`, `sccm.elevate2`, `sccm.elevate3`, `sccm.takeover2`, `sccm.creds2`, and `sccm.creds5`. Historical SCCM canonical completions remain historical while gaining atomic accounting.
- Raised canonical methodology from **111 implemented / 16 partial / 0 gaps / 0 stale** to **117 implemented / 10 partial / 0 gaps / 0 stale**, **92% fully implemented**, and **100% represented**.
- Expanded source inventory from **5/17** to **6/17** methodology files atomized, from **18/34** to **24/34** frozen partial baselines decomposed, and from **70/70** to **93/93** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **16** to **10** broad source-inventory/decomposition items, moving the active priority into `admin.md` with zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel75(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, retained the overview-first Dashboard owner, and added no no-op Dashboard metadata layer.
- Added v7.5 browser/runtime wiring, SCCM terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, historical-test future-safety repairs, and a dedicated v7.5 regression suite under the exact-head release workflow.

## v7.4 - authenticated source-depth completion

- Atomized the pinned `authenticated.md` methodology family into nineteen meaningful source-fidelity units spanning authenticated users and SMB shares, BloodHound Legacy and CE collection, LDAP and AD-integrated DNS inventory, AD CS and SCCM routing, AD-miner, PingCastle, adPEAS, Kerberoasting, four coercion families, Entra / AD Connect discovery, lateral-movement routing, and known-vulnerability routing.
- Modeled all nineteen units end to end and reused mature BloodHound, AD CS, SCCM, Kerberoast, Entra, lateral-movement, and vulnerability-specific owners instead of creating release-only duplicates.
- Added focused v7.4 owners for classic authenticated enumeration, automated AD posture assessment, and authenticated authentication coercion, with explicit Kali/Windows execution context, semantic command behavior, conservative Evidence profiles, Next Steps integration, cleanup where relevant, and report contracts.
- Preserved strict separation between enumeration, scanner findings, coercion preparation/triggering, inbound authentication, relay success, vulnerability validation, credential/hash/certificate/ticket material, authenticated access, execution, administrator/SYSTEM access, privilege, and cleanup.
- Advanced only the three authenticated parents that remained partial in the frozen v6.2 source-depth baseline: `authenticated.auto-scan`, `authenticated.coerce`, and `authenticated.known-vulns`. Historical canonical completions remain historical while gaining atomic accounting.
- Raised canonical methodology from **108 implemented / 19 partial / 0 gaps / 0 stale** to **111 implemented / 16 partial / 0 gaps / 0 stale**, **87% fully implemented**, and **100% represented**.
- Expanded source inventory from **4/17** to **5/17** methodology files atomized, from **15/34** to **18/34** frozen partial baselines decomposed, and from **51/51** to **70/70** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **19** to **16** broad source-inventory/decomposition items, moving the active priority into `sccm.md` with zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel74(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, retained the overview-first Dashboard owner, and added no no-op Dashboard metadata layer.
- Added v7.4 browser/runtime wiring, authenticated-source terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, future-safe v7.3 regression coverage, and a dedicated v7.4 regression suite under the exact-head release workflow.

## v7.3 — MITM / relay source-depth completion

- Atomized the pinned `mitm.md` methodology family into ten meaningful source-fidelity units spanning credential/hash listening, legacy MS08-068 self-relay, NTLM relay to LDAP(S), SMB, HTTP, MSSQL, and NETLOGON/DCSync, plus Kerberos relay to HTTP/AD CS, SMB, and LDAP(S).
- Modeled nine units end to end and explicitly superseded the obsolete MS08-068 self-relay branch as a preferred modern workflow instead of silently dropping the source node or adding an obsolete exploit-first operator card.
- Reused mature unsigned-SMB NTLM relay, Kerberos relay, ESC8, and DCSync owners where they already satisfied the operator contract; added dedicated v7.3 owners for listener Evidence, LDAP(S), HTTP, MSSQL, and the retained legacy NETLOGON relay route.
- Added `data/source-delivery-v7.3.js` to normalize the new MITM owner mappings, keep the historical listener helper out of duplicate delivery debt, and preserve the existing NTLM and Kerberos relay canonical milestones.
- Preserved strict separation between listener startup, inbound authentication, relay authentication, directory/service mutation, credential/hash/certificate/ticket material, authenticated access, execution, administrator/SYSTEM access, privilege, and cleanup.
- Advanced only `mitm.listen`, the MITM parent that remained partial in the frozen v6.2 source-depth baseline. `mitm.ntlm-relay` retains its v5.6 canonical completion and `mitm.kerberos-relay` retains its v6.0 completion while both gain deeper atomic source accounting.
- Raised canonical methodology from **107 implemented / 20 partial / 0 gaps / 0 stale** to **108 implemented / 19 partial / 0 gaps / 0 stale**, **85% fully implemented**, and **100% represented**.
- Expanded source inventory from **3/17** to **4/17** methodology files atomized, from **14/34** to **15/34** frozen partial baselines decomposed, and from **41/41** to **51/51** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **20** to **19** broad source-inventory/decomposition items, moving the active priority into `authenticated.md` with zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel73(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, retained the overview-first Dashboard owner, and added no no-op Dashboard metadata layer.
- Added v7.3 browser/runtime wiring, MITM-specific terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, future-safe v7.2 regression coverage, and a dedicated v7.3 regression suite under the exact-head release workflow.

## v7.2 — ACL / ACE source-depth completion

- Atomized the pinned `acl.md` methodology family into sixteen meaningful source-fidelity units spanning DCSync, Shadow Credentials, group control, computer RBCD/Key Credential control, user password/SPN/Key Credential/logon-script control, OU inheritance/GPO links, gMSA, LAPS, GPO control, and DNSAdmins.
- Reused mature existing DCSync, LAPS, and v7.1 RBCD owners where they already satisfied the full operator contract instead of duplicating workflows merely for release symmetry.
- Added dedicated v7.2 owners for Shadow Credentials, group membership and owner/DACL control, user password reset, targeted Kerberoast, logon-script control, OU DACL and GPO-link control, gMSA retrieval, GPO reversible-write proof, and DNSAdmins ServerLevelPluginDll lifecycle.
- Added `data/source-delivery-v7.2.js` to expose the atomized ACL family in the Methodology map and to add explicit cleanup markers for owner, group-DACL, and OU-DACL restoration.
- Preserved the separation between rights discovery, directory or policy mutation, credential/certificate/hash/ticket material, authenticated service use, execution, administrator access, privilege, and cleanup. A write or retrieved credential artifact never silently becomes access or privilege.
- Reconciled the seven frozen ACL parents that were still partial at the v6.2 boundary: `acl.shadow-credentials`, `acl.group-control`, `acl.computer-control`, `acl.user-control`, `acl.ou-control`, `acl.gmsa`, and `acl.gpo`. Already-implemented DCSync, LAPS, and DNS Admin parents remain historical canonical completions while gaining deeper atomic source accounting.
- Raised canonical methodology from **102 implemented / 25 partial / 0 gaps / 0 stale** to **109 implemented / 18 partial / 0 gaps / 0 stale**, **86% fully implemented**, and **100% represented**.
- Expanded source inventory from **2/17** to **3/17** methodology files atomized, from **9/34** to **16/34** frozen partial baselines decomposed, and from **25/25** to **41/41** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **25** to **18** broad source-inventory/decomposition items, with `mitm.md` credential/hash listening and NTLM relay now highest priority and zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel72(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, while retaining the overview-first Dashboard owner and delta-based release architecture without a no-op `dashboard-v7.2.js`.
- Added v7.2 browser/runtime wiring, ACL-specific terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, and a dedicated v7.2 regression suite under the exact-head release workflow.

## v7.1 — Kerberos delegation source-depth completion

- Atomized the pinned `delegation.md` methodology family into six meaningful source-fidelity units: discovery/routing, unconstrained delegation, constrained delegation with protocol transition, constrained delegation without protocol transition, resource-based constrained delegation, and S4U2Self.
- Added dedicated v7.1 owners for each delegation unit with pinned Orange provenance, explicit Kali/Windows execution context, semantic command controls, conservative Evidence profiles, reporting contracts, and cleanup/restoration for temporary RBCD and machine-account changes.
- Preserved the separation between directory mutation, ticket material, ticket use, authenticated service access, execution, administrator access, privilege, and cleanup. A saved TGT/TGS or successful delegation write never silently becomes access or privilege.
- Modeled the pinned Kerberos-only constrained-delegation variant as an explicit staged RBCD-assisted chain, including temporary computer creation, temporary RBCD configuration, intermediate/final ticket material, and independent cleanup proof.
- Reconciled only the two frozen delegation parents that were still partial at the v6.2 boundary: `delegation.unconstrained` and `delegation.constrained`. Already-implemented discovery, RBCD, and S4U2Self parents remain historical canonical completions while gaining deeper atomic source accounting.
- Raised canonical methodology from **100 implemented / 27 partial / 0 gaps / 0 stale** to **102 implemented / 25 partial / 0 gaps / 0 stale**, **80% fully implemented**, and **100% represented**.
- Expanded source inventory from **1/17** to **2/17** methodology files atomized, from **7/34** to **9/34** frozen partial baselines decomposed, and from **19/19** to **25/25** currently inventoried atomic units fidelity-complete.
- Reduced the live Build Next queue from **27** to **25** broad source-inventory/decomposition items, with ACL / ACE control paths now highest priority and zero implemented-quality, mapped-delivery, canonical-gap, or inventoried-fidelity debt.
- Advanced the stable current projection through `C.projectModel71(...)`, `C.currentProjectModel(...)`, and `C.currentNorthStarDashboard(...)`, while retaining the overview-first Dashboard owner and delta-based release architecture without a no-op `dashboard-v7.1.js`.
- Added v7.1 browser/runtime wiring, delegation-specific terminal Evidence interpretation, current-project documentation, README/North Star synchronization, source-wave UI summary, sanitized-export version migration, and a dedicated v7.1 regression suite under the exact-head release workflow.

## v7.0 — AD CS certificate-mapping fidelity completion

- Completed the five remaining inventoried AD CS certificate-mapping source-fidelity units: Shadow Credentials bridge, ESC9, both ESC10 mapping cases, and ESC14.
- Added dedicated v7.0 methodology owners with pinned Orange provenance, current Certipy-oriented operator surfaces, explicit execution context, conservative Evidence profiles, reporting contracts, and cleanup/restoration guidance for temporary account changes.
- Kept temporary Key Credential writes, returned NT-hash material, account-attribute mutation, certificate material, authentication, service access, privilege, and cleanup as separate proof states.
- Modeled the Shadow Credentials bridge through Certipy `shadow auto` with explicit NT-hash proof and restoration proof boundaries.
- Modeled ESC9 and both ESC10 cases as temporary identity-preparation plus certificate-request workflows while refusing to infer authentication or privilege from successful mutation or certificate issuance.
- Explicitly **superseded** the pinned Orange ESC14 exploit branch rather than inventing mechanics that are not present in the source. v7.0 uses current Certipy finding collection and explicit `altSecurityIdentities` review as an assessment/reporting handoff.
- Reconciled `adcs.certificate-mapping` from partial to implemented only after all five inventoried subordinate units became terminal and fidelity-complete.
- Raised canonical methodology from **99 implemented / 28 partial / 0 gaps / 0 stale** to **100 implemented / 27 partial / 0 gaps / 0 stale**, **79% fully implemented**, and **100% represented**.
- Advanced the currently inventoried AD CS atomic ledger from **14/19** to **19/19** complete while preserving **1/17 methodology files atomized** and **7/34 frozen partial baselines decomposed**.
- Reduced the live Build Next queue from **32** to **27** items. With zero implemented-quality debt, zero mapped-delivery debt, zero canonical gaps, and zero pending inventoried AD CS units, the active phase becomes Orange source inventory/decomposition beginning with Kerberos delegation.
- Advanced the stable current project projection to `C.projectModel70(...)` through `C.currentProjectModel(...)`, kept the overview-first Dashboard owner, and retained delta-based release scaffolding without creating a no-op Dashboard overlay.
- Added v7.0 browser/runtime wiring, terminal Evidence interpretation, README/North Star synchronization, release documentation, future-safe v6.9 regression coverage, and a dedicated v7.0 regression suite while preserving the exact-head release workflow.

## v6.9 — ESC5, ESC6, and ESC11 source-fidelity delivery

- Consumed the next three live North Star Build Next items after v6.8: ESC5 vulnerable PKI-object ACL / CA-key control, ESC6 CA SAN-flag identity selection, and ESC11 RPC/ICPR enrollment relay.
- Added dedicated owners `adcs-esc5-69`, `adcs-esc6-69`, and `adcs-esc11-69` with pinned Orange provenance, current Certipy-oriented operator surfaces, explicit Kali/Windows execution context where practical, conservative Evidence profiles, Next Steps transitions, and reporting contracts.
- Kept ESC5 CA backup material separate from the offline forged certificate it can enable. CA private-key material, forged certificate material, authenticated access, privilege, and DCSync capability remain separate proof states.
- Modeled ESC6 as a requester-controlled SAN identity-selection path only after the CA flag and a suitable client-authentication-capable template. Certificate issuance remains credential material until later authentication/access Evidence proves more.
- Modeled ESC11 RPC/ICPR relay with Certipy as the preferred compact operator surface and ntlmrelayx as the pinned-source-compatible fallback. Listener startup and inbound authentication are not certificate issuance, and certificate/ticket material is not DCSync or privilege proof.
- Reconciled `adcs.pki-object-acl` from partial to implemented after ESC5 became fidelity-complete and reconciled `adcs.ca-misconfig` only after both inventoried ESC6 and ESC11 branches became fidelity-complete.
- Raised canonical methodology from **97 implemented / 30 partial / 0 gaps / 0 stale** to **99 implemented / 28 partial / 0 gaps / 0 stale**, **78% fully implemented**, and **100% represented**, while preserving the frozen 34-section v6.2 source-depth denominator.
- Advanced atomic source fidelity from **11/19** to **14/19** complete, leaving **5** inventoried AD CS certificate-mapping audits followed by **27** source-inventory/decomposition items for a **32-item** Build Next queue. The certificate-mapping shadow-credential bridge becomes the next live item.
- Kept `C.currentProjectModel(...)` and `C.currentNorthStarDashboard(...)` as the stable current pointers backed by the v6.9 adapters, and made the v6.8 UI decorator inactive when a later release owns the current version surface.
- Added v6.9 browser/runtime wiring, terminal Evidence interpretation, release documentation, README/North Star synchronization, future-safe v6.8 regression coverage, and a dedicated v6.9 regression suite while preserving the exact-head release workflow.

## v6.8 — ESC4 and ESC7 source-fidelity delivery

- Consumed the next three live North Star Build Next items after v6.7: ESC4 writable certificate-template ACL, ESC7 Manage CA officer transition, and ESC7 Manage Certificates enable / request / issue / retrieve.
- Added dedicated v6.8 owners `adcs-esc4-68`, `adcs-esc7-manage-ca-68`, and `adcs-esc7-manage-cert-68` with current Certipy operator surfaces, explicit execution context, semantic controls, conservative Evidence profiles, Next Steps transitions, cleanup/restoration, and reporting contracts.
- Reconciled `adcs.template-misconfig` and `adcs.acl-misconfig` only after their inventoried subordinate source units became fidelity-complete.
- Raised canonical methodology to **97 implemented / 30 partial / 0 gaps / 0 stale**, **76% fully implemented**, and **100% represented**.
- Advanced atomic source fidelity from **8/19** to **11/19** complete and added stable current project pointers through `C.currentProjectModel(...)`.
- Added v6.8 browser/runtime wiring, Intake interpretation, current-project documentation, README synchronization, future-safe v6.7 regression coverage, and a dedicated v6.8 regression suite.

## v6.7 — ESC13 and ESC15 source-fidelity delivery

- Consumed the next three inventoried AD CS atomic source-fidelity items: ESC13 issuance-policy/group-link template abuse and both ESC15 application-policy injection variants.
- Added dedicated v6.7 owners with pinned source provenance, Kali/Windows execution context where applicable, semantic controls, conservative Evidence profiles, Next Steps transitions, and reporting contracts.
- Preserved the pinned 127-section canonical baseline at **95 implemented / 32 partial / 0 gaps / 0 stale**, **75% fully implemented**, and **100% represented** while advancing atomic fidelity from **5/19** to **8/19**.
- Kept certificate/PFX material below authentication, access, group membership, privilege, and DCSync consequence.
- Added v6.7 browser/runtime wiring, terminal Evidence interpretation, release documentation, README synchronization, future-safe v6.6 compatibility coverage, and v6.7 regression tests.

## v6.6 — architecture consolidation and project-status simplification

- Established `C.projectModel66(...)` as the single current projection for canonical progress, source-depth/source-fidelity progress, quality debt, Build Next, recent release trend, and the next priority.
- Added `data/project-model-v6.6.js` as the authoritative current release/project metadata owner and `tools/current-runtime.js` as the shared Node-side loader.
- Rebuilt the default North Star Dashboard around an immediate project overview while preserving detailed metrics, the atomic ledger, and full Build Next queue behind drill-downs.
- Reorganized documentation so `README.md`, the architecture/proof/source-depth documents, `BUILDING.md`, and this changelog each own a durable concern.
- Preserved methodology and source-fidelity state at **95 implemented / 32 partial / 0 gaps / 0 stale**, **75% fully implemented**, **100% represented**, **1/17 source files atomized**, **7/34 frozen partial baselines decomposed**, and **5/19 inventoried atomic units fidelity-complete**.
- Kept browser-local workspace migration, human-run command behavior, conservative Evidence/proof boundaries, Next Steps semantics, report lineage, sanitized export, and the exact-head tiered CI contract unchanged.

## v6.5 — first AD CS atomic source-fidelity delivery wave

- Consumed the first five atomic source-fidelity items: AD CS enumeration/routing, ESC8, ESC1, ESC2, and ESC3.
- Added dedicated AD CS owners and source-delivery reconciliation with explicit execution context, semantic controls, conservative Evidence profiles, reporting contracts, and source provenance.
- Moved only the exhausted `adcs.enumeration` and `adcs.web-enrollment` parents to implemented while keeping broader template misconfiguration partial.
- Raised canonical methodology to **95 implemented / 32 partial / 0 gaps / 0 stale**, **75% fully implemented**, and **100% represented**.
- Advanced atomic source fidelity from **0/19** to **5/19** and reduced Build Next to **41** items.
- Wired v6.5 through browser runtime, Intake, state migration/sanitized export, README generation, release documentation, CSS/UI, and regression coverage.

## v6.4 — atomic Orange source-fidelity accounting

- Preserved canonical methodology at **93 implemented / 34 partial / 0 gaps / 0 stale**, **73% fully implemented**, and **100% represented** while adding a deeper denominator.
- Added `data/orange-fidelity-v6.4.js`, a machine-readable atomic source-fidelity ledger tied to the pinned Orange 2025.03 commit and source-file hashes.
- Atomized `adcs.md` first into **19 meaningful source units** spanning enumeration and the major ESC branches and variants.
- Added source paths, branch conditions, tool inventories, transitions, owner mappings, cleanup obligations, audit state, and per-requirement review dimensions.
- Established the initial fidelity baseline at **1/17 source files atomized**, **7/34 frozen partial baselines decomposed**, and **0/19 atomic units fidelity-complete**.
- Extended Build Next with atomic source-fidelity audits ahead of remaining source-depth decomposition and kept project/source accounting separate from engagement facts.

## v6.2 — canonical completion and Orange source-depth phase

- Completed the final canonical gap, `trusts.parent-child`, bringing the 127-section denominator to **93 implemented / 34 partial / 0 gaps / 0 stale**, **73% fully implemented**, and **100% represented**.
- Froze the **34 partial canonical sections** at the v6.2 boundary as a persistent source-depth audit denominator.
- Added the durable source-depth plan and explicit `needs-audit`, `modeled`, `superseded`, and `rejected` outcomes.
- Extended North Star Dashboard and Build Next with separate source-depth accounting so canonical representation cannot be confused with source exhaustion.

## v6.1 — PXE, TimeRoast, and trust-path completion wave

- Completed PXE / NAA credential discovery, TimeRoasting, the SCCM PXE / NAA recovery mapping, child-to-parent trust paths, and external / forest trust paths.
- Kept hash material, cracked secrets, trust material, forged ticket artifacts, cross-domain service access, and privilege as separate proof boundaries.
- Raised strict methodology to **92 implemented / 34 partial / 1 gap / 0 stale**, **72% fully implemented**, and **99% represented**.

## v6.0 — canonical quick-win and relay completion wave

- Completed Java RMI, Log4Shell, Tomcat / JBoss manager, Veeam quick-win, and the separate MITM Kerberos relay canonical branch.
- Added delivery-ready owners with explicit execution metadata, conservative Evidence profiles, decision-path placement, reporting traceability, and bounded proof semantics.
- Raised strict methodology to **87 implemented / 34 partial / 6 gaps / 0 stale**, **69% fully implemented**, and **95% represented**.

## v5.9 - generic release-quality gate and canonical gap wave

- Added the generic release-quality gate and required zero implemented-quality / mapped-delivery debt before canonical expansion.
- Completed UAC bypass, EternalBlue, Exchange ProxyShell, GLPI, and Java deserialization canonical gaps with bounded Evidence semantics.
- Raised strict methodology to **82 implemented / 34 partial / 11 gaps / 0 stale**, **65% fully implemented**, and **91% represented**.

## v5.8 — canonical gap wave and release-contract enforcement

- Completed PrintNightmare, PrivExchange, ProxyNotShell, AppLocker bypass, and Kerberos relay.
- Added `tools/validate-release-pr.js` and the release-PR metadata/description contract.
- Raised strict methodology to **77 implemented / 34 partial / 16 gaps / 0 stale**, **61% fully implemented**, and **87% represented**.

## v5.7 — highest-priority canonical gap completion wave

- Added delivery-ready owners for DNSAdmins, Entra ID / AD Connect discovery, Certifried, MS14-068, and noPac with bounded proof semantics.
- Raised strict methodology to **72 implemented / 34 partial / 21 gaps / 0 stale**, **57% fully implemented**, and **83% represented**.

## v5.6 — mapped-delivery cleanup and canonical completion wave

- Cleared mapped-workflow delivery debt by adding explicit Evidence and execution contracts to remaining mapped workflows.
- Moved Shadow Credentials, gMSA password retrieval, S4U2Self/S4U service-ticket use, NTLM relay, and weak-web-service triage from partial to implemented.
- Raised strict methodology to **67 implemented / 34 partial / 26 gaps / 0 stale**, **53% fully implemented**, and **80% represented**.

## v5.5 — implemented-quality cleanup and canonical completion wave

- Cleared implemented-canonical quality debt and added dedicated owners for authenticated AD CS enumeration, delegation discovery, DPAPI backup-key collection, LSASS extraction, and token/session impersonation.
- Raised strict methodology to **62 implemented / 39 partial / 26 gaps / 0 stale**, **49% fully implemented**, and **80% represented**.

## v5.4 — synchronized README agenda and persistence completion wave

- Added `tools/sync-readme-build-next.js` so README Build Next is generated from the same live model used by the North Star Dashboard.
- Completed dedicated lifecycle owners for Skeleton Key, Custom SSP/memssp, Diamond Ticket, Sapphire Ticket, and DCShadow.
- Raised strict methodology to **57 implemented / 44 partial / 26 gaps / 0 stale**, **45% fully implemented**, and **80% represented**.

## v5.3 — implemented-quality delivery repair wave

- Added explicit Evidence profiles and execution metadata to existing implemented workflows including SMB, DNS, ticket hygiene, LAPS, Windows enumeration, SeImpersonate, DPAPI, and stored-credential hunting.
- Preserved the strict baseline at **52 implemented / 49 partial / 26 gaps / 0 stale**, **41% fully implemented**, and **80% represented**.

## v5.2 — delivery-ready canonical accounting and build-next queue

- Added delivery-ready accounting over the 127-section ledger and a prioritized Build Next queue ordered as implemented-quality debt, mapped-delivery debt, then canonical gaps.
- Preserved **52 / 49 / 26 / 0**, **41% fully implemented**, and **80% represented**.

## v5.1 — delivery-debt drill-down and dashboard quality gates

- Added mapped-workflow delivery-debt accounting and searchable visibility for missing Run, Evidence, execution-side, and reporting contracts.
- Preserved the five-item primary workflow and strict **52 / 49 / 26 / 0** baseline.

## v5.0 — dashboard IA, changelog separation, and UI hygiene

- Moved full project-health reporting from Home into the dedicated North Star Dashboard under More.
- Kept Home limited to a compact completion/representation summary and dashboard link.
- Added UI/UX policy accounting for five-item primary navigation, single-dashboard ownership, current-version contract, changelog ownership, and brand-surface policy.
- Constrained Orange Cyber Defense branding to Dashboard and Home while retaining source provenance underneath neutral Methodology/Next Steps/Report surfaces.
- Replaced stacked release cards in Guide with a current workflow guide and changelog link.
- Preserved **52 / 49 / 26 / 0**, **41% fully implemented**, **80% represented**.

## v4.9 — single North Star dashboard

- Added one consolidated project dashboard with hard counts and percentages for canonical methodology, represented coverage, Run → Evidence readiness, Evidence profiles, execution metadata, decision-path mapping, tool review, reporting traceability, command UX, active-context progress, release trend, and backlog concentration.
- Added broad execution-metadata accounting and source-file backlog drill-down.
- Kept fixed commands separate from GUI-adjustable commands rather than treating every fixed command as a defect.

## v4.8 — domain persistence branch depth and lifecycle

- Added dedicated Silver Ticket, DSRM, Golden Certificate, credential-subsystem persistence, Diamond/Sapphire ticket, DCShadow, and ACL-persistence lifecycle workflows.
- Added explicit execution-side metadata, GUI controls where meaningful, conservative Evidence profiles, Next Steps integration, cleanup semantics, and report traceability.
- Moved Silver Ticket, DSRM, Golden Certificate, and ACL persistence to implemented while keeping Skeleton Key, Custom SSP, Diamond/Sapphire, and DCShadow partial.
- Raised canonical coverage to **52 implemented / 49 partial / 26 gaps / 0 stale**, **41% fully implemented**, **80% represented**.

## v4.7 — retroactive reporting traceability

- Added report contracts to all live mapped methodology cards.
- Kept finding-bearing methodology separate from path/context methodology.
- Added canonical decision-path provenance to Standard and OSCP report drafts.
- Added Draft Reporting Gaps from existing proof-readiness requirements without rewriting successful activity.

## v4.6 — SCCM branch depth and operator loop

- Expanded SCCM beyond reconnaissance into credential recovery, relay/site takeover, administrative execution, cleanup, and post-exploitation mapping.
- Added explicit Kali/Windows metadata and full Run → Evidence contracts for the new SCCM workflows.
- Added context-scoped SCCM progression to Next Steps/Home.
- Moved six SCCM sections to implemented and six more from gap to partial.
- Raised canonical coverage to **48 implemented / 45 partial / 34 gaps / 0 stale**, **38% fully implemented**, **73% represented**.

## v4.5 — Run / Evidence contract audit

- Added reusable per-card Run/Evidence contract accounting.
- Cataloged inherited parser coverage instead of treating mature earlier Evidence handlers as unknown.
- Added explicit Evidence profiles for Hashcat AD modes, BloodHound collection, SCCM discovery, trust enumeration, GPP recovery, AD CS enumeration, MSSQL access, and Golden Ticket creation.
- Added GUI-control improvements for SCCMHunter and Impacket MSSQL.

## v4.4 — canonical decision-path integration

- Grouped mapped methodology into bounded stages from environment identification through credentials, authenticated mapping, control paths, movement, host control, domain control, and persistence.
- Added context-scoped stage progress and small positive ranking signals to already-applicable Next Steps.
- Added current/next stage and canonical direction visibility to Next Steps and Home.

## v4.3 — canonical reconciliation and cracking audit

- Reconciled the v4.2 canonical denominator against methodology already present in Obol.
- Repaired the stale RBCD mapping and recognized existing DC identification, SCCM recon, GPP, MSSQL, trust, Golden Ticket, database, and other mature workflows.
- Expanded the AD Hashcat reference and corrected NetNTLMv1 to mode 5500.
- Raised live coverage to **42 implemented / 39 partial / 46 gaps / 0 stale**, **33% fully implemented**, **64% represented**.

## v4.2 — canonical Orange 2025.03 snapshot

- Added `data/orange-ad-2025.03.js` as a pinned structural snapshot of all 17 methodology-bearing AD source files plus support-file provenance.
- Pinned upstream commit `6d16ca0d1434875e0617f2f3cfa825fad0bc7d7e` and AD tree `51b414fc0c0a1a4414e86986ec5e2b5225a6d698`.
- Established the stable 127-section completion denominator.
- Added snapshot integrity, duplicate-key checks, source-file filtering, stale mapping detection, and persistent completion visibility.
- Validated baseline: **25 implemented / 39 partial / 62 gaps / 1 stale**, **20% fully implemented**, **50% represented**.

## v4.1 — methodology coverage and tool audit

- Added the first machine-readable coverage ledger for major Orange 2025.03 AD source containers.
- Added implemented / partial / gap / stale states and live card-reference validation.
- Added structured keep / supplement / replace / review tool decisions.
- Began replacing execution-side inference with explicit audited command metadata.

## v4.0 — execution context

- Added per-context operator planning mode: Either, Kali, or Windows host.
- Added Kali / Windows / target-local / neutral command-side classification and small ranking relevance signals.
- Preserved opposite-side fallbacks instead of hiding them.
- Snapshotted operator planning mode and command execution side into activity history and reports.

## v3.9 — Evidence normalization expansion

- Expanded high-confidence command-intent and outcome handling for Impacket Kerberos, secretsdump/DCSync, Impacket remote execution, PEASS-ng, and SQLmap.
- Kept command recognition separate from proven outcomes.
- Added mixed full-session transcript regression coverage and Evidence intent-coverage transparency.

## v3.8 — pivot operational state

- Added pivot source-interface context, listener health, bounded operational history, and transition-aware compromise summaries.
- Added transition-specific report proof templates and additional mixed-session regression coverage.

## v3.7 — reachability and multi-hop lineage

- Added target-specific reachability and pivot verification freshness.
- Added conservative consumer activity-ID repair.
- Added multi-hop compromise paths, artifact neighborhoods, and broader full-session transcript regression fixtures.

## v3.6 — Rubeus workbench

- Added first-class Rubeus command planning for AS-REP roasting, Kerberoasting, TGT requests, Pass-the-Ticket, and S4U/delegation.
- Connected Rubeus to Methodology, Evidence, historical command lineage, and the Tool Library.
- Added conservative Rubeus outcome inference and exact-command lineage rules.

## v3.5 — Evidence and Report field hardening

- Corrected overloaded-tool activity classification and anonymous LDAP outcome handling.
- Consolidated Report around proof readiness, external screenshot confirmation, rendered preview, and PDF export.
- Strengthened lineage repair and retained Evidence normalization.

## v3.4 — decision-first Next Steps

- Made the recommendation queue the center of Next Steps.
- Added active target/reachability context, compact decision metrics, lane/status filters, planning signals, and exact activity-ID handoff from methodology cards.

## v3.3 — command-behavior audit

- Established the command contract that the base command performs only the minimum useful maneuver and optional enumeration/scope/output/performance behavior belongs in explicit semantic controls.
- Audited major NetExec, LDAP, web discovery, data-service, and Tool Library command families around that rule.

## v3.2 — entity-first navigation cleanup

- Returned the primary workflow to Home, Targets, Evidence, Next Steps, and Report.
- Consolidated Nmap under Targets and moved graph imports to Evidence.
- Kept advanced/reference features under More.

## v3.1 — Nmap-first discovery

- Made host discovery and scanning accessible earlier in the workflow.
- Added dedicated discovery state and Nmap planning for discovery, full scans, and service scans.
- Added Nmap host/service parsing and target creation/merge behavior.

## v3.0 — workflow-first UI

- Introduced the five-item primary navigation, Home workspace overview, collapsible context panel, mobile navigation, command palette, and clearer workflow guidance.
- Separated primary operator workflow from advanced/reference surfaces.

## v2.9 — pivot lifecycle and proof obligations

- Added explicit pivot lifecycle state, reachability-aware ranking, cross-artifact dependency graphs, and stronger finding proof requirements.

## v2.8 — explicit network paths and lineage timeline

- Added explicit direct/pivot network path records, lineage timeline improvements, and report evidence state.

## v2.7 — lineage and network observations

- Added typed-artifact producer/consumer lineage, network observation extraction, context-safe deduplication, and review gates.

## v2.6 — typed artifacts and negative evidence

- Added typed artifact stores, structured handoffs, negative-evidence semantics, refuted-path handling, and broader workspace search.

## v2.5 — command-builder breadth and AD playbook

- Expanded practical semantic switches across common lab tools.
- Added staged AD methodology and machine-account-quota readiness.
- Improved prompt/ANSI normalization and evidence signatures.

## v2.4 — planned work queue

- Added context-scoped Planned Work with priorities, notes, done/deferred state, reopen behavior, and report integration.

## v2.3 — enrichment and reusable command controls

- Added Nmap hostname/OS/domain enrichment, LDAP/NetExec username distillation, and practical command controls for major tools.

## v2.2 — tool preference and transition tracking

- Added tool availability/preference handling, semantic NetExec controls, service-depth accounting, transition recording, and report readiness improvements.

## v2.1 — knowledge and terminal-aware intake

- Added supported/refuted knowledge semantics, terminal command segmentation, activity reconstruction, report readiness, and credential-aware report redaction.

## v2.0 — host-scoped evidence ledger foundation

- Established host/domain-scoped facts, activity, evidence, migration, reporting snapshots, sanitized export, and the core static/offline browser-local architecture that later releases build on.
