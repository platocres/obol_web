# OBOL: the browser coach that works the box with you

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-2ea44f?style=flat-square)](LICENSE)
![Backend: none](https://img.shields.io/badge/backend-none-informational?style=flat-square)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-2ea44f?style=flat-square)
![Offline: ready](https://img.shields.io/badge/offline-ready-2ea44f?style=flat-square)
![Runs in: browser](https://img.shields.io/badge/runs%20in-browser-8a2be2?style=flat-square)
[![Live demo](https://img.shields.io/badge/live-demo-0aa0ff?style=flat-square)](https://platocres.github.io/obol/)

**OBOL (Offensive Box Operations Ledger) is a free, browser-based companion for hacking practice
boxes and prepping for the OSCP.** You hack in your own terminal. OBOL is the calm voice beside you
that says *"here's the exact next command, and here's why,"* tracks everything you've actually proven
about a target, turns a SharpHound dump into a route to Domain Admin, and assembles your exam report
as you go. No install, no login, no backend. Nothing you type ever leaves your browser.

<p align="center">
  <img src="screenshots/coach.png" alt="The OBOL coach: ranked, copy-ready next moves with a one-line why, the live context rail, and per-move field notes" width="100%">
</p>

**Live site: https://platocres.github.io/obol/**

> OBOL **never runs commands for you.** It builds them so *you* can review and run them in an
> authorized lab or exam. You stay in control, and every command lands in your own terminal history
> as evidence.

---

## Why OBOL

Studying for the OSCP (or grinding HTB / PG / TryHackMe) is really an exercise in *not getting lost*:
you stare at an open port wondering what to run, forget which cred worked where, scroll a 500-line
cheatsheet for the one command you need, and panic about proof screenshots the night before. OBOL
takes that load off you:

- **It tells you what to do next.** Instead of a cheatsheet, OBOL looks at what you've *proven* about
  a target and hands you a short, ranked list of the next commands worth running, each copy-ready and
  pre-filled with your target, creds, and LHOST, with a one-line "why" and an honest note on what it
  does **not** prove.
- **It only believes your output.** An open port is not a shell. A crackable hash is not a login.
  OBOL mints a fact only when your pasted tool output actually demonstrates it. That is the exact
  discipline the exam graders (and good pentesters) expect.
- **It remembers everything.** Hosts, services, which cred is valid where, what you've already tried,
  flags captured, all tracked, so you never re-scan the same box at 3am.
- **It reads your SharpHound dump.** Drop a BloodHound collection and OBOL draws your owned-to-Domain
  Admin attack paths, answers the high-value queries, and feeds the whole thing back into the coach.
- **It carries a whole workbench.** Reverse-shell builder, hash identifier, encoders, a JWT decoder,
  GTFOBins, a wordlist picker, a manual-SQLi guide, all client-side, all filled from your engagement.
- **It writes your report.** As you capture flags and findings, OBOL assembles an OSCP-style report
  and exports it as Markdown, HTML, PDF, or Word, with the proof discipline and redaction the exam
  requires.
- **It runs entirely on your machine.** A static web page. Your targets, creds, and notes live in
  your browser only. Save the page and it works offline, even during the exam.

---

## The loop: run, paste, get the next move

OBOL watches one thing: **proof**. You run a command in your terminal, paste the output, and OBOL's
conservative parsers mint *facts*, but only for what the output genuinely shows. Every fact is
timestamped, attributed to the command that proved it, and drives everything else, the coach, the
attack graph, the findings, and the report all recompute the instant a new fact lands.

<p align="center">
  <img src="screenshots/runlog.png" alt="The Run Log: every command with the exact facts it proved, shown as chips, newest first, with full saved output" width="92%">
</p>

```mermaid
flowchart LR
    s["Set target<br/>and platform"] --> scan["Run a command<br/>in your terminal"]
    scan --> paste["Paste the output<br/>(Evidence, or Paste anywhere)"]
    paste --> mint["OBOL mints only<br/>the proven facts"]
    mint --> coach["Coach re-ranks<br/>your next moves"]
    coach --> scan
    mint --> flags["Capture flags<br/>and findings"]
    flags --> report["Export the<br/>OSCP report"]
```

The loop is deliberately tight: **run, paste, get the next move**, over and over, until the box is
rooted. Findings and flags accumulate as you go, so your report is essentially finished the moment
you are.

---

## Turn a SharpHound dump into a route to Domain Admin

Drop a SharpHound `.zip` (or BloodHound-CE `.json` files) on the **Domain** tab and OBOL parses the
whole collection in your browser, nothing is uploaded anywhere. From that one export it derives and
**draws every owned-to-Domain-Admin attack path** as an interactive graph you can pan, zoom, and
rearrange. Owned accounts glow green, nodes you already control are ringed, Domain Admin is red, and
each edge is labelled with the abuse that walks it.

<p align="center">
  <img src="screenshots/domain-graph.png" alt="The attack-path graph: several owned accounts funnelling through nested groups to the Domain Admin node, each edge labelled with its abuse" width="100%">
</p>

Then it does what a raw BloodHound dump does not: it **hands you the route as numbered, copy-ready
commands** (grant yourself DCSync, dump the Administrator hash, pass it), flags who is Kerberoastable,
AS-REP roastable, or can DCSync, ranks the accounts worth hunting next by how many hops they save, and
bridges the whole thing back to the coach, all pre-filled with your target and credentials.

<p align="center">
  <img src="screenshots/domain.png" alt="The Domain tab: census of the collection, owned count, and the Route To Domain Admin as numbered bloodyAD and DCSync commands" width="92%">
</p>

---

## The Workbench: borrowed back-ends, no network

A global **Workbench** of client-side utilities that answer your situation right now, each filling
from your active engagement and working standalone: a reverse-shell builder (every language, plus
one-click Base64 and PowerShell `-EncodedCommand` the way OffSec teaches it), a rule-based hash
identifier with ready crack commands, an all-at-once encoder and a multi-layer smart decoder, a JWT
decoder, a GTFOBins browser, a stack-aware wordlist picker, a manual (exam-legal) SQLi guide, an
"Explain This Output" annotator, and a lockout-aware spray planner.

<p align="center">
  <img src="screenshots/workbench.png" alt="The Workbench reverse-shell builder with LHOST and LPORT filled from the engagement, language presets, and a copy-ready payload plus its catcher" width="92%">
</p>

---

## Stuck? Ask the Ferryman

Hit a wall and don't want to paste anything? The **Stuck?** tab is a guided, sandboxed advisor.
Charon, OBOL's namesake ferryman, asks a few quick questions about your target, then lays out ranked
moves to try, in order, using the exact same coach as Next Steps. It never touches your real
engagement unless you ask it to.

<p align="center">
  <img src="screenshots/stuck.png" alt="The Stuck tab: a glowing cyberpunk Charon the Ferryman inviting you to answer a few questions so he can lay out ranked moves" width="92%">
</p>

---

## Cruise: hands-off, but exam-legal

**Cruise** is OBOL on autopilot. It hands you a batch of the *safe* enumeration moves you can run
right now, independent of each other; you run them on your own box and paste the output back; OBOL
learns the new facts and hands you the next batch, round after round. It always stops and asks before
anything that lands a shell, sprays credentials, or fires an exploit, so Exam mode stays exam-legal.
A Lab mode batches further for practice.

<p align="center">
  <img src="screenshots/cruise.png" alt="The Cruise tab: Exam and Lab mode toggle, the run-paste-advance loop, and a batch of safe steps with copy-all and download-script" width="92%">
</p>

---

## See it the way a blue team would: ATT&CK, D3FEND, compliance

The **Findings** tab carries a Splunk-ES-style framework view, flipped to the offensive side: your
recorded moves and minted findings light up the exact **MITRE ATT&CK** matrix cells a defender's SIEM
would try to detect, with the kill chain across the top. A Defensive sub-view maps each technique to
its **D3FEND** countermeasure and ATT&CK detection; Compliance rolls findings up to NIST / CIS / PCI /
CWE / OWASP; and CVEs flags the CISA KEV "actively exploited" list. Dual-use and educational: it shows
you both the attack and the catch.

<p align="center">
  <img src="screenshots/attack-matrix.png" alt="The offensive ATT&CK matrix: tactic columns and technique cells lit by what you did this engagement, with the kill chain across the top" width="100%">
</p>

Every finding stays proof-bound: catalogued, grouped by severity or target, each with the fact that
proved it, a remediation, and a CWE reference.

<p align="center">
  <img src="screenshots/findings.png" alt="The Findings list: proof-bound findings grouped by target, each with the proven fact, a fix, and a CWE link" width="92%">
</p>

---

## Everything tracked, and an exam-ready report

The **Map** draws the whole engagement from proven evidence alone: scope and domains, every target
coloured by access level, services, credentials, and findings, all hanging from the scope they belong
to.

<p align="center">
  <img src="screenshots/map.png" alt="The engagement Map: scope and domains, targets by access level, services, credentials, and findings, all from proven evidence" width="92%">
</p>

When you're done, **Report** exports an OSCP-style writeup with the proof discipline and redaction the
exam requires, in Markdown, HTML, PDF, or Word. It even calls out readiness gaps, like a flag that
still needs a compliant proof screenshot, before you submit.

<p align="center">
  <img src="screenshots/report.png" alt="The Report tab: profile, candidate and OSID fields, redaction toggle, export formats, readiness-gap warnings, and the rendered OSCP report" width="92%">
</p>

---

## The tabs, in plain terms

**Global** (always available, no engagement needed)

| Tab | What it's for |
|---|---|
| **Learn** | The methodology as a curriculum: study the moves, the field notes, the decision map. |
| **Loadout** | Your attack box. Generates a setup script that installs and pins your toolkit (fixes the common gotchas, like the evil-winrm sealing bug). |
| **Engagements** | Start/switch a run; pick your platform (HTB, OSCP, PWK, TryHackMe, CPTS, CTF, OSWP); set scope. |
| **Tools** | Build a specific tool's command with every flag, presets, and your values filled in. |
| **Workbench** | Client-side utilities: reverse shells, hash ID, encoders, JWT, GTFOBins, wordlists, manual SQLi, and more. |
| **Stuck?** | Charon the Ferryman: answer a few questions, get ranked moves, without pasting anything. |
| **Cruise** | Hands-off, exam-legal batches of safe enumeration; run, paste, advance. *(Experimental.)* |
| **Help** | A map of the whole app, a glossary, and a context-aware `?` on any screen. |

**Inside an engagement**

| Tab | What it's for |
|---|---|
| **Hub** | The box at a glance: what's proven, what's next, where you are. |
| **Targets** | Your boxes. Select one for its personal attack-path page. |
| **Next Steps** | The coach: your ranked, copy-ready next commands with field notes. |
| **Evidence** | Paste tool output and OBOL turns it into proven facts. Also attach proof screenshots. |
| **Map** | The whole engagement: scope, hosts, services, creds, domain, findings. |
| **Domain** | Drop a SharpHound zip for owned-to-DA paths, high-value queries, and a printable report. |
| **Creds** | Which credential works on which host; one-click retarget. |
| **Checklist** | The full methodology, tickable, so nothing gets missed. |
| **Findings** | Proof-bound findings, plus the ATT&CK / D3FEND / compliance / CVE framework views. |
| **Run Log** | Every command you ran, what it proved, and its full saved output. |
| **Flags** | Local/root flags captured and OSCP points vs. the pass threshold. |
| **Report** | Your exportable OSCP/CTF report, with proof discipline and redaction. |

**Pro tip:** hit **Paste** (top-right) on any screen to drop in terminal output, or press
**⌘K / Ctrl+K** to fuzzy-search every command and copy it pre-filled. A skin picker (bottom-right)
sets the console green, amber, or several other themes.

---

## How it works

OBOL is a **static single-page app**: plain HTML, CSS, and vanilla JavaScript, no framework, no build
step, no server. The engine (facts, parsers, methodology packs, findings, report, attack graph) is
pure and UI-independent; the UI routes are thin views over it. All state lives in your browser's
IndexedDB, so an engagement survives a refresh and never leaves the machine.

```mermaid
flowchart TB
    term["Your Kali terminal<br/>(you run every command)"]
    subgraph browser["Runs entirely in your browser, no backend, nothing leaves the page"]
        direction TB
        ui["UI routes<br/>coach · evidence · domain · workbench · findings · report"]
        engine["Engine<br/>facts · parsers · packs · bloodhound · frameworks · report · path graph"]
        packs["Methodology packs<br/>bundled JSON: recon, AD, web, privesc, cracking, pivot, …"]
        db[("IndexedDB<br/>engagements · facts · evidence · screenshots")]
        ui --> engine
        engine --> packs
        ui <--> db
        engine <--> db
    end
    term -- "paste tool output" --> ui
    ui -- "copy the next command" --> term
```

**Design principles**

- **Proof-gated.** Facts are only minted from real tool output; the coach, graph, findings, and
  report are all projections of that fact ledger.
- **No execution, no telemetry.** OBOL builds commands for you to run; it never runs them, and it
  makes no network calls. That is also why it stays exam-legal: it is a deterministic reference and
  notes tool, with no LLM.
- **Offline-first.** Everything is client-side, so the app works from `file://` and keeps running
  with no connection.

---

## A note for exam day

OBOL models the OSCP scoring rules: local + proof flags per machine, the 70-point pass threshold, and
the Active-Directory set's all-or-nothing block. It reminds you when a flag needs a **compliant proof
screenshot** (the flag *and* `ip a` / `hostname` in the same window), which is the most common way
students lose points they earned. OBOL can't take the screenshot for you, but it won't let you forget
it. Everything is browser-local, so keep the tab open (or save the page) during your exam. Nothing is
sent anywhere.

---

## Run it yourself

Open `index.html` in any modern browser: no server, no build step, no dependencies. It works offline.
To host your own copy, drop the folder on any static host (GitHub Pages, Netlify, or even `file://`).
Your engagement data is stored in your browser's local database (IndexedDB); clearing site data resets
it, and different browsers or devices keep separate copies.

Tests live in `tests/` (a pure-Node engine suite and a headless-browser smoke of the real app).

---

## Status and direction

OBOL is under active development, a growing companion rather than a finished product. The methodology
packs, parsers, and coaching keep improving, and you should expect the occasional rough edge.

One thing won't change: **OBOL will never pwn a box for you.** It doesn't run exploits, and it can't
guarantee an end-to-end path to root on every machine, by design. It's a coach that keeps you
oriented, honest, and organized while *you* do the hacking, which is exactly the skill the OSCP is
testing. Where OBOL doesn't yet have a move for some niche service, it won't invent one; it points you
at the next reasonable step and stays out of your way.

The long-term goal is to map **every attribute of a quality penetration test** into OBOL's workflow:
disciplined enumeration, proof-gated findings, the full attack-path methodology, credential and pivot
tracking, and exam-grade reporting, so that working a box in OBOL mirrors how a strong operator
actually thinks and documents.

---

## Legal and ethics

OBOL is for **authorized** labs, training, CTFs, exam preparation, and engagements where you have
explicit permission to test. Don't point it at anything you're not allowed to touch. The ACME.CORP
data in the screenshots above is entirely fictional.

## License

Copyright (C) 2026 platocres.

OBOL is free software, released under the [GNU Affero General Public License v3.0](LICENSE). You may
use, study, modify, and share it under those terms; any distributed or network-served derivative must
remain open under the same license. See [CONTRIBUTING.md](CONTRIBUTING.md) for how contributions are
licensed.
