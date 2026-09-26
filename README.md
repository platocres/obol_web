# Obol — your OSCP prep companion, in the browser

**Obol is a free, browser-based sidekick for hacking practice boxes and exams.** You still do
the hacking in your own terminal — Obol is the calm voice next to you that says *"here's the
next command to try, and here's why,"* keeps track of what you've actually proven about a box,
and quietly assembles your report as you go.

No install. No login. No backend. Nothing you type ever leaves your browser. Open the page and
start.

👉 **Live site: https://platocres.github.io/obol_web/**

---

## What Obol does for you

Studying for the OSCP (or grinding HTB / TryHackMe / CPTS) is really an exercise in *not getting
lost*: you're staring at an open port wondering what to run, forgetting which creds worked where,
and panicking about screenshots the night before the exam. Obol takes that load off you:

- **Tells you what to do next.** Instead of a giant cheatsheet, Obol looks at what you've proven
  about a target so far and gives you a short, ranked list of the *next* commands worth running —
  each ready to copy, with a one-line "why" and an honest note on what it does **not** prove.
- **Keeps you honest.** Obol only marks something as true when your tool output actually shows it.
  An open port is not a shell. A crackable hash is not a login. This is exactly the discipline the
  exam graders (and good pentesters) expect.
- **Remembers everything.** Which hosts are up, which services are open, which creds are valid where,
  what you've already tried — all tracked so you don't re-scan the same box at 3am.
- **Writes your report.** As you capture flags and findings, Obol builds an OSCP-style report you
  can export — with the proof discipline and redaction the exam requires.
- **Runs entirely on your machine.** It's a static web page. Your targets, creds, and notes live in
  your browser only. You can even save the page and use it offline.

> ⚠️ Obol **never runs commands for you** — it builds them so *you* can review and run them in an
> authorized lab or exam. That's on purpose: you stay in control, and every command lands in your
> own terminal history as evidence.

---

## How to use it — a quick walkthrough

**1. Start an engagement.** On the **Engagements** screen, pick the platform you're working on —
**HTB, OffSec/OSCP, OffSec Labs (PWK), TryHackMe, HTB CPTS, CTF, or OSWP**. Your choice tunes Obol
to that platform's flags, proof rules, and report style. Paste your target IP(s) (junk and CIDR
ranges are filtered automatically) and hit **Create & launch**.

**2. Get your first move.** You land on **Next Steps** — the coach. For a fresh box it'll suggest
an nmap scan first. Click **copy**, paste it into *your* terminal, and run it.

**3. Feed Obol what you found.** Copy your tool's output and paste it into **Evidence**. Obol's
parsers read it and record only what's actually proven (open ports, reachable services, a valid
credential…). Nothing is invented.

**4. Watch the path open up.** Next Steps recomputes instantly. New moves unlock (found LDAP? now
you'll see the AD enumeration moves). Blocked moves are listed too, each telling you exactly which
fact would unlock it — so you always know what to hunt for next.

**5. Repeat until rooted.** Run → paste → get the next move. Along the way:
   - Need to *build* a specific command with all its flags? That's the **Tools** tab.
   - Popped a shell? The **target page** shows that box's attack path and access level.
   - Dumped BloodHound data? Drop the zip on **Domain** for instant attack-path analysis.
   - Got creds? The **Creds** matrix shows where they work and retargets everything with one click.

**6. Capture flags and report.** The **Scoreboard** tracks your local/root flags and OSCP points.
When you're done, **Report** exports an OSCP-style writeup (secrets redacted by default).

---

## The tabs, in plain terms

| Tab | What it's for |
|---|---|
| **Engagements** | Start/switch a run; pick your platform; set your scope. |
| **Targets** | Your boxes. Click one for its personal attack-path page. |
| **Evidence** | Paste tool output here → Obol turns it into proven facts. Also attach **proof screenshots** that embed into your report. |
| **Next Steps** | The coach: your ranked, copy-ready next commands. |
| **Playbooks** | Ready-made command sequences (e.g. AD recon) for common flows. |
| **Tools** | Build a specific tool's command with every flag, presets, and your values filled in. |
| **Map** | The whole engagement at a glance: hosts → services → creds → domain. |
| **Domain** | Upload a SharpHound zip → who's Kerberoastable, paths to Domain Admin, a printable report. |
| **Creds** | Which credential works on which host; one-click retarget. |
| **Checklist** | The full methodology, tickable, so nothing gets missed. |
| **Findings** | Every catalogued finding across all your hosts, by severity, with remediation. |
| **Scoreboard** | Flags captured and OSCP points vs. the pass threshold. |
| **Report** | Your exportable OSCP/CTF report, with proof discipline and redaction. |

**Pro tip:** hit **⌘K / Ctrl+K** anywhere to fuzzy-search every command — Enter copies it with
your target and creds already filled in. And there's a **skin picker** (top-right) if you like
your console matrix-green or amber. 🙂

---

## A note for exam day

Obol models the OSCP scoring rules: local + proof flags per machine, the 70-point pass threshold,
and the Active-Directory set's all-or-nothing block. It also reminds you when a flag needs a
**compliant proof screenshot** (the flag *and* `ip a`/`hostname` in the same window) — the #1 way
students lose points they earned. Obol can't take the screenshot for you, but it won't let you
forget it.

Everything is browser-local, so keep the tab open (or save the page) during your exam. Nothing is
sent anywhere.

---

## Run it yourself

Just open `index.html` in any modern browser — no server, no build step, no dependencies. It works
offline. To host your own copy, drop the folder on any static host (GitHub Pages, Netlify, or even
`file://`).

Your engagement data is stored in your browser's local database (IndexedDB). Clearing site data
resets it; different browsers/devices keep separate copies.

---

## Under the hood (for developers)

Obol web is the static-site edition of the terminal tool
[obol-local](https://github.com/platocres/obol-local): its planner, methodology packs, evidence
parsers, BloodHound analysis, and report pipeline, all ported to run purely in the browser. See
[`AGENTS.md`](AGENTS.md) and [`docs/LOCAL-INHERITANCE-OVERHAUL.md`](docs/LOCAL-INHERITANCE-OVERHAUL.md)
for the architecture and the obol-local → obol_web source map. Tests live in `tests/` and run in CI
(`.github/workflows/ci.yml`).

## Legal / ethics

Obol is for **authorized** labs, training, CTFs, exam preparation, and engagements where you have
explicit permission to test. Don't point it at anything you're not allowed to touch.
