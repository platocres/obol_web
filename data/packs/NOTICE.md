# Methodology pack attribution


## Staged materials (obol/provision.py)

The §8 material cache (`obol/provision.py`) is **project-authored** and vendors no
third-party code. It records the **public download URLs** and licenses of external
tools an operator may choose to fetch onto their own Kali box (privesc enum scripts,
potato exploits, tunnel binaries, common OSCP-lab tooling). Each item remains the
property of its upstream project under that project's own license — e.g. PEASS-ng
(linPEAS/winPEAS, GPL-3.0), ligolo-ng (GPL-3.0), chisel (MIT), GodPotato /
PrintSpoofer / RunasCs / pspy (MIT-family / Unlicense), linux-exploit-suggester
(GPL-2.0), GhostPack Rubeus/Seatbelt (BSD-3-Clause). obol's code here is the
cache/registry machinery only; downloading and staging these tools is an operator
action against authorized targets.

## Shell handlers (obol/tools.py)

The reverse-shell handler catalogue (`obol/tools.py`, "Shell handlers") likewise vendors
no third-party code — it detects, apt/pipx-installs, or fetches these tools onto the
operator's own Kali box. Each remains its upstream project's property under its own
license: penelope (brightio/penelope, fetched as a single script), pwncat-cs, netcat,
rlwrap, socat. obol records only where to get them.

## obol_local_pivot_2026_09.json

The local pivot action pack is **project-authored** pack
data for small post-foothold host/network enumeration commands that bridge the
sessions/privesc milestone into the later tunnel milestone.

It intentionally records candidate facts only (`host.multihomed`,
`network.subnet_candidate`, `pivot.candidate`) and never claims that a tunnel,
route, proxy, or through-pivot scan is working. The later tunnel registry should
consume these facts and record live tunnel state separately.

## scripts_2026_09.json — manual-exploitation script library (§11)

`scripts_2026_09.json` is **project-authored** data, not
third-party code. It is a project-authored copy/paste snippet library of
common-knowledge manual-exploitation technique. Fact kinds in each script's
`prereq`/`produces`/`evidence` are normalized to obol-local's namespace
(AGENTS.md). Every snippet is `examSafe` (manual, no automated exploitation) and
**human-run** — obol fills its `{{tokens}}` and proposes it by evidence, but never
executes it.
