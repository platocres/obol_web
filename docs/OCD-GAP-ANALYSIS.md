# obol coverage & gap analysis (OSCP-scoped)

*Working build plan. Sources: `Orange-Cyberdefense/ocd-mindmaps` (GPL-3.0, AGPLv3-compatible) for the
AD lane; obol's own 19 packs for everything else.*

> **Methodology note (read first).** An earlier version of this doc used a signature `grep` scan and
> was **wrong in both directions** (an `\|`-in-ERE bug produced false zeros; and finding a handler
> string in a file does not mean it is *dispatched* for a given input). Parser coverage below is now
> established the only reliable way: **running representative pasted output through obol's actual
> parser engine** (`OBOL.parsers.parseActionOutput`) and recording the facts it mints. Harness:
> `scratchpad/ptest.js` / `ptest2.js`.

## 0. Headline (engine-verified)

- **Remote output is well parsed.** `nxc`/NetExec alone mints 12+ fact kinds (`access.admin` from
  `Pwn3d!`, `smb.shares`, `credential.available`, DC/domain/OS facts…). The same dispatcher covers
  ldapsearch, smbclient/smbmap, impacket `secretsdump`, BloodHound, kerbrute, and more. The
  **remote-first path** obol's methodology prefers is in good shape.
- **On-host / interactive output is almost entirely unparsed.** This is the real gap, and it is
  exactly the surface obol-local structurally could never ingest. obol-web *can* (paste), but the
  parsers don't exist yet.
- Net: the move library + the remote parsers are solid; **the work is the on-host/interactive
  ingestion layer**, bounded to the moves we approve.

## 1. Governing principles (unchanged — these held up)

- **Bounded parse surface.** obol parses the output of the moves it *approves*; the ingestion surface
  is the union of approved moves' parsers. Each move's "definition of done" = gate · `produces` ·
  **parser** · weight · teaching metadata (`proves`/`does_not_prove`) · scope tag.
- **Remote-first ranking.** Every move carries a locus — `R` (remote from Kali), `F` (one-shot
  code-exec), `I` (interactive on-host). The coach prefers the lowest-friction locus for an objective.
  On-host parsers are a safety net for when you're legitimately on the box — never a nudge to go there.
- **obol-web vs obol-local.** Same remote-first, proof-gated core. New *option*: parse on-host/
  interactive paste (this gap list). New *limitation*: paste-based, no live host-watching.

## 2. Engine-verified parser gaps (the build list)

Each ran through the real engine and minted **nothing** today unless noted. Facts named are the
*proposed* producers; several already exist as gate conditions waiting for a producer.

| # | Pasted output | Should mint | Unlocks / feeds | Locus | Engine result | Effort |
|---|---|---|---|---|---|---|
| 1 | mimikatz `sekurlsa::logonpasswords` | `credential.plaintext`, `hash.ntlm` | credentials, PtH | I | NO FACTS | parser |
| 2 | mimikatz `lsadump::sam` / `lsadump::lsa` | `hash.ntlm`, `loot.ntds` | PtH, cracking | I | NO FACTS | parser |
| 3 | `whoami /priv` | `privesc.windows_privilege` | **already gates `seimpersonate`** | F/I | NO FACTS | **dispatch only** — minter exists in `host.js` |
| 4 | `sudo -l` | `privesc.sudo_rights` | **already gates `sudo-abuse`** | F/I | NO FACTS | **dispatch only** — minter exists in `host.js` |
| 5 | winPEAS / PrivescCheck | `privesc.leads`, `privesc.windows_privilege`, `privesc.stored_credentials` | `windows-enum` | I | NO FACTS | parser |
| 6 | PowerView `Get-NetUser`/`Get-DomainUser` | `ad.user_list`, `ad.control_paths` | `powerview-enum` | I | NO FACTS | parser |
| 7 | `net user` / `net localgroup`/`net group` | `ad.user_list`, local-admin membership | enum, admin discovery | F/I | NO FACTS | parser |
| 8 | `schtasks /query /v` | `privesc.leads` | `windows-enum` | F/I | NO FACTS | parser |
| 9 | `reg query` (autologon / stored creds) | `credential.candidate`, `privesc.stored_credentials` | cred reuse | F/I | NO FACTS | parser |
| 10 | `klist` | `kerberos.tickets` | `ticket-reuse` | F/I | NO FACTS | parser |
| 11 | `icacls` / `accesschk` | `privesc.leads` (writable service/path) | `windows-enum` | F/I | partial — only `host.notable_program` | enhance |

**Priority order (remote-first + leverage):**
- **Batch 1 — the two dispatch-only wins (tiny, high symbolism):** #3 `whoami /priv`, #4 `sudo -l`.
  Each completes an already-gated chain by wiring the existing minter to the command. Flagship proof
  that the gate *earns* its unlock from evidence.
- **Batch 2 — credential dumps:** #1/#2 mimikatz. Highest loot value once you're admin on a host.
- **Batch 3 — on-host enumeration:** #5 winPEAS, #7 `net *`, #6 PowerView, #8 schtasks, #9 reg,
  #10 klist, #11 icacls.

## 3. Move gaps — DEFERRED, prior list retracted

The earlier grep-based move-gap list (noPac / PrintNightmare / EternalBlue / RID-brute / zone
transfer / password-policy as "missing") is **retracted** — it came from the same broken scan, and
spot-checks already show several are present (`recon-dns` does zone transfer; `nxc` paths cover
RID-brute and `--pass-pol`). Move existence must be re-established from the authoritative pack
inventory (`actions[].id/title`) and, where relevant, the engine — not grep. Candidates that the
reliable move-inventory (`id`/`title` across packs) shows no dedicated move for, pending confirmation:
**MS14-068**, **MSCache2 (DCC2) crack**. Everything else: verify before claiming.

## 4. Small engine additions implied

- **Dispatch wiring** for bare on-host commands (`whoami /priv`, `sudo -l`, `net *`, `schtasks`,
  `reg query`, `klist`, mimikatz) in `parsers/index.js`.
- **Producers** for facts already referenced as gates but unminted from these inputs
  (`privesc.windows_privilege`, `privesc.sudo_rights` — minters exist, just unrouted).
- **A `locus` field** (`R`/`F`/`I`) + **scope tag** (`oscp`/`oscp+`/`beyond`) on moves, for remote-first
  ranking and a newcomer-safe scope lens.

---
*OCD scoping reality: OCD's machine-readable source is AD-only, so it informs the AD move lane; the
non-AD breadth and all parser work above come from obol's own surface. Parser findings are
engine-verified; move findings are pending the same rigor.*
