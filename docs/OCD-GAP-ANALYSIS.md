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

| # | Pasted output | Should mint | Unlocks / feeds | Locus | Status |
|---|---|---|---|---|---|
| 1 | mimikatz `sekurlsa::logonpasswords` | `credential.plaintext`, `hash.ntlm` | credentials, PtH | I | ✅ **shipped** |
| 2 | mimikatz `lsadump::sam` / `lsadump::lsa` | `hash.ntlm`, `loot.ntds` | PtH, cracking | I | ✅ **shipped** |
| 3 | `whoami /priv` | `privesc.windows_privilege` | gates `seimpersonate` | F/I | ✅ **shipped** |
| 4 | `sudo -l` | `privesc.sudo_rights` | gates `sudo-abuse` | F/I | ✅ **shipped** |
| 5 | winPEAS / PrivescCheck | `privesc.windows_privilege`, `privesc.stored_credentials`, `privesc.leads` | `windows-enum` | I | ✅ **shipped** |
| 6 | PowerView `Get-NetUser`/`Get-DomainUser`/`Get-ADUser` | `ad.user_list`, `ad.acl_lead`→(ACL moves), `ad.group_list`, `ad.computer_list` | `powerview-enum`, ACL abuse | I | ✅ **shipped** |
| 7 | `net user` / `net localgroup`/`net group` | `ad.user_list`, `config.review` (local admins) | enum, admin discovery | F/I | ✅ **shipped** |
| 8 | `schtasks /query /v` | `privesc.scheduled_task` → `privesc.leads` | `windows-enum` | F/I | ✅ **shipped** |
| 9 | `reg query` (autologon / stored creds) | `credential.candidate`, `privesc.stored_credentials` | cred reuse | F/I | ✅ **shipped** |
| 10 | `klist` | `kerberos.tickets` | `ticket-reuse` | F/I | ✅ **shipped** |
| 11 | `icacls` / `accesschk` | `privesc.weak_service_permission` → `privesc.leads` (writable service/path) | `windows-enum` | F/I | ✅ **shipped** |

**Note (shipped work):** wiring `whoami /priv`/`sudo -l` only needed dispatch (the `host.js` minters existed).
The ACL path got a bonus fix: `ad.acl_lead` (from PowerView *and* bloodyAD) was produced but consumed by
no move — now wired into `ad-acl-abuse` / `bloodyad-acl` / `ad-path-manual`'s gates, so ACL enumeration is
actionable. `nxc`/netexec output was already parsed (not a gap — an earlier grep false alarm, corrected).

**Priority order (remote-first + leverage):**
- **Batch 1 (shipped):** `whoami /priv`, `sudo -l` — dispatch-only wins completing already-gated chains.
- **Batch A (shipped):** mimikatz dumps (#1/#2), winPEAS (#5), PowerView (#6), `net *` (#7), plus the
  `ad.acl_lead` gate wiring.
- **Batch B (shipped):** `schtasks` (#8), `reg query` (#9), `klist` (#10), `icacls`/`accesschk` enhance (#11)
  — each content-gated (a signature + `_parse_*` → existing minters), so a harmless dump mints nothing.

**Parser work complete:** the on-host/interactive ingestion layer (Batches 1/A/B) now covers every approved
on-host move. Remote parsing was already solid. The ingestion gap this doc opened with is closed.

## 3. Move gaps — CONFIRMED (structured field search, not grep)

Re-established by loading every pack and searching `id`/`title`/`tool`/`commands`/`refs` per action
(not the broken grep). The earlier grep list was wrong; several it flagged are present (`recon-dns`
does zone transfer; `nxc` covers RID-brute and `--pass-pol`). What is **genuinely** missing:

| Technique | Scope | State | Move added |
|---|---|---|---|
| **EternalBlue (MS17-010)** | CORE-OSCP | ✅ **shipped** | `eternalblue` (gated on `smb.ms17_010`, minted by the nmap NSE parser from a positive `smb-vuln-ms17-010` verdict only) → `foothold.windows`/`access.system` |
| noPac (CVE-2021-42278/42287) | OSCP+-edge | ✅ **shipped** | `nopac` (creds + DC context) |
| PrintNightmare (1675/34527) | OSCP+-edge | ✅ **shipped** | `printnightmare` |
| MS14-068 (PAC forge) | OSCP+-edge | ✅ **shipped** | `ms14-068` (legacy AD CVE) |
| MSCache2 / DCC2 crack | OSCP+-edge | ✅ **shipped** | `crack-mscache2` in the `cracking` pack (gated on `hash.mscache`, minted from a `$DCC2$` cache dump) |

All five shipped as data-only pack additions with the usual gate/`produces`/parser treatment. EternalBlue
and MSCache2 both earn their gate fact from a conservative, content-bound parser (a positive NSE verdict;
a well-formed `$DCC2$#user#hash` token) — never from a bare mention. The ranker treats the proven-vuln
facts (`smb.ms17_010`, `hash.mscache`) as deterministic cash-ins and the speculative legacy-CVE firings
(`ms14-068`, `nopac`, `printnightmare`) as gambles, so they rank sensibly rather than over-eagerly.

## 4. Small engine additions implied

- **Dispatch wiring** for bare on-host commands (`whoami /priv`, `sudo -l`, `net *`, `schtasks`,
  `reg query`, `klist`, mimikatz) in `parsers/index.js`.
- **Producers** for facts already referenced as gates but unminted from these inputs
  (`privesc.windows_privilege`, `privesc.sudo_rights` — minters exist, just unrouted).
- **A `locus` field** (`R`/`F`/`I`) + **scope tag** (`oscp`/`oscp+`/`beyond`) on moves, for remote-first
  ranking and a newcomer-safe scope lens.

---
*OCD scoping reality: OCD's machine-readable source is AD-only, so it informs the AD move lane; the
non-AD breadth and all parser work above come from obol's own surface. Parser and move findings are now
engine-verified: each shipped parser mints through the real dispatcher, and each new move unlocks only when
its gate fact is held (and stays blocked otherwise) under the live ranker.*
