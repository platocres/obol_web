# OCD-Mindmaps → obol: OSCP-scoped gap analysis

*Working build plan. Source: `Orange-Cyberdefense/ocd-mindmaps` (GPL-3.0; AGPLv3-compatible).
Cross-checked against all 161 obol moves across 19 packs + a parser-signature scan.*

## 0. Headline findings (read this first)

1. **OCD's machine-readable source is Active Directory only.** `excalimap/mindmap/` contains
   just the AD maps; the old broad recon/web/privesc "pentest mindmap" exists here only as images.
   So this diff is an **AD-lane** diff. Non-AD breadth comes from obol's own packs + other sources.

2. **obol's OSCP *move* coverage is already strong.** Judged only against the 48 AD moves, the AD
   map looked full of gaps — but most are already shipped in other packs: `seimpersonate` (Potato),
   `windows-enum` (winPEAS), `dpapi-secrets`, `crack-ntlm`/`crack-netntlmv2`, `mssql-login`/
   `mssql-xp-cmdshell`, `responder-poison`, `ntlm-relay-attack`, `mitm6`, `recon-dns` (zone transfer),
   Tomcat deploy. The move library is **not** the main gap.

3. **The dominant real gap is the ingestion layer — parsers, not moves.** Moves exist; the parsers
   that mint facts from their pasted output mostly don't — especially the post-foothold / interactive
   Windows surface obol-local structurally never could ingest. Several chains are **fully wired except
   the parser**:
   - `whoami /priv` → `privesc.windows_privilege` → already gates **`seimpersonate`**  *(parser missing)*
   - `sudo -l` → `privesc.sudo_rights` → already gates **`sudo-abuse`**  *(parser missing)*
   - `nxc …` output → shares/users/admin/creds → feeds **`nxc-arsenal`** + others  *(parser missing)*

4. So the work is **"audit each approved move for its parser; fill the gaps,"** plus a short list of
   genuinely-absent moves — not a 40-move import.

## 1. Governing principles (how to rank the work)

- **Bounded parse surface.** obol parses the output of the moves it *approves*, nothing more. The
  ingestion surface = the union of approved moves' parsers. Bounded, testable, per-move.
- **Remote-first ranking.** In a timed lab you stay off the host until you must. Every move carries a
  **locus**; the coach prefers lower-friction loci for the same objective:
  - `R` — remote from Kali, no foothold (nmap, nxc, impacket, bloodhound-python, ldapsearch). *Preferred.*
  - `F` — needs code-exec but one-shot / non-interactive (`nxc -x`, wmiexec one-liners).
  - `I` — interactive on-host session (evil-winrm, RDP, running winPEAS/PowerView live). *Last resort.*
- **obol-web vs obol-local.** Same remote-first, proof-gated core. New *option*: can parse on-host /
  interactive output (paste), which obol-local couldn't. New *limitation*: paste-based, no live host
  watching. On-host parsers are a safety net for when you're genuinely there — never a nudge to go there.
- **Definition of done (every approved move):** gate (`requires_*`) · `produces` facts · **parser** ·
  weight/priority · teaching metadata (`proves` / `does_not_prove`) · scope tag (OSCP / OSCP+ / beyond).

## 2. Axis A — parser / ingestion gaps  *(PRIORITY — move exists, output unparsed)*

> Signature-scan based; confirm each before building. The P0 items (whoami/priv, nxc, PowerView, net)
> are near-certain. Locus shown because it sets ranking, not whether to build the parser.

| # | Pasted output to parse | Mint fact(s) | Completes move(s) | Locus | Status | Pri |
|---|---|---|---|---|---|---|
| A1 | `nxc`/netexec (smb/ldap/winrm/mssql) output | `smb.shares`, `ad.user_list`, `credential.candidate`, `access.admin`, `enum.deep` | `nxc-arsenal`, share/user enum, spray results | **R** | missing | **P0** |
| A2 | `whoami /priv` (+ `/all`, `/groups`) | **`privesc.windows_privilege`**, group membership | **`seimpersonate`** (already gated on it) | F/I | missing | **P0** |
| A3 | winPEAS / PrivescCheck.ps1 | `privesc.leads`, `privesc.stored_credentials`, `privesc.windows_privilege` | `windows-enum` | I | missing | **P0** |
| A4 | `sudo -l` | **`privesc.sudo_rights`** | **`sudo-abuse`** (already gated on it) | F/I | missing | **P0** |
| A5 | PowerView / `Get-ADUser`/`Get-DomainUser` | `ad.user_list`, `ad.control_paths`, `ad.attack_paths` | `powerview-enum`, `ad-legacy-enum` | I | missing | P1 |
| A6 | mimikatz `sekurlsa::logonpasswords` / `lsadump::sam`/`lsa` | `credential.plaintext`, `hash.ntlm`, `loot.ntds` | `lsass-dump-onbox`, `dump-secrets` | I | thin | P1 |
| A7 | `net user` / `net localgroup` / `net group /domain` | `ad.user_list`, local-admin membership | on-host enum | F/I | missing | P1 |
| A8 | linPEAS | `privesc.leads` | `linux-enum` | I | thin | P2 |
| A9 | `klist` / `.kirbi` / `.ccache` references | `kerberos.tickets` | `ticket-reuse`, `kerberos-tickets` | F/I | thin | P2 |

**Note the ranking consequence:** A1 (`nxc`, locus R) is the highest-leverage parser because it
serves the *remote-first* path and lights up many moves at once. A2–A4 (on-host) are P0 for a
different reason — they complete already-wired chains with a single parser each — but they fire only
once you're legitimately on the box.

## 3. Axis B — genuine move gaps  *(OSCP-scoped, after full cross-check)*

### CORE-OSCP
| Move | Gate (proposed) | Produces | Parser hook | Locus | Notes |
|---|---|---|---|---|---|
| **EternalBlue (MS17-010) exploit** | `scan.nmap.vuln?` (or a new `ms17010.vulnerable`) | `foothold.windows`, `access.system` | msf/exploit console output → `access.system` | R | detection exists (`nmap-vuln-scripts`); no exploit move |
| **RID-brute / null-session user enum** | `smb.reachable?`, `port:445?` (no creds) | `ad.user_list` | `nxc --rid-brute` / `lookupsid.py` output | R | PARTIAL of `ad-user-enum` (that one is kerbrute/pre-auth style) |

### OSCP+-EDGE
| Move | Gate (proposed) | Produces | Parser hook | Locus | Notes |
|---|---|---|---|---|---|
| **noPac** (CVE-2021-42278/42287) | `credential.available`, `ad.dc_candidate?` | `loot.ntds`, `access.admin` | tool output → ntds/admin | R | add to known-exploits |
| **PrintNightmare** (1675/34527) | `credential.available` | `access.system` | PoC output | R/F | |
| **MS14-068** (forged PAC) | `credential.available`, `ad.dc_candidate?` | `kerberos.tickets`, `access.admin` | goldenPac output | R | legacy DCs |
| **Blind Kerberoasting** (no-preauth) | `ad.user_list` (SPN user) | `hash.tgs` | reuse `kerberoast` parser | R | variant of `kerberoast` |
| **Targeted Kerberoasting** (ACL add-SPN) | `ad.control_paths?` | `hash.tgs` | reuse `kerberoast` parser | R | variant; chains off ACL |
| **Password-policy / lockout enum** | `credential.available?` | `ad.pass_policy` (new) | `nxc --pass-pol` output | R | feeds safe-spray threshold before `password-spray` |
| **Crack MSCache2 (DCC2)** | `hash.mscache?` (new, from `dump-secrets`) | `credential.candidate` | hashcat `-m 2100` | R | add to `cracking` pack |

### Deliberately deferred (BEYOND-OSCP — build later for the all-in-one vision; gated so they never
surface in an OSCP-shaped engagement): full ADCS ESC chains (ESC2/3/4/5/6/7/9–15), NTLM/Kerberos
relay *delivery* chains, SCCM takeover, cross-forest trust escalation, golden/silver/diamond-ticket
*persistence*, DSRM/Skeleton-Key/SSP, DPAPI domain-backup-key, Shadow/Sapphire-ticket variants.
obol already has recon/finder stubs for most of these (`adcs-esc`, `trust-enum`, `sccm-enum`,
`golden-ticket`, …); the deferred work is the deeper chains, not net-new lanes.

## 4. Ranked build order (portions, OSCP-first)

- **Batch 1 — the remote-first parser backbone (P0).** A1 `nxc` output parser (highest leverage,
  locus R). Pairs with: confirm the spray/enum facts it should mint. *One parser, many moves lit.*
- **Batch 2 — the "already-wired chain" parsers (P0).** A2 `whoami /priv` → `privesc.windows_privilege`
  (flagship: completes `seimpersonate`), A4 `sudo -l` → `privesc.sudo_rights` (completes `sudo-abuse`),
  A3 winPEAS/PrivescCheck. These are tiny, high-value, and make the proof-gate *demonstrably* teach.
- **Batch 3 — remote enumeration parity parsers (P1).** A5 PowerView/AD-PS output, A7 `net *`,
  A6 mimikatz dump output.
- **Batch 4 — CORE-OSCP move gaps.** EternalBlue exploit move; RID-brute enum variant.
- **Batch 5 — OSCP+-EDGE move gaps.** noPac / PrintNightmare / MS14-068; blind & targeted Kerberoast;
  password-policy enum; MSCache2 crack.
- **Later — beyond-OSCP** (the deferred list), gated to stay invisible in OSCP context.

## 5. Two small engine additions this implies

- **New fact kinds:** `privesc.windows_privilege`*(already referenced by `seimpersonate`'s gate —
  just needs a producer)*, `privesc.sudo_rights` *(same, for `sudo-abuse`)*, `ad.pass_policy`,
  `hash.mscache`, optionally `ms17010.vulnerable`.
- **A `locus` field on moves** (`R`/`F`/`I`) so the coach can enforce remote-first ranking, and a
  **scope tag** (`oscp` / `oscp+` / `beyond`) so the all-in-one breadth stays newcomer-safe via an
  optional lens — not deletion.

---
*Method caveat: parser statuses are from a signature scan; confirm per-item before building. Move
cross-check is exhaustive across all 19 packs.*
