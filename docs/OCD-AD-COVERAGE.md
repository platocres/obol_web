# OCD AD mindmap → obol coverage (full scope, OSCP-first)

*Working build plan. Source: the **full** `Orange-Cyberdefense/ocd-mindmaps` AD mindmap
(GPL-3.0, AGPLv3-compatible), parsed from its **machine-readable markdown** (the `.md` lane
files — the code, not the rendered images). Mapped against obol's own 19 packs (~166 moves) and
the paste-ingestion parser engine.*

> **Scope.** OCD's machine-readable source is **AD-only**, so this doc scopes obol against the AD
> mindmap end to end (every lane, every node). Non-AD breadth (web, Linux privesc, service
> exploits) is out of scope here and comes from obol's own lanes — where an AD lane spills into
> service exploitation (the "Quick Compromise" lane), coverage is noted against obol's
> `web` / `known_exploits` reference lanes rather than the AD move pack.

> **Methodology note (read first, same as `OCD-GAP-ANALYSIS.md`).** Coverage below is established
> by **loading every pack and doing a structured field search** per action
> (`id` · `title` · `tool` · `tools` · `commands[].run` · `requires_*` · `produces` · `refs`) and
> by reading the real parser dispatcher (`parsers/index.js`) for ingestibility — **never a naive
> `grep`**. An earlier grep gave false zeros (an `\|`-in-ERE bug) and false hits (a handler string
> in a file is not proof it is *dispatched* for a given input). A move is ✅ only when a real
> action carries the technique; a parser is asserted only when it is wired in the dispatcher.

**Coverage legend:** ✅ covered · 🟡 partial (move exists but a variant/sub-case is missing, or only
a reference entry) · ⬜ missing. **OSCP scope:** `oscp` (exam-core) · `oscp+` (PEN-300/common lab) ·
`beyond` (exotic/legacy/edge).

**Totals: 150 OCD AD techniques catalogued — ✅ 75 · 🟡 38 · ⬜ 37.**

---

## 1. no_creds — unauthenticated foothold

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Network / port / vuln scan | `nmap-fast-open-ports`, `nmap-version-scripts`, `nmap-vuln-scripts`, `nmap-udp-top` | ✅ | oscp | nmap NSE + rustscan, parsed. |
| Find DC & domain (SRV, p88) | `ad-dc-identify` | ✅ | oscp | nslookup SRV + nxc ldap. |
| DNS zone transfer | `recon-dns` | ✅ | oscp | `dig axfr` + dnsrecon, zone parser. |
| Anonymous / guest SMB | `recon-smb-anon`, `ad-anon-ldap-enum` | ✅ | oscp | nxc `-u '' -p ''`, enum4linux, smbclient. |
| Anonymous LDAP enum | `ad-anon-ldap-enum`, `ad-dc-identify` | ✅ | oscp | base DN + objectClass=user. |
| User enum (RID-brute, net rpc) | `ad-user-enum`, `recon-smb-anon` | ✅ | oscp | `--rid-brute`, rpcclient enumdomusers. |
| Kerbrute user enum | `ad-user-enum` | ✅ | oscp | kerbrute userenum parsed. |
| LLMNR / NBT-NS / mDNS poison | `responder-poison` | ✅ | oscp | NetNTLM captured + parsed. |
| DHCPv6 / mitm6 takeover | `mitm6-ipv6-takeover` | ✅ | oscp+ | mitm6 + ntlmrelayx. |
| ARP poisoning (bettercap) / Pcredz ASREQ-roast | — | ⬜ | beyond | niche, lab-rare; not worth a move. |
| Unauth coercion PetitPotam (CVE-2022-26925) | `coerce-auth` | 🟡 | oscp+ | coerce-auth does PetitPotam but from creds; the unauth MS-EFSR variant isn't separately gated. |
| PXE boot creds (pxethief) | — | ⬜ | beyond | SCCM PXE, out of OSCP. |
| TimeRoasting | — | ⬜ | beyond | niche; see crack-hash gap too. |

## 2. low_hanging — "Quick Compromise" (mostly non-AD service exploits)

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Zerologon (CVE-2020-1472) | `zerologon-check`, `zerologon-exploit` | ✅ | beyond | safe scan + exploit-with-restore. |
| EternalBlue MS17-010 | `eternalblue` | ✅ | **oscp (CORE)** | gated on NSE `smb.ms17_010` verdict. |
| Tomcat / JBoss manager → WAR | `web` pack + `known_exploits` (Tomcat Manager → WAR) | 🟡 | oscp | reference + web lane; no dedicated AD move. |
| Java RMI / serialized (ysoserial) | `web` pack (ysoserial), `known_exploits` | 🟡 | oscp+ | web-lane territory. |
| Log4Shell | `known_exploits` (CVE-2021-44228) | 🟡 | oscp+ | reference entry, not an executable AD move. |
| MSSQL enum / weak logins | `lateral-exec`, `database` pack | ✅ | oscp | nxc mssql + mssqlclient. |
| Exchange ProxyShell | — | ⬜ | beyond | non-AD, exotic. |
| Veeam CVEs | — | ⬜ | beyond | non-AD. |
| GLPI CVEs | — | ⬜ | beyond | non-AD. |
| Weak sites (nuclei / nessus) | `web` pack (nuclei) | 🟡 | oscp | obol's web lane. |

## 3. valid_user — creds-less (spray / roast)

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Get password policy | `password-spray` (`--pass-pol`), `ad-path-manual` | ✅ | oscp | pulled before spraying. |
| Password spraying (user=pass, common, kerbrute) | `password-spray`, `nxc-arsenal` | ✅ | oscp | sprayhound + DomainPasswordSpray. |
| AS-REP roasting | `asrep-roast` | ✅ | oscp | GetNPUsers/nxc/Rubeus → `hash.asrep`. |
| Blind Kerberoasting (no-preauth) | `kerberoast` | 🟡 | oscp+ | standard kerberoast move; `-no-preauth` / GetUserSPNs blind variant not explicit. |
| CVE-2022-33679 | — | ⬜ | beyond | edge CVE. |

## 4. authenticated — valid-creds enumeration

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Find all users | `ad-user-enum`, `nxc-arsenal`, `ad-anon-ldap-enum` | ✅ | oscp | GetADUsers / nxc `--users`. |
| Enumerate SMB shares | `smb-share-inventory`, `nxc-arsenal` | ✅ | oscp | spider_plus / smbmap, share parser. |
| BloodHound (legacy + CE) | `bloodhound-collect` | ✅ | oscp | python/nxc/SharpHound, collection + analysis parsers. |
| LDAP enum (ldeep / ldapdomaindump) | `ad-anon-ldap-enum`, `nxc-arsenal` | ✅ | oscp | ldapsearch parser. |
| Internal DNS enum (adidnsdump) | `recon-dns` | 🟡 | oscp+ | zone transfer covered; authenticated adidnsdump zone dump missing. |
| Enumerate ADCS (certipy find) | `adcs-esc` | ✅ | oscp+ | `certipy find -vulnerable`, `_parse_adcs`. |
| Enumerate SCCM | `sccm-enum` | ✅ | beyond | sccmhunter find/smb, `_parse_sccm`. |
| Scan-auto (adPEAS / PingCastle / AD-miner) | `bloodhound-collect`, `ad-path-manual` | 🟡 | oscp+ | analysis covered; no adPEAS/PingCastle move. |
| Kerberoasting | `kerberoast` | ✅ | oscp | → `hash.tgs`. |
| Coerce (printerbug / petitpotam / coercer) | `coerce-auth` | ✅ | oscp+ | → `credential.netntlm`. |
| Intra ID Connect / MSOL discovery | — | ⬜ | beyond | hybrid-AD, out of OSCP. |

## 5. crack_hash

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Hash identification | `crack-identify` (name-that-hash / hashid) | ✅ | oscp | feeds the whole lane. |
| LM (`-m 3000`) | `crack-ntlm` + generic hashcat | 🟡 | oscp | no explicit LM mode move. |
| NT (`-m 1000`) | `crack-ntlm` | ✅ | oscp | |
| NetNTLMv1 (`-m 5500`) | — | 🟡 | oscp | only v2 move ships. |
| NetNTLMv2 (`-m 5600`) | `crack-netntlmv2` | ✅ | oscp | |
| Kerberos TGS (`-m 13100`) | `crack-tgs`, `crack-kerberoast` | ✅ | oscp | |
| Kerberos TGS AES128 (`-m 19600`) | — | 🟡 | oscp+ | only RC4 TGS mode ships. |
| Kerberos AS-REP (`-m 18200`) | `crack-asrep`, `crack-asrep-offline` | ✅ | oscp | |
| MSCache2 / DCC2 (`-m 2100`) | `crack-mscache2` | ✅ | beyond | gated on a `$DCC2$` token. |
| TimeRoast (`-m 31300`) | — | ⬜ | beyond | no roast move either. |
| PXE hash (`-m 19850`) | — | ⬜ | beyond | SCCM PXE. |

## 6. acl — ACL/ACE abuse

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| DCSync | `dcsync`, `bloodyad-acl` (`add dcsync`), `ad-acl-abuse` | ✅ | oscp+ | → `loot.ntds`/`hash.krbtgt`. |
| Shadow credentials (msDS-KeyCredentialLink) | `shadow-credentials` | ✅ | oscp+ | pywhisker. |
| On Group (GenericAll/Write/WriteOwner/WriteDACL) | `ad-acl-abuse`, `bloodyad-acl` | ✅ | oscp | add-member / grant-rights; `ad.acl_lead` wired. |
| On Computer (GenericAll → RBCD / shadow) | `delegation-abuse`, `shadow-credentials` | ✅ | oscp+ | |
| On User (ForceChangePassword / addSPN / shadow) | `ad-acl-abuse` (net user), `shadow-credentials` | 🟡 | oscp / oscp+ | ForceChangePassword covered; **targetedKerberoast (add-SPN) move missing**. |
| On OU (WriteDACL / OUned / GP-Link) | `gpo-abuse` | 🟡 | beyond | GP-link abuse partial; OUned not covered. |
| ReadGMSAPassword | `gmsa-read` | ✅ | oscp+ | → `credential.ntlm_hash`. |
| Get LAPS passwords | `laps-read` | ✅ | oscp+ | nxc `-M laps` parsed. |
| GPO control / abuse | `gpo-abuse` | ✅ | oscp+ | pygpoabuse. |
| DnsAdmins (CVE-2021-40469) | `dnsadmins-abuse` | ✅ | beyond | ServerLevelPluginDll. |

## 7. delegation

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Find delegation (findDelegation / BH) | `ad-path-manual`, delegation-surface parser | ✅ | oscp+ | `_parse_ad_delegation_surface` mints `ad.delegation`. |
| Unconstrained delegation (coerce + Rubeus) | `unconstrained-delegation` | ✅ | oscp+ | monitor/dump TGT. |
| Constrained delegation (S4U2self/proxy, protocol transition) | `getst-impersonation`, `delegation-abuse` | 🟡 | oscp+ | getST S4U covered; full `asktgt`→`s4u /altservice` chain not spelled out. |
| RBCD (addcomputer + rbcd + getST) | `delegation-abuse` | ✅ | oscp+ | end-to-end. |
| S4U2self abuse | `getst-impersonation` | ✅ | oscp+ | |

## 8. dom_admin

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Dump NTDS.dit (nxc `--ntds` / secretsdump / ntdsutil / dcsync / certsync) | `dump-secrets`, `dcsync` | ✅ | oscp+ | → `loot.ntds`. |
| Grab DPAPI backup keys (donpapi `--fetch-pvk`) | — | ⬜ | beyond | domain backup-key theft. |

## 9. lat_move — lateral movement

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Cleartext exec (psexec/wmiexec/smbexec/atexec/dcomexec) | `lateral-exec`, `nxc-arsenal` | ✅ | oscp | |
| WinRM (evil-winrm / PSSession) | `lateral-exec`, `own-domain-pth` | ✅ | oscp | parsed. |
| RDP (xfreerdp) | `rdp-enum`, `ad-legacy-enum` | ✅ | oscp | |
| SMB file access (smbclient) | `smb-share-inventory` | ✅ | oscp | |
| MSSQL access & exec | `lateral-exec`, `database` pack | ✅ | oscp | nxc mssql / mssqlclient. |
| Pass-the-Hash (impacket/nxc/mimikatz/winrm/RDP) | `own-domain-pth`, `ticket-reuse` | ✅ | oscp | → `access.admin`. |
| Overpass-the-Hash / PTK | `ticket-reuse`, `kerberos-tickets` | ✅ | oscp+ | asktgt /rc4, getTGT -hashes. |
| Pass-the-Ticket (ccache/kirbi) | `ticket-reuse`, `kerberos-tickets` | ✅ | oscp+ | klist parser + KRB5CCNAME. |
| AES-key auth (getTGT -aesKey) | `kerberos-tickets` | 🟡 | oscp+ | hash path covered; dedicated aesKey step implicit. |
| Socks relay (proxychains impacket) | `pivot-*` (chisel/ligolo/sshuttle/ssh/proxychains) | ✅ | oscp | pivoting pack. |
| Certificate (PtC / unPAC-the-hash) | `cert-authenticate`, `adcs-esc` | ✅ | oscp+ | certipy auth → NT hash. |
| MSSQL linked-server crawl / xp_cmdshell | `database` pack, `lateral-exec` | 🟡 | oscp | xp_cmdshell partial; `Get-SQLServerLinkCrawl` trust-link chain not a move. |

## 10. mitm — listen & relay

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Listen (Responder) | `responder-poison`, `credential_access` responder | ✅ | oscp | |
| NTLM relay SMB→LDAP(S) (add-computer/shadow/escalate/interactive) | `ntlm-relay-attack`, `coerce-auth` (`--delegate-access`) | 🟡 | oscp+ | relay-to-LDAP RBCD covered via coerce-auth; `--escalate-user`/`--shadow-credentials`/interactive shell variants not separate moves. |
| Relay to SMB (unsigned, gen-relay-list, socks) | `ntlm-relay-attack` | ✅ | oscp+ | |
| Relay to MSSQL | — | 🟡 | oscp+ | generic ntlmrelayx move; mssql target not spelled out. |
| Relay to HTTP → CA ESC8 / WSUS | `adcs-esc` (`--adcs`), `wsus-abuse` | ✅ | oscp+ | ESC8 relay. |
| MS08-068 self-relay | — | ⬜ | beyond | legacy. |
| Zerologon safe relay (dcsync://) | `zerologon-exploit` | 🟡 | beyond | direct exploit covered; relay-one-DC-to-another variant not. |
| Kerberos relay (krbrelayx) | — | ⬜ | beyond | |

## 11. trusts

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Trust enumeration (nltest / Get-DomainTrust / lookupsid) | `trust-enum` | ✅ | oscp+ | `_parse_domain_trusts`. |
| Child→Parent trust-key ticket | `sid-history-abuse`, `golden-ticket`, `trust-enum` | 🟡 | beyond | trust-key extraction step implicit. |
| Cross-domain Golden (raiseChild / ExtraSID-519) | `sid-history-abuse` (raiseChild), `golden-ticket` | ✅ | beyond | |
| Parent→Child | `sid-history-abuse` | 🟡 | beyond | same primitives. |
| External / forest trust (pw-reuse / foreign group / SID history / ADCS) | `sid-history-abuse` | 🟡 | beyond | SID-history covered; foreign-group + pw-reuse paths manual. |
| MSSQL trusted links (SQLServerLinkCrawl) | `database` / `lateral-exec` | 🟡 | oscp+ | not a dedicated crawl move. |

## 12. sccm — all `beyond` (SCCM/MECM takeover)

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Recon (sccmhunter find/show, ldeep sccm) | `sccm-enum` | ✅ | beyond | `_parse_sccm`. |
| Creds from PXE | — | ⬜ | beyond | |
| Relay on site systems | `coerce-auth` + `ntlm-relay-attack` (generic) | 🟡 | beyond | not SCCM-specific. |
| Force / automatic client push | — | ⬜ | beyond | |
| Loot creds (cmloot / SCCMSecrets / dploot sccm) | `sccm-enum` (smb) | 🟡 | beyond | DP looting partial. |
| Takeover → relay to MSSQL | — | ⬜ | beyond | |
| Policy-request creds (sccmwtf / SharpSCCM) | — | ⬜ | beyond | |
| Exec (SharpSCCM exec) | — | ⬜ | beyond | |

## 13. adcs — certificate-services abuse

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Enumeration (certutil / certify / certipy find / ldeep templates) | `adcs-esc` | ✅ | oscp+ | `-vulnerable`, `_parse_adcs`. |
| ESC1 (SAN UPN) | `adcs-esc` (`req -upn`) | ✅ | oscp+ | |
| ESC8 (web-enroll relay) | `adcs-esc` (`--adcs`), `coerce-auth` | ✅ | oscp+ | |
| ESC2 | `adcs-esc` (title "ESC1-11") | 🟡 | oscp+ | named in move but no per-template parameterization. |
| ESC3 (enrollment agent) | `adcs-esc` | 🟡 | oscp+ | `-on-behalf-of` not spelled out. |
| ESC4 (template ACL write) | `ad-acl-abuse` + `adcs-esc` | 🟡 | oscp+ | |
| ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) | `adcs-esc` | 🟡 | oscp+ | |
| ESC7 (manage CA / issue) | `adcs-esc` | 🟡 | beyond | |
| ESC11 (RPC ICPR relay) | `adcs-esc` | 🟡 | beyond | |
| ESC5 (PKI object ACL / golden cert) | — | ⬜ | beyond | |
| ESC9 / ESC10 (cert mapping) | `cert-authenticate` + `shadow-credentials` (partial path) | ⬜ | beyond | no mapping-abuse move. |
| ESC13 | — | ⬜ | beyond | |
| ESC14 | — | ⬜ | beyond | |
| ESC15 (app-policies) | — | ⬜ | beyond | |

## 14. persistence

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Add Domain Admin (`net group … /add`) | `ad-acl-abuse`, `windows-persistence` | ✅ | oscp | |
| Golden ticket | `golden-ticket` | ✅ | beyond | |
| Silver ticket | `silver-ticket` | ✅ | beyond | |
| Diamond ticket | `diamond-ticket` | ✅ | beyond | |
| Golden certificate | `adcs-esc` / `cert-authenticate` (path) | 🟡 | beyond | no `certipy forge` move. |
| DSRM | — | ⬜ | beyond | |
| Skeleton key | — | ⬜ | beyond | |
| Custom SSP | — | ⬜ | beyond | |
| Sapphire ticket | — | ⬜ | beyond | |
| DCShadow | — | ⬜ | beyond | |

## 15. know_vuln_auth — authenticated known-CVE chains

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| MS14-068 (PAC forge) | `ms14-068` | ✅ | beyond | goldenPac. |
| GPP cpassword (MS14-025) | `gpp-passwords` | ✅ | oscp | SYSVOL cpassword + gpp-decrypt. |
| noPac (CVE-2021-42278/42287) | `nopac` | ✅ | beyond | |
| PrintNightmare (CVE-2021-1675/34527) | `printnightmare` | ✅ | beyond | |
| Certifried (CVE-2022-26923) | `adcs-esc` + `cert-authenticate` (machine-cert path) | 🟡 | beyond | no dedicated account-create → machine-template move. |
| PrivExchange (CVE-2019-0724) | — | ⬜ | beyond | |
| ProxyNotShell (CVE-2022-41040/41082) | — | ⬜ | beyond | non-AD. |

## 16. low_access — local privilege escalation

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| Auto-enum (winPEAS / PrivescCheck) | `windows-enum` | ✅ | oscp | `_parse_winpeas` ships. |
| Search files (`findstr pass`) | `stored-credentials` | ✅ | oscp | |
| SeImpersonate (GodPotato/PrintSpoofer/RoguePotato) | `seimpersonate` | ✅ | **oscp (CORE)** | `whoami /priv` gate + potato. |
| SMBGhost (CVE-2020-0796) | `known_exploits` (reference) | 🟡 | oscp+ | catalog entry, no executable privesc move. |
| WebDAV → HTTP coerce | `coerce-auth` | 🟡 | oscp+ | coerce covered; local WebClient-enable chain not. |
| **UAC bypass (Fodhelper/wsreset/msdt)** | — | ⬜ | **oscp** | **CORE-OSCP Windows escalation, no move.** |
| AppLocker bypass (installutil/mshta/msbuild) | — | ⬜ | oscp+ | |
| HiveNightmare / SeriousSAM (CVE-2021-36934) | — | ⬜ | oscp+ | SAM via volume shadow copy. |
| Kerberos Relay (KrbRelayUp) | — | ⬜ | beyond | |

## 17. admin — post-admin credential extraction

| Technique | obol move id(s) | Cov | Scope | Note |
|---|---|---|---|---|
| LSASS extraction (mimikatz/procdump/lsassy/kiwi) | `dump-secrets`, `lsass-dump-onbox` | ✅ | oscp | `_parse_mimikatz` ships. |
| SAM extraction (nxc `--sam`/hashdump/reg save) | `dump-secrets`, `windows-old-hives` | ✅ | oscp | |
| LSA extraction (nxc `--lsa`/lsadump::lsa) | `dump-secrets` | ✅ | oscp | |
| DPAPI (nxc `--dpapi`/donpapi/SharpDPAPI/dploot) | `dpapi-secrets` | ✅ | oscp+ | impacket-dpapi. |
| Crack masterkey (DPAPImk2john) | `dpapi-secrets` + `cracking` | 🟡 | oscp+ | DPAPImk john format not a move. |
| Impersonate token (incognito / schtask_as / irs) | `seimpersonate` | 🟡 | oscp+ | potato covered; incognito token theft not. |
| Impersonate w/ ADCS (masky) | `adcs-esc` (path) | 🟡 | beyond | |
| Impersonate RDP session (tscon) | — | ⬜ | beyond | |
| KeePass extraction (KeePwn) | — | ⬜ | oscp+ | common loot, no move. |
| Hybrid Azure AD-Connect MSOL decrypt | — | ⬜ | beyond | |

---

## Headline gaps, prioritized (OSCP-first)

Ordered by exam leverage × build cost. "Add" = move (data) and/or parser (engine).

1. **UAC bypass — ⬜ CORE-OSCP, loudest gap.** Fodhelper / wsreset / msdt auto-elevation is a
   staple of the OSCP Windows local-escalation path and obol has **no move** for it. **Add a move**
   in `windows_privesc` (gated on a medium-integrity admin-group member, proven via a post-bypass
   `whoami`). No new parser needed — proof is the elevated shell.

2. **Crack-hash mode gaps — 🟡, cheap OSCP wins.** LM (`-m 3000`), NetNTLMv1 (`-m 5500`), and
   Kerberos TGS-AES128 (`-m 19600`) have no explicit move. `crack-identify` already routes them and
   the crack parser already mints `credential.*`. **Add three data-only moves** mirroring the
   existing `crack-*` shape — near-zero cost, directly exam-relevant.

3. **targetedKerberoast — 🟡, OSCP+ AD staple.** The "On-User GenericAll/GenericWrite → add SPN →
   roast" path is the single most common ACL-to-creds pivot in labs and only the ForceChangePassword
   half is covered. **Add a move** (`targetedKerberoast.py` / bloodyAD setSPN) producing `hash.tgs`
   — it feeds the existing `crack-tgs` and the TGS parser already ingests it. Move only.

4. **HiveNightmare / SeriousSAM (CVE-2021-36934) — ⬜, OSCP+ privesc.** SAM/SYSTEM via volume shadow
   copy is a frequent patch-gap win. **Add a move** producing `hash.ntlm`; the existing
   `windows-old-hives` secretsdump parser already ingests the `LOCAL` dump, so it's move-mostly.

5. **Per-ESC ADCS coverage — 🟡, OSCP+ and rising.** `adcs-esc` is one catch-all titled "ESC1-11";
   ESC2/ESC3/ESC4/ESC6/ESC7 lack per-case parameterization and ESC9/10/13/14/15 are absent.
   `certipy find -vulnerable` is already parsed (`_parse_adcs`), so this is **mostly move-data work**:
   split or parameterize the template/on-behalf-of/manage-CA sub-cases. Highest-value: ESC3 and ESC4.

**Runner-up (noted, lower priority):** constrained-delegation protocol-transition chain (🟡,
oscp+), NetNTLM relay `--escalate-user`/`--shadow-credentials` variants (🟡, oscp+), KeePass loot
(⬜, oscp+), incognito token impersonation (🟡, oscp+). Everything in the **sccm**, **trusts**,
most of **persistence**, and the exotic **adcs** ESC9-15 rows is correctly `beyond` and not an
OSCP-scope gap — leave them visible but unbuilt.

---

*This doc references the OCD mindmap **and** obol internals (move ids, pack layout, parser
dispatcher), so — exactly like `OCD-GAP-ANALYSIS.md` — it is **INTERNAL**. Do **not** port it to the
public mirror. OCD scoping reality: OCD's machine-readable source is AD-only, so it scopes the AD
move lane; non-AD breadth comes from obol's own packs. Coverage here is structure-verified (packs
loaded + fields searched; dispatcher read), never grep-guessed.*
