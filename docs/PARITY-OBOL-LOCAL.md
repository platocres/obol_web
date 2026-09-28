# obol-local ↔ obol-web — Bidirectional Improvement Map

`obol-local` (`platocres/obol-local`) is the terminal-first, on-box Python operator tool
(packs in `obol/packs/*.json` under the `actions` key, dynamic AD command builder in
`obol/bloodhound.py`, parsers in `obol/parsers/*.py`, template fill in `obol/board.py`).
`obol-web` is its static browser edition (packs in `data/packs/*.json`, AD builder in
`assets/engine/bloodhound.js`, parsers in `assets/engine/parsers/`, template fill in
`assets/engine/command.js`). Both carry the **same 2026_09 pack schema and metadata**, so
pack-JSON additions port directly as data. Command **execution** features are terminal-only
and intentionally do **NOT** port to the build-only web edition: cruise/autopwn/autopilot
(`obol/cruise.py`, `obol/autopilot*.py`, `obol/moves.py`), the live OOB HTTP catcher
(`obol/oob.py`), on-disk archive extraction (`obol/archives.py`), and paste-back ingest
(`obol/ingest.py`). None of these have any counterpart under `assets/engine/` (verified: no
`cruise`/`oob`/`archive`/`ingest`/`frontier`/`moves` module there).

All file:line and strings below were verified by opening the cited ranges in **both** repos
(obol-local @ `1a16fe9`-era source on disk; obol-web on disk).

---

## A. What obol-local can adopt FROM obol-web

**Nothing.** Every command-quality issue that obol-web fixed is already present (correct) in
obol-local, and every issue still open is open in **both** repos (see section C). On the 10
checkpoints from the command review, obol-local is at or ahead of obol-web — and strictly
ahead on two (delegation flag, dynamic-builder auth threading). Condensed evidence:

| # | Checkpoint | obol-local | obol-web | Verdict |
|---|---|---|---|---|
| 1 | sccmhunter auth | `ad:1559/1564` `sccmhunter.py find -u {{user}} -p '{{password}}' -d {{domain}} -dc-ip {{target}}` | `ad:1669/1674` identical | both correct (bare `-u`, separate `-d`) |
| 2 | Domain-tab evil-winrm/xfreerdp | `bloodhound.py:1045-1053` `-p '{pw}'` | `bloodhound.js:515-519` hardcoded `-p ''` | **both broken** (§C-2); local strictly ahead (interpolates pw) |
| 3 | Static DCSync `-just-dc` | pack `ad:1056` lacks it; builder `bloodhound.py:1037` has it | pack `ad:1087` lacks it; builder `bloodhound.js:508` has it | **both** miss it on the pack step (§C-3) |
| 4 | Golden ticket key | `ad:1395` `{{nthash}}` = first-cred hash (`board.py:252-256`) | `ad:1494` same (`command.js:121-131`) | **both broken** (§C-1) |
| 5 | ACL-abuse ordering | `ad:1753` set owner → `:1758` genericAll → `:1763` add dcsync | equivalent | both correct order |
| 6 | nxc delegation flag | `ad:910` `--trusted-for-delegation --find-delegation` | `ad:941` `--trusted-for-delegation` only | **local ahead** (adds `--find-delegation`) → §B |
| 7 | writable-GPO | `ad:2526` `bloodyAD … get writable` (no bogus nxc `-M gpo_privesc`) | `ad:2689` `bloodyAD … get writable --detail` | both correct |
| 8 | getST/psexec SPN | `ad:1810/1815/1820` psexec target `{{spn_host}}` matches minted `cifs/{{spn_host}}` | `ad:1950` same `{{spn_host}}` | both correct |
| 9 | literal `<…>` placeholders | intentional operator-fill (`bloodhound.py:1021-1022`) | same placeholders | N/A — by design |
| 10 | bare `{{password}}` | quoted at fill via `_SHELL_VALUE_TOKENS` (`board.py:367,389`) | same guard (`command.js:15,280`) | N/A — mitigated |

No port candidates invented to pad this section; there genuinely are none.

---

## B. What obol-web can adopt FROM obol-local

All items below were verified **absent** from obol-web (`data/packs/*.json`,
`assets/engine/parsers/`, `assets/engine/pack.js` FRIENDLY). Pack data ports as-is;
parsers need a JS regex equivalent.

### New moves

| Move | obol-local source | web has? | Effort / notes |
|---|---|---|---|
| `crack-archive` | `cracking_2026_09.json:24`; cmds `:37` `zip2john archive.zip > archive.hash`, `:38` rar2john, `:39` 7z2john, `:40` `john --wordlist=/usr/share/wordlists/rockyou.txt archive.hash`; `autonomy:"auto"`, `requires_any:["loot.material"]` | no | **trivial** (data). Drop the `obol ingest --archive` re-scan callback (`:40` note) — extraction is terminal-only (`obol/archives.py`). |
| `param-discovery` | `web_2026_09.json:8`; cmds `:38` `arjun -u http://{{target}}/ -m GET,POST`, `:43` `arjun … -w …/burp-parameter-names.txt`; `produces:["web.param_candidate"]` | no | **trivial** (data) + register `arjun` tool; pairs with arjun parser below. |
| `windows-old-hives` | `windows_privesc_2026_09.json:517` (action, `autonomy:"approve"`, `produces:["credential.candidate","hash.ntlm","loot.files"]`); cmds `:553` `dir /a C:\ | findstr /i windows.old`, `:558` `reg save HKLM\SAM %TEMP%\SAM.hive & …`, `:563` `impacket-secretsdump -sam SAM.hive -system SYSTEM.hive -security SECURITY.hive LOCAL`, `:568` `impacket-secretsdump {{domain}}/{{user}}:'{{password}}'@{{target}}`. Also a coach-script variant `scripts_2026_09.json:562`. | no | **trivial** (data, both objects). |

### New scripts / known_exploits

New coach-scripts in `scripts_2026_09.json` (all **trivial** data ports — methodology text +
command blocks, not executed by web):

- `:449` `snmp-community-enum` — SNMP community mining (`snmpbulkwalk -c public -v2c`, onesixtyone, users/process OIDs).
- `:489` `suid-path-hijack` — SUID relative-command PATH hijack → `access.root`.
- `:526` `screen-suid-4506` — GNU Screen 4.5.0 setuid root (CVE-2017-5618 / EDB-41154).
- `:603` `mssql-xpcmdshell-shell` — MSSQL `xp_cmdshell` → reverse shell as SQL service account.
- `:640` `seimpersonate-potato` — SeImpersonate → SYSTEM via PrintSpoofer/GodPotato. **Caveat:** obol-web has key `seimpersonate-potato` only in `findings_catalog_2026_09.json` (a *finding definition*), NOT this script — different objects, still needs porting.
- `:677` `tar-wildcard-injection` — tar `--checkpoint-action` wildcard injection via root cron.

New `vulnmatch` exploit cards in `known_exploits_2026_09.json` (all **trivial** data;
obol-web already surfaces `known_exploits` cards and never auto-fires, matching its model):

- `:832` `text4shell` (CVE-2022-42889) · `:871` `freeswitch-event-socket` (EDB-47799, ClueCon default on 8021) · `:905` `jdwp-debug` (JDWP RCE) · `:942` `usermin-authrce` (EDB-50234, port 20000) · `:972` `aerospike-udf` (CVE-2020-13151; the PoC git-clone staging in `obol/provision.py` is terminal-only, but the card ports) · `:1001` `wifi-mouse-rce` (EDB-50972, port 1978).

### Enhanced commands

| Enhancement | obol-local | obol-web current | Effort |
|---|---|---|---|
| AD recon rustscan accelerant | `ad_2026_09.json:44` `rustscan -a {{target}} --ulimit 5000 -- -sV -oN nmap-allports.txt` | absent | **trivial** (data) + register `rustscan` tool |
| nxc delegation flag | `ad_2026_09.json:910` `… --trusted-for-delegation --find-delegation` | `ad:941` `--trusted-for-delegation` only | **trivial** (add `--find-delegation`) |
| PuTTY/WinSCP stored-cred hunt | `windows_privesc_2026_09.json:349` `reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s`, `:354` `reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s 2>nul` | absent | **trivial** (data) |
| `produces` widening | `recon_2026_09.json:73` snmp now `["snmp.community","snmp.info","ad.user_list","credential.candidate"]`; ad sccm move `:1544` adds `sccm.enumerated` | narrower | **trivial** (data) |

> Note: the Kerberos-ccache psexec SPN fix flagged by the prior inventory is **already at
> parity** — obol-web `ad:1950` `impacket-psexec -k -no-pass '{{spn_host}}'` already uses
> `{{spn_host}}`. No port needed there.

### New parsers (port as JS regex into `assets/engine/parsers/*.js` — **parser-needed** effort)

All verified absent from the web engine (no `param_candidate`/`notable_program`/`vcs_token`/
`connection_uri`/`exposed_artifact`/`domain_control`/`putty_registry`/`winscp`/
`exposed-sqlite`/`cracked_secret`/`snmp-process` markers anywhere under `assets/engine/`).

| Parser | obol-local | Produces | Port to |
|---|---|---|---|
| SNMP loot | `services.py` `_parse_snmp_output` | `ad.user_list` (LanMan users table `77.1.2.25.1.1.*`), `credential.candidate {via:"snmp-process"}` (process-args pw) | `parsers/services.js` (has basic SNMP, lacks loot logic) |
| SQLite dump | `services.py` `_parse_sqlite_dump` | `credential.candidate {via:"exposed-sqlite"}` | `parsers/services.js` |
| Notable-program | `host.py` `_parse_notable_programs` | `host.notable_program` | `parsers/host.js` (the inspect *move* is engine-only; parser ports) |
| PuTTY/WinSCP/plink creds | `host.py` `_PUTTY_PROXYPW_RE`, plink `-pw` regex, `simontatham`/`winscp`/`vncpassword` markers | `credential.candidate {via:"putty_registry"}` | `parsers/host.js` (pairs with the reg-query move) |
| VCS-token / URI / framework-config secrets | `websource.py` `_parse_source_secret` (`_VCS_TOKEN_RE` `ghp_`/`glpat-`, `_URI_CRED_RE`, PHP/WP/.env pw) | `credential.candidate {kind:"vcs_token"/"connection_uri"}` | `parsers/websource.js` (has none) |
| john LIVE cracked line | `creds.py`/`_common.py` `_JOHN_CRACKED_LIVE_RE` | `credential.candidate {kind:"cracked_secret"}` | `parsers/creds.js` (closes archive-crack loop) |
| arjun | `web.py` `_parse_arjun` | `web.param_candidate` | `parsers/web.js` (pairs with `param-discovery`) |
| exposed-artifact classifier | `web.py` `_exposed_artifacts`/`_classify_artifact` | `web.exposed_artifact` | `parsers/web.js` (the fetch-and-loot *consumer* is engine-only) |
| sccmhunter null-match | `ad_extra.py` `_parse_sccm` | `sccm.enumerated {present:false/true}` | `parsers/` (careful anchoring so a query-desc line isn't a hit) |
| bloodyAD domain-control | `ad.py` `_parse_bloodyad_domain_control` | `ad.domain_control {principal,right}` | `parsers/` (earned DACL evidence vs hardcoded assumption) |

**Do NOT port:** `_parse_oob_callback` (`web.py`) — parses obol's own live catcher; obol-web
never runs the catcher and has no paste-back ingest path.

### New friendly fact-kind labels

`obol/pack.py` `_FRIENDLY` gained labels absent from `assets/engine/pack.js` FRIENDLY
(verified 0 hits in pack.js for each) — **trivial** data port for honest reporting:
`sccm.enumerated`, `mssql.reachable`, `mssql.authenticated`, `access.root`,
`privesc.script_sink`, `host.notable_program`, `host.program_inspected`, `lead.stalled`,
`web.exposed_artifact`, `web.artifact_looted`, `web.param_candidate`, `web.params_discovered`,
`web.param_probed`, `web.injectable_param`, `web.param_exploited`.

---

## C. Shared defects (present in BOTH; need a fresh fix in each)

All three reproduce in current source of both repos.

### C-1. Golden ticket forges with the wrong key
- **obol-local:** `obol/packs/ad_2026_09.json:1395` `impacket-ticketer -nthash {{nthash}} -domain-sid {{domain_sid}} -domain {{domain}} administrator`. `{{nthash}}` is filled from the **first validated credential's** `nthash`/`hash` (`obol/board.py:252-256`), not the krbtgt key. The correct key **exists** as fact `hash.krbtgt` (`obol/parsers/creds.py:238`) but is wired to no token.
- **obol-web:** `data/packs/ad_2026_09.json:1494` identical string; `assets/engine/command.js:121-131` fills `ctx.nthash` from the first credential the same way.
- **Fix (both):** add a dedicated `{{krbtgt_hash}}` token fed from the `hash.krbtgt` fact and use it in the golden-ticket command; fall back to a `<krbtgt-nt-hash>` placeholder when the fact is absent. (The diamond-ticket path `ad:2481` correctly uses a separate `/krbkey:` slot — leave it.)

### C-2. Domain-tab evil-winrm/xfreerdp blank password for a hash-only identity
- **obol-local:** `obol/bloodhound.py:1045` `xfreerdp /u:{u} /p:'{pw}' /v:<HOST> /cert:ignore`, `:1047` `evil-winrm -i <HOST> -u {u} -p '{pw}'`, and the `rdp_reach`/`psremote_reach` twins `:1051`/`:1053`. With `pw = cred.get("password") or ""` (`:1025`), a hash-only identity renders `-p ''` / `/p:''` and fails; these never emit `-H {nt}` / `/pth:{nt}`. (The nxc variant in the same buckets is correct via `_nxc_auth` `:264-267`.)
- **obol-web:** worse — `assets/engine/bloodhound.js:515,516,518,519` hardcode literal `/p:''` and `-p ''` with no `pw` interpolation at all.
- **Fix (both):** branch on the identity — `evil-winrm … -H {nt}` and `xfreerdp … /pth:{nt}` when hash-only, mirroring `_nxc_auth`. obol-web additionally needs to interpolate the password/secret at all.

### C-3. Static DCSync command missing `-just-dc`
- **obol-local:** `obol/packs/ad_2026_09.json:1056` `impacket-secretsdump '{{domain}}/{{user}}:{{password}}'@{{target}}` (and the sibling at `:1005`). The note still claims automatic DRSUAPI fallback; without `-just-dc` secretsdump attempts a local SAM/LSA read first.
- **obol-web:** `data/packs/ad_2026_09.json:1087` (and `:1036`) identical.
- Both **dynamic builders already emit it** (`bloodhound.py:1037`, `bloodhound.js:508`), so this is only the pack step.
- **Fix (both):** append `-just-dc` to the primary DCSync pack command to force the replication path.

---

## D. Suggested port order (highest value / lowest effort first)

1. **Fix the 3 shared defects (C-1, C-2, C-3)** in obol-web (and file the same fixes for obol-local). C-3 is a one-token append; C-2 is a `-H`/`/pth` branch; C-1 needs one new token — all high value, low effort.
2. **Trivial enhanced-command edits** (data): add `--find-delegation` (`ad:941`), the rustscan accelerant, the PuTTY/WinSCP reg-query commands, and the `produces` widenings.
3. **Bulk data ports:** the 3 new moves, 6 scripts, 6 known_exploits cards, and the 15 FRIENDLY labels — pure JSON/label additions.
4. **arjun tool + `param-discovery` move + arjun parser** together (small, self-contained loop).
5. **Credential-bearing parsers first** (highest analytic value): VCS-token/URI/config (`websource.js`), PuTTY/WinSCP (`host.js`), sqlite-dump + SNMP-loot (`services.js`), john-live-crack (`creds.js`).
6. **Remaining parsers:** sccmhunter null-match, bloodyAD domain-control, notable-program, exposed-artifact classifier.
7. **Skip** everything tied to terminal execution: cruise/autopwn/autopilot, the OOB catcher and `_parse_oob_callback`, on-disk archive extraction, ingest, `frontier_moves`, `webprobe.py`, PoC provisioning.
