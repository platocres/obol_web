# Corpus Mining Ledger

> **Read this before you mine anything. Update it in the same change, right after you do.**
> This is the single running record of what mining has been done, how thoroughly, and what was
> derived from it, so that no agent (on any platform, in any chat) redoes work another agent
> already finished. The method and rationale live in [CORPUS-MINING.md](CORPUS-MINING.md); this
> file is the log.
>
> **The rule, for every agent:**
> 1. Before you mine a source, find its entry below and read its Axes and Status. Do not
>    re-mine an axis already marked DONE.
> 2. After you mine, update or add the entry in the same change: what you took, how thoroughly
>    (which axes), what you derived, and the date. If it is not logged here, the next agent will
>    assume it was never done.

## Centralized Corpus Root

All pulled data lives together under one local root so it is never scattered or re-fetched:
`E:\KaliFiles\obol\obol-site\corpus\` is the canonical store going forward. Each source gets one
subfolder (for example `corpus\0xdf-offsec-2026-08-20\`), and this ledger is that store's index:
every subfolder has a Sources entry below.

**The agent does the pulling and the tracking.** When a planned source is acquired, the agent
fetches it into the corpus root, records the pull here (source, date, scope, how obtained), and
only then mines it. Existing pulls predate this convention and still sit at their original paths
(`0xdf-offsec-complete-2026-08-20\` beside `qa\`, and the screenshot queues in `qa\Testing\`);
consolidating them under `corpus\` is a pending, path-sensitive step (tools reference the current
paths) to be done deliberately, not silently.

## The Four Axes (The Whole-Asset Rule)

Every source is mined along four axes. A source is only DONE when all four are taken. We may
process an asset in stages, but we never abandon it half-mined.

- **output**: raw tool output captured as parser input.
- **facts**: what each output should mint (the ground truth the parser is measured against).
- **failures**: error and negative-output strings and their meaning (for `FIELD_DOCTORS` and
  the blockers parser).
- **flow**: the move sequence and the command combinations inside each move (banked for the
  move and ordering audit, now spent: Stage 7 2026-10-23 found coverage complete and ordering
  faithful, enforced by eligibility gates; feeds Pillar 4.1). The vision / screenshot tier was
  deep-audited in Stage 3 (2026-10-23): a 194-walkthrough structural context sweep (2396 captures)
  and 75-image visual inspection across 63 boxes proved that while ~75% of screenshots are pure web
  GUI, 25.3% of inspected screenshots (38.0% of high-suspicion captures lacking an adjacent code
  block) carry unique terminal output, Jenkins Groovy/Pipeline scripts, webshell execution, or Burp
  Repeater payloads; 19 validated `fidelity: 'ocr'` records are now locked in
  `qa/tools/corpus/labels/0xdf-screenshots-ocr.json` and `harvest-screenshots.js --candidates`
  surfaces the 382 high-signal no-adjacent-code captures directly.

Axis status values: `DONE (date)`, `PARTIAL (date, note)`, or `NOT YET`.

---

## Sources

### 0xdf OffSec Collection (Snapshot 2026-08-20)

- **Location**: `E:\KaliFiles\obol\obol-site\0xdf-offsec-complete-2026-08-20\` (local, about
  352 MB). Source index: `https://0xdf.gitlab.io/cheatsheets/offsec`.
- **Scale**: 194 walkthroughs, each saved as HTML and Markdown in `walkthroughs/`; per-box
  screenshots in `assets/<slug>/` with SHA-256 checksums and original URLs. Inventory:
  `corpus-manifest.json` (194 completed, 0 failed).
- **Axes mined**:
  - **output**: DONE (2026-10-23; Stages 0-7 complete, 97.5% actionable enumeration coverage across 1842 units). Deterministic sweep done and sharpened:
    `qa/tools/corpus/harvest-markdown.js` segments every console block into command units
    (split on real shell prompts) and runs each through the real parser. Report:
    `qa/tools/corpus/reports/0xdf-blindspots.json`. Trustworthy signal is the fact-bearing
    tools only (enumeration/exploitation output we expect to mint): 2153 units with output,
    70% mint, 30% blind (642 units). Mature parsers confirm the method (nmap 1% blind, netexec
    2%, secretsdump 5%). Top actionable gaps by blind count: smbclient, curl, dns, gobuster,
    mysql, feroxbuster, certipy, mssql, smbmap, rpcclient. Known inflation to correct next:
    smbclient (Impacket login banners are factless launches; real listings are in the following
    `smb: \>` units) and curl (mixes web content with file-reads and PowerShell-alias failures).
    DE-INFLATED IN THE SWEEP (2026-10-23, Stage 2 classification cleanup): that smbclient/curl
    inflation is now corrected inside `harvest-markdown.js` itself, so the persisted ranking no
    longer falsely crowns the two multi-purpose primitives as the top gaps. Both stay fact-bearing
    (their real output already mints: smbclient interactive ls/dir via `_parse_share_inventory` ->
    loot.files, curl web pages via the web parser -> web.*/http.*), so a MINTED unit is real
    coverage and is never reclassified. Only BLIND residue moves out, gated on independent content
    signatures (never on mint status) by a new `rankingLabel`: smbclient connect/login banners with
    no listing -> `smbclient-launch`, smbclient REPL put/get/cd navigation -> `smbclient-xfer`; curl
    file downloads/redirects -> `curl-xfer`, PowerShell curl-alias errors -> `curl-fail`, raw app
    payloads / file / API bodies with no web-enumeration envelope -> `curl-read`. A blind curl that
    DOES carry an HTTP/HTML envelope, and smbclient `-L` share-lists / `-c` one-shots, stay counted
    as genuine gaps, so nothing real is hidden. The residue buckets are emitted as explicit
    non-fact-bearing rows in the report (self-documenting; re-running the sweep reproduces them).
    Result (fact-bearing rows): smbclient blind 110 -> 31 (blindRate 0.42 -> 0.17), minted 149
    unchanged; curl blind 105 -> 0, minted 138 unchanged (all blind curl was content/transfer/alias
    residue). Actionable aggregate blind 537 -> 314, mint rate 74% -> 83%. The honest top enumeration
    gaps now surface: mysql (39), feroxbuster (36), certipy (31), smbclient (31), smbmap (27), mssql
    (26). qa-only tooling change (no engine/parser edit, so no stamp-assets); the axis report
    (`0xdf-axes.json`) is untouched because the axis tally still keys on the real tool label.
    Confirmed real gaps spotted: gobuster v2.0.1 old `=====` format (found paths not parsed) and
    `dig` A-records (not minted). Failure-axis leads also surfaced (dig axfr "Transfer failed",
    curl 404/resolution errors). Fixtures and parser fixes not yet derived.
    FIXED (2026-10-23, Stage 5 parser hardening): the gobuster v2.0.1 gap was a DISPATCH miss, not a
    regex miss. `_WEB_GOBUSTER_RE` already parsed `/path (Status: NNN)`, but when a found-path block
    was pasted without the command line, the shape sniff in `assets/engine/parsers/index.js` required
    the modern `[Size: N]` suffix and the old (Status)-only lines fell through unparsed. Broadened the
    sniff to `[Found: ][http://host]/path (Status: NNN)` with zero or more trailing bracket groups,
    anchored to end-of-line so mid-sentence prose does not false-positive (old, 3.x `[Size]`, and
    redirect `[--> url]` forms all covered). No new fact kind (reuses `web.content_map`), so no
    parser-signatures or decisionmap change. Locked by `tests/engine/web-content-paths-smoke.js`
    (7 assertions, corpus-free).
    FIXED (2026-10-23, Stage 5 parser hardening): the `dig` A-record gap. A plain forward lookup
    (dig/host/nslookup resolving one name to an address) is not a zone transfer, so it never met the
    `dns.zone` receipt's >=2-record floor and `_parse_dns` minted nothing at all. Added a new terminal
    kind `dns.a_record` {name, ip} minted for a single forward resolution (scoped to the resolved host),
    WITHOUT raising the `dns.zone` "Zone Transfer Permitted" medium finding; a real multi-record AXFR
    still mints `dns.zone` and does not also emit per-record a_records, and a DC resolution stays
    `ad.dc_candidate`. Registered in `data/parser-signatures.js` (internal-dns emits) and the recon-dns
    move's `produces`; terminal via decisionmap's `dns.` class, so gap-report stays at 0 orphans. Locked
    by `tests/engine/dns-a-record-smoke.js` (11 assertions, corpus-free). Remaining sub-gap: `dig +short`
    bare-IP output carries no name (the queried name is only on the command line), so it still mints
    nothing; closing it would mean correlating command and output across `_parse_dns`'s call sites.
    No named output-axis gaps remain open; `dig +short` is the one tracked sub-gap.
    HARVESTER FIDELITY (2026-10-23, Stage 5, qa-only, no stamp): the mysql/mssql/rpcclient blind counts
    were inflated the same way the smbclient/curl counts were, by a harvester-vs-product mismatch rather
    than a pure engine gap. The product's `assets/ui/ingest.js` `_promptCmd` prepends the sub-shell tool
    token to a REPL command (`mysql> show tables;` becomes the command string `mysql show tables;`), which
    is what `parsers/index.js` dispatches on; the harvester segmented the same prompts but passed the bare
    REPL command, so the sub-parser was never reached and real listings read as FALSE blinds. Mirrored the
    product in `tools/corpus/harvest-markdown.js`: each REPL `PROMPTS` entry now carries a `prefix`, and a
    new `_applyPrefix` helper prepends it in `matchPrompt` (idempotent: it skips when the token is already
    present). `SMB_REPL_XFER` was loosened to tolerate the now-prepended `smbclient ` so the smbclient-xfer
    de-inflation bucketing still holds. This recovered about 10 false blinds across the REPL tools and is a
    measurement fix only (no engine/parser edit here), so the axis report is unaffected and nothing is
    stamped.
    FIXED (2026-10-23, Stage 5 parser hardening, SHIPPED engine change): interactive `show databases;` /
    `show tables;` output now mints `db.databases` / `db.tables`. The database parser's signature already
    DECLARED these emits (`data/parser-signatures.js`), with a labeled FRIENDLY entry and a live consumer
    (the `crack-identify` move's `requires_any`), but the interactive `database.js` path never produced
    them, so a schema inventory (the map of what to loot next) read as a blind unit. `_parse_database_output`
    now, when the command is a `show databases/schemas` or `show tables` verb, pulls the single-column
    inventory via a new `_db_listing_names` helper that reads both shapes the clients print (the boxed ASCII
    grid `| name |` rows, and the bare newline list a one-shot `mysql -e` prints), drops the header labels
    (`Database`, `Tables_in_<db>`) and the status/warning lines, and mints the matching kind (capped at 50,
    attributed to the detected client). It is gated on the inventory verb AND a single-column shape, so a
    multi-column `describe`/`select` grid, an empty set, and a `Query OK` DDL acknowledgement all mint
    nothing (no false positives). No new fact kind, so no parser-signatures or decisionmap change. Locked by
    `tests/engine/db-listing-parser-smoke.js` (15 assertions, corpus-free, incl. the false-positive guards
    and a live-consumer assertion). Corpus effect (fact-bearing rows, after the harvester-fidelity fix
    above): mysql minted 22 -> 28, blind 31 -> 25 (blindRate 0.47); actionable aggregate blind 304 -> 298.
    FIXED (2026-10-23, Stage 5 parser hardening, SHIPPED engine change): raw rpcclient SID/name resolution
    and single-object detail dumps now feed the existing `ad.user_list` / `ad.group_list` facts. Dispatch
    already routed every `rpcclient` sub-command to `_parse_rid_user_list` (directory.js), but that function
    read usernames only via `_rid_usernames`, which matches the `(SidTypeUser)` and `user:[x] rid:[y]`
    shapes nxc/enum4linux-ng relabel to, never the raw interactive residue of an `rpcclient $>` session (or
    a RID-cycling loop). A new `_rpc_resolution(text)` helper reads the four raw shapes the client prints:
    `lookupsids` (`<SID> DOMAIN\name (type)`, classified by SID_NAME_USE type: 1 = user, 2/4/5 = group),
    `lookupnames` (`<name> <SID> (Label: type)`, classified by the explicit label), `queryuser`
    (`User Name : <name>`), and `querygroup` (`Group Name : <name>`). Resolved users merge into the
    `ad.user_list` the function already mints (the sprayable/roastable pivot, 5 live consumers: asrep-roast,
    password-spray, online-brute-ssh/ftp/rdp) and resolved groups into `ad.group_list`. `*unknown*`
    resolutions, non-user/-group SID classes (Domain/Invalid/Unknown), machine accounts (trailing `$`, kept
    out by `_valid_username(name, false)`), and `NT_STATUS_NONE_MAPPED` failures carry no sprayable name and
    mint nothing (no false positives). No new fact kind (both were already declared at
    `data/parser-signatures.js`), so no signature or decisionmap change; `gap-report` stays at
    `orphanParserFacts: 0`. Locked by `tests/engine/rpc-resolution-parser-smoke.js` (14 assertions,
    corpus-free, incl. the machine-account / *unknown* / NONE_MAPPED guards and a no-regression merge of
    enumdomusers rows + a lookupsids resolution). Corpus effect (fact-bearing rows): rpcclient minted 6 ->
    12, blind 15 -> 9 (blindRate 0.71 -> 0.43); actionable aggregate blind 298 -> 292.
    FIXED (2026-10-23, Stage 5 parser hardening, SHIPPED engine change): feroxbuster plain-text result
    rows now feed the existing `web.content_map` fact across both output formats. Dispatch and the
    `_WEB_FEROX_RE` regex already existed, but the regex required a method column (`\w+`) between the
    status code and the line count. Newer feroxbuster builds print one (`200  GET  6l  77w  3351c  URL`),
    while older/default output omits it (`301  9l  28w  313c  URL`), so every result-bearing walkthrough
    on the no-method format (fingerprint, sense, writer, pikaboo, love, dynstr, and more) read as blind
    even though the paths were right there. The fix makes the method optional and uses `[A-Za-z]+` (not
    `\w+`) for it, so when absent the group matches empty instead of swallowing the leading `9l` line
    count: `common.js` `_WEB_FEROX_RE`, plus the same widening in the `index.js` text-shape dispatch
    fallback (for a bare result paste with no command line). Pure regex-widening into an established fact
    (`web.content_map`, 8 live downstream consumers), so no new fact kind and no signature or decisionmap
    change; `gap-report` stays at `orphanParserFacts: 0`. 404 rows, scan progress bars
    (`[####] ... found:11 errors:0`), and a banner/config-only paste with no result rows still mint
    nothing (no false positives). Locked by `tests/engine/feroxbuster-nomethod-parser-smoke.js` (9
    assertions, corpus-free, incl. the 404-drop, redirect-source, progress-bar-junk, and
    banner-only-mints-nothing guards). Corpus effect: feroxbuster minted 51 -> 80, blind 36 -> 7
    (blindRate 0.41 -> 0.08, now level with gobuster); actionable aggregate blind 292 -> 263. The
    remaining 7 feroxbuster blinds are all genuinely banner-only or 0xdf-snipped blocks (jail, jeeves,
    luanne, object, monitors, and fulcrum's empty `-x asp,aspx` run) with no result rows to mint.
    FOLLOW-UP CANDIDATES, honest and open (2026-10-23): (1) rpcclient's remaining residue after the fix
    above is `querygroupmem` (member RID lists with no names in the same unit; resolving them needs
    cross-unit correlation with a `queryuser`/`lookupsids` pass, so no name to mint standalone), the
    `setuserinfo2` -> `NT_STATUS_PASSWORD_RESTRICTION` failure-axis units, and the rare `enumprinters`
    comment password leak (loot axis). (2) a mysql/mssql `select` of a users table that returns hash columns
    could widen into a `credential.candidate` dump; set aside here to keep this change tight (minting new
    credential shapes needs its own forbidden-kind guards).
    ACTIONABLE BLIND SWEEP COMPLETED (2026-10-23, Stage 5 & 6 completion): triaged all 263 remaining
    actionable blind units across the 194 walkthroughs and closed every recurring parser and blocker gap:
    `dns.js` (`dig +short` hostname/PTR correlation), `directory.js` (`certipy req` cert/key receipt,
    `ESC7`, `certipy account read` base DN, SMB compressed `Dc`/`Ac` rows, single-file `ls`, NTFS ADS
    `:Name:$DATA`, piped `smbclient -L`, `putting file` transfer receipt, `smbmap` session/auth/access
    blockers, `rpcclient` password change confirmation + `querygroupmem` 0x1f4 + piped `nxc --rid-brute`
    bare user lists, `bloodhound-python` completion without `--zip`), `database.js` (Drupal `$S$` and
    Django `pbkdf2_sha256$` hashes, reversed hash/user columns, `master.sys.databases`, `CONTROL SERVER` /
    `IMPERSONATE ANY LOGIN` / `SYS DBA` -> `db.admin`), `creds.js` (`$ansible$`, `$PEM$`, `.psafe3`,
    96-hex/salted NTLM, optional-user IPMI RAKP, wrapped `$krb5*` lines), `web.js` (`sqlmap` ASCII
    `[N tables]` and `--dump` grids, `FILE` privilege -> `db.admin`), `host.js` (`neofetch`/`hostnamectl`
    OS & kernel, Spanish `whoami /priv` `Habilitada`), `blockers.js` (`blocker.password_restriction`,
    expanded `blocker.certutil_usage`, `blocker.access_denied`, `blocker.logon_failure`,
    `blocker.name_resolution`, `blocker.tls_scheme`, `blocker.hash_format`, `blocker.kerberos_spn`,
    `blocker.web_wildcard`, `blocker.ldap_anonymous_disabled`, `blocker.cracking_exhausted`,
    `blocker.dcsync_denied`), and `harvest-markdown.js` (command-head `detectTool` token matching so
    `-u john` / `git clone NetExec` / `ls /usr/share/nmap` are not misclassified, plus content-gated
    true-negative residue buckets for 0-hit web fuzzing, empty SMB dirs, and negative AD checks).
    Actionable enumeration coverage across the 194 walkthroughs reached 1796 minted / 46 blind of 1842
    units (97.5% coverage; 0 blind on `feroxbuster` 80/80, `gobuster` 69/69, `ffuf` 10/10, `curl`
    138/138, `secretsdump` 20/20, `bloodhound` 19/19, `john` 16/16, `kerbrute` 7/7, `GetNPUsers` 6/6,
    `GetUserSPNs` 6/6, `wpscan` 5/5, `postgres` 3/3, `hydra` 3/3). Locked corpus-free by
    `tests/engine/stage5-corpus-remining-smoke.js`.
    CORRECTION (2026-10-22): excluding navigational, file-read, and shell-launch units applies to
    the ENUMERATION ranking only, not to scope. Those outputs carry other signal axes we will
    measure next, using the surrounding walkthrough prose as ground truth for whether the output
    mattered: (2) state-change (you now have a shell on host X as user Y, which should flip
    on-host suggestions), (3) loot-in-content (a cat/ls that reveals a key, flag, or config
    secret; low base rate, so a curated high-value pattern catalog, not arbitrary file parsing),
    and (4) outcome (did a suggested transfer or auth succeed or fail, feeding success-advance and
    failure-doctoring). Nothing here is dismissed; it is measured per axis before we decide scope.
    MEASURED (2026-10-22, report `qa/tools/corpus/reports/0xdf-axes.json`): per axis, with the
    walkthrough prose as oracle, opportunity = a materiality cue fired AND OBOL minted nothing.
    state-change: 1681 units with output, 508 minted, 539 opportunities. loot: 1339 / 138 minted /
    601 opportunities. outcome: 248 / 123 minted / 70 opportunities. These three axes hold about
    1200 prose-confirmed opportunities, rivaling the 598 enumeration blind spots, so the earlier
    exclusion would have missed roughly half the total value. Clearest concrete wins: flag-file
    reads (`type`/`cat user.txt` and `root.txt` yield the flag value but mint nothing),
    credential-file reads (a `curl` of a credentials file), and command-failure doctoring (a
    `certutil` usage error). Caveats: some state-change hits are likely already covered by the
    initial-access move's own proof, and the prose cues are broad, so the counts are candidates
    pending human review of the samples.
    DE-INFLATED + FIRST OUTPUT-AXIS FIX SHIPPED (2026-10-22): the top three raw blind tools were
    split banner-from-residue (scratch: deinflate-dump.js over the blind units). Findings: netcat
    (253 raw) is about 83% reverse-shell listener catches (state-change, not enumeration) plus
    idiosyncratic banners; curl (105 raw) is about 93% box-specific app payloads and overlaps the
    already-covered flag/cred machinery; smbclient (171 raw) carried about 60 factless Impacket
    login banners, leaving its interactive "smb: \>" ls/dir directory listings as the single
    biggest real, patterned, high-value residue (leverage lens: smbclient is a weak high-use
    parser). Built it: _parse_share_inventory now has a branch for the interactive listing format
    ("name ATTR size Day Mon DD HH:MM:SS YYYY" rows plus the "." / ".." self entries and the
    blocks-of-size footer), feeding the existing loot.files fact (no new kind). index.js sniffs the
    output so a unit whose command is just "ls"/"dir" (no tool token) still routes to the parser.
    Corpus gain: of 145 interactive smbclient units with output, 106 now mint loot.files (119 mint
    any fact); the rest are correctly inert (put/mput uploads, empty dirs, navigation). HTB Active's
    GPP Groups.xml lead is now flagged sensitive. Files: assets/engine/parsers/directory.js
    (_SMB_LS_ROW_RE/_SMB_LS_FOOTER_RE + branch), assets/engine/parsers/index.js (dispatch sniff),
    tests/engine/smb-ls-parser-smoke.js (regression, 12 cases incl. false-positive guards). Gauntlet
    with the change: build-packs/flag-paths clean, gap-report parser corpus 81/81, post-parse-audit
    and move-lint and gate-audit 0 FAIL, rankers 0 violations, all engine suites pass.
    SECOND OUTPUT-AXIS FIX SHIPPED (2026-10-22): native on-host directory listings now mint
    loot.files. The loot axis (601 prose-confirmed opportunities, the largest of the three) was the
    lead, and native shell listings were the biggest patterned residue after smbclient: cmd "dir"
    ("Directory of C:\path" plus dated `"MM/DD/YYYY HH:MM AM  <size|<DIR>>  name"` rows), PowerShell
    Get-ChildItem ("Mode  LastWriteTime  Length Name" table), and Invoke-Command { ls } (the same
    table with a trailing PSComputerName column). These carry no tool token on the unit command
    (just "dir"/"ls"/"gci"), so index.js sniffs the header anchors and the new _parse_fs_listing
    anchors each file row to its "Directory of"/"Directory:" header, feeding the existing loot.files
    fact (no new kind). SMB-share and shell-listing minting now share one _emit_file_loot helper, so
    sensitive-name flagging, GPP cpassword extraction, and config.review emission are identical on
    both paths. A bare date line, a bare mode row, an empty header, or inline prose mints nothing.
    Files: assets/engine/parsers/directory.js (_parse_fs_listing + _emit_file_loot refactor),
    assets/engine/parsers/index.js (dispatch sniff), data/parser-signatures.js (prose),
    tests/engine/win-dir-parser-smoke.js (regression, 20 cases incl. false-positive guards). Full
    gauntlet 100% green: build-packs/flag-paths, gap-report, post-parse-audit, move-lint, gate-audit,
    field-notes-coverage, lint-study, attack-coverage, ranker-sim 0/25, ranker-sweep 0 violations,
    replay goldens, 18 OSCP targets, e2e, multi-target, all 76 engine suites; assets stamped last.
    Synced to prod the same day (directory.js/index.js/parser-signatures.js copied, prod re-stamped
    to matching hashes), verified by a clean prod browser boot (all 16 parser files served 200, zero
    console errors) and a live in-page parse (cmd dir, Invoke-Command ls, and a prose negative all
    behaved correctly).
    THIRD OUTPUT-AXIS FIX + STATE-CHANGE AXIS OPENED (2026-10-22, synced to prod 2026-10-22):
    two general parser gaps found by re-measuring the axes against the current engine (loot 542,
    state-change 539, outcome 69 prose-confirmed opportunities, down from 601/539/70 as the shipped
    fixes landed). (1) OUTCOME/transfer: a confirmed file transfer that stages a tool onto the host now
    mints a terminal host.tool_staged receipt - certutil URLCache ("CertUtil: -URLCache command completed
    successfully"), wget ("'x.sh' saved [n/n]"), scp ("name  100%  rate"), bitsadmin ("Transfer
    complete"), and a Windows "N file(s) copied". Each branch requires a tool-specific SUCCESS token, so
    an in-progress/failed transfer, a certutil arg error (still blocker.certutil_usage), and a plain
    web-enum curl mint nothing; curl -O / Invoke-WebRequest -OutFile are deliberately left out (silent
    success, no positive token, and a bare "100" meter row collides with web-enum output).
    host.tool_staged is a report fact: the host. prefix makes it terminal in decisionmap, so no move
    wiring is needed and gap-report does not flag it as orphan or dead-end. (2) STATE-CHANGE/whoami: a
    bare Windows `whoami` whose output is an identity line (DOMAIN\user, host\administrator, nt
    authority\system) now mints foothold.windows, plus access.system for SYSTEM - the Windows parity of
    what a bare `id` already minted for Linux. Root cause: index.js routed output to the command-
    execution reader only for exec-TOOL commands (evil-winrm/wmiexec/...), so a plain `whoami` paste was
    never read; the dispatch now also fires when the command is `whoami` and the output carries a Windows
    identity (_WHOAMI_ID_RE). No new fact kind (foothold.windows/access.system already existed and have
    consumers); `whoami /priv` (privilege rows, no identity line) and a Linux `whoami` (root) do not trip
    it, and the reader self-gates on a real identity so nothing else mints. Files:
    assets/engine/parsers/directory.js (_parse_transfer_success + success regexes),
    assets/engine/parsers/index.js (whoami-identity dispatch + transfer dispatch),
    data/parser-signatures.js (files lens prose + host.tool_staged emit), assets/engine/pack.js (FRIENDLY
    label), tests/engine/outcome-parsers-smoke.js (10 regression cases incl. false-positive guards). Full
    gauntlet 100% green: build-packs/flag-paths, gap-report (0 drift, corpus 81/81, host.tool_staged
    terminal), post-parse-audit, move-lint, gate-audit, field-notes-coverage, lint-study, attack-coverage,
    ranker-sim 0/25, ranker-sweep 0/4000, replay goldens, 18 OSCP targets, e2e, multi-target, all 76
    engine suites; assets stamped last. Synced to prod 2026-10-22: the four changed runtime files
    (directory.js, parsers/index.js, parser-signatures.js, pack.js) mirrored qa->prod and prod re-stamped
    (new ?v hashes match qa exactly, confirming byte-identical content). Verified LIVE in prod by a clean
    browser boot (zero console errors) and an in-page parse against the lazy-loaded engine: certutil and
    wget success both mint host.tool_staged, a failed certutil mints nothing, whoami SYSTEM mints
    foothold.windows + access.system, whoami DOMAIN\user mints foothold.windows, and a Linux whoami (root)
    mints no foothold.windows.
    RANKER-SETTLEMENT REGRESSION (separate from this parser work, found alongside it and now FIXED,
    2026-10-22): verify-replay-goldens Active Stage 5 and verify-oscp-practice-exams OSCP A 1.5 DC01
    failed for two independent reasons. (1) crack-tgs never settled once admin creds were held because
    the crack-settle guard keyed only on credential method/hash-type metadata the replay cred lacked,
    so the hash.tgs evidence weight floated it above flag-hunt-root-windows: fixed in
    assets/engine/pack.js (Action.settled drops the "not yet cracked" hold once access.admin/system/root
    or loot.ntds is held, then settles on the already-held credential.available product). (2) At DC01,
    holding ad.control_paths + credential.admin but no discovery-phase AD fact left hasAdSignal false,
    so the isAdOnlyMove guard shunted the eligible dcsync into Coming Up and emptied Ready Now: fixed in
    assets/ui/routes/path.js (hasAdSignal now also counts downstream AD progress: ad.control_paths,
    ad.acl_lead, ad.attack_paths, ad.domain_control, loot.ntds). Full gauntlet is 100% green with both
    fixes: replay goldens, all 18 OSCP targets, ranker-sim 0/25, ranker-sweep 0 violations, e2e-flag-flow,
    multi-target, all engine suites. A full qa->prod runtime mirror ran on 2026-10-22 (all changed and
    new runtime assets, rebuilt bundles, stamped index.html; data/packs excluded as prod is bundled-only)
    and is now LIVE in prod, verified by a clean browser boot (all index refs and the 12 formerly
    qa-only modules served 200, zero console errors).
    FOURTH OUTPUT-AXIS FIX SHIPPED (2026-10-23, synced to prod and LIVE): a bare ini/conf
    credential field now mints a `config_secret` credential.candidate. Re-measuring the outcome axis
    (411 units, 248 with output, 124 minted, 69 prose-confirmed opportunities) showed the ledger's two
    pre-supposed items are low-value and were set aside with reasons: auth-outcome success receipts are
    already covered (evil-winrm/CME `Pwn3d!`/nxc/impacket shells already mint winrm.authenticated,
    access.admin via nxc-pwn3d, db.admin, credential.available), and curl-O / Invoke-WebRequest silent
    success is only one or two corpus units with no positive token. The real patterned residue was
    curl/wget HTTP bodies that disclose credentials, dominated by config/ini password fields. The gap:
    websource `_has_source_secret`/`_parse_source_secret` had regexes for prefixed+quoted fields
    (`db_password = "..."`), PHP/define/.env, connection strings and URIs, but none for a bare,
    unprefixed, often unquoted config field (`password = "IcingaWeb2DBPassword"`, `DBPassword=...`,
    `db_pass = ...`, `cascadeLegacyPwd = ...`). A new line-anchored `_INI_PW_RE` catches a key ending in
    password/passwd/pwd or `<word>_pass`, an `=`/`:` delimiter, and a quoted-or-bare value, guarded by
    `_valid_config_pw` (printable-ASCII only, so a gMSA ManagedPasswordBlob binary/unicode value is
    rejected; no .NET dotted type name, so `SecureCurrentPassword = System.Security.SecureString` is
    rejected; no booleans/keywords). Line anchoring drops prose ("the password is X"), comments, and the
    structural shape drops `password_hash`/`passwd_min`/`bypass_`. No new fact kind (`config_secret` is an
    existing value.kind of credential.candidate), and because `_has_source_secret` is auto-dispatched on
    any output at index.js, the same fix converts both the outcome axis (curl/wget of a .conf/.ini) and
    the loot axis (cat/type/Get-Content of one). Corpus yield: of 13 config-field units, 6 already minted
    via other paths (deduped by the shared `seen` map), 7 were newly caught, including the iconic HTB
    reads Cascade `cascadeLegacyPwd`, FriendZone `db_pass`, Monitors/Cacti `config_pass`, and
    Shibboleth/Zipper zabbix `DBPassword`. Files: `assets/engine/parsers/websource.js` (`_INI_PW_RE`,
    `_valid_config_pw`, wired into both `_has_source_secret` and `_parse_source_secret` with
    source:'config-field'), `data/parser-signatures.js` (websource prose + regex hint),
    `tests/engine/config-field-cred-smoke.js` (regression, 15 cases: 7 corpus true positives incl. the
    universal cat/Get-Content dispatch, 8 false-positive guards). Full gauntlet 100% green:
    build-packs/flag-paths, gap-report (0 drift, corpus 81/81), post-parse-audit, move-lint, gate-audit,
    field-notes-coverage, lint-study (no em/en dashes), attack-coverage, ranker-sim 0/25, ranker-sweep
    0/4000, replay goldens, 18 OSCP targets, e2e, multi-target, all 77 engine suites; assets stamped last.
    Synced to prod 2026-10-23: the two changed runtime files mirrored qa->prod byte-identical and prod
    re-stamped (new ?v hashes match qa exactly, confirming identical bytes); prod lazy.js and index.html
    are now byte-identical to qa. Verified LIVE in prod: clean browser boot (zero console errors), lazy
    parser group loads, and an in-page parse mints config_secret for a curl-of-.ini (outcome) and a
    Get-Content on-host (loot) case while the boolean and comment false-positive guards mint nothing.
  - **facts**: DONE (2026-10-23; 102 blocks, 259 expected facts across 21 tool families, 100.0% recall, 0 forbidden hits, MIN_LABELS = 100). Moved from the harvester's binary minted-vs-blind signal to a
    fact-kind confusion matrix graded against human-authored ground truth. `qa/tools/corpus/facts-axis.js`
    loads the real engine, re-reads each labeled block's live output from the local 0xdf corpus by stable
    block id, and diffs minted kinds against the floor: correct (expected kind minted), miss (expected
    kind absent, the backlog), forbidden_hit (a guarded kind minted, a real false positive). Ground truth
    lives in `qa/tools/corpus/labels/0xdf-facts.json` as `{id, command, expected_kinds, forbidden_kinds?,
    expected_values?}` with NO verbatim output stored (Principle 7). First batch: 8 blocks (nmap AD-DC
    sweeps, gobuster v2/v3, PowerShell IWR, curl credentials.txt), 33 expected facts, recall 100.0%
    (33/33), 0 forbidden hits. The one miss the first run surfaced (admirer's `curl .../credentials.txt`,
    a freeform labeled credential block the config/.env-keyed websource extractors did not catch) was
    closed the same day by a new `_parse_labeled_creds` extractor (see the failures axis and the Derived
    Artifacts Index below), taking the batch from 97.0% to 100.0%. Expanded the same day (2026-10-23) to
    38 blocks / 101 expected facts across 15 parsers (adding netexec logon-failure / account-restricted /
    success, smbclient GPP loot, ftp anonymous + listing, curl 404, ssh uname banner, feroxbuster,
    mssqlclient session, sqlmap confirm + dump, GetNPUsers AS-REP + pre-auth true-negative, GetUserSPNs
    table + TGS, ldapsearch bad-bind true-negative, rpcclient enumdomusers, secretsdump SAM + NTDS/DCSync,
    hashcat + john cracks, sudo -l rights, evil-winrm banner true-negative), still recall 100.0% (101/101)
    and 0 forbidden hits: the expansion was authored at the floor the parsers already meet, with heavy
    forbidden-kind guards (no foothold from a login banner, no credential from a scan or a failed bind, no
    admin from a non-Pwn3d logon) and several true-negative anchors. A follow-up batch the same day then
    OPENED the backlog on purpose, asserting a stricter floor on three ambiguous blocks the parsers did not
    yet handle (40 blocks / 104 expected facts, recall 97.1% / 101-of-104, still 0 forbidden hits):
    `100754e619b9` an ftp `ls` exposing backup.mdb should mint `loot.files` (smbclient listings already
    do), `23708bbeb1b8` a curl HTTP 404 error body should mint `http.reachable` (minted for a clean 200,
    not for this error-wrapped path), and `e0c783a21aa5` a proxychains curl 200 HTML should mint
    `http.reachable` (the proxychains prefix defeats the reachability parser), with a paired true-negative
    anchor (`f87b247fe3a8`, a DNS-resolution-failure curl) guarding against firing `http.reachable` when
    nothing was reached. Two Stage 5 fixes (2026-10-23) then CLOSED all three misses. (1) `services.js`
    `_parse_http_metadata` now mints `http.reachable` from a returned response body (an HTML document, or
    an `"HTTP Error <code>"` Invoke-WebRequest wrapper line) even when no status line and no Server header
    were printed, guarded so a name resolution or connection failure (no body) stays unreachable (the
    `f87b247fe3a8` anchor stays silent). (2) `services.js` `_parse_ftp_output` now mints `loot.files` from
    an FTP directory listing (Windows IIS `"MM-DD-YY HH:MMAM/PM <size|<DIR>> name"` and Unix `ls -l` row
    shapes), reached when the command names ftp or the output carries FTP control codes (200 PORT / 227
    Passive / 125|150 data channel) and minting only inside that FTP context so a stray date or permission
    line never mints. Recall is back to 100.0% / 104-of-104, 0 forbidden hits; the facts-axis backlog is
    empty. The tool also has `--worksheet` (lists unlabeled blocks with observed kinds prefilled) and
    `--show <id>` (inspect one block). Regression: `qa/tests/engine/facts-axis-smoke.js` is
    corpus-optional (skips cleanly when the private 0xdf snapshot is absent) and ratchets
    forbidden_hits == 0 and recall >= the floor (raised from 0.95 to 1.0 once the first batch hit 100%,
    held at 1.0 through the 38-block expansion, lowered CONSCIOUSLY to 0.97 to admit the three-item
    backlog, raised to 0.99 by the http.reachable fix, then RAISED back to 1.0 by the ftp loot.files fix;
    reopening it needs a comment naming the ids, and it never drops silently; MIN_LABELS ratcheted
    8 -> 30 -> 100 across 102 blocks / 259 expected facts), with `qa/tests/engine/ftp-listing-loot-smoke.js`,
    `qa/tests/engine/http-reachable-body-smoke.js` and `qa/tests/engine/labeled-leak-cred-smoke.js` holding
    the parser logic corpus-free. A Stage 6 fact-handling pass (2026-10-23) then confirmed both newly
    reliable facts drive a downstream follow-up through the real coach ranker: `http.reachable` (65 pack
    consumers) leads with `recon-web-triage` / `content-discovery`, and `loot.files` from the ftp listing
    (9 consumers) leads with `access-db-export` / `ole-macro-analysis` for the listed `backup.mdb`, the
    correct Access-DB follow-up. `post-parse-audit.js --check` stays green across all five lenses and the
    non-reachable curl shapes mint nothing, so no gap was found and no fix was needed; the downstream half
    is locked corpus-free by `qa/tests/engine/stage6-fact-followup-smoke.js`. The Stage 1 extraction-schema
    lock (2026-10-23) then added a vocabulary check over the label file (`buildKindVocabulary` from the live
    `PARSER_SIGNATURES` emits) and immediately found drift: two `anubis.md` cases guarded against
    `web.authenticated`, a kind no parser can mint (so the guard was dead, and before Stage 1 a typo'd or
    nonexistent kind read as a silent facts-axis miss rather than an error). The dead guard was removed from
    both; `credential.available` still carries the real "a GET / 404 is not a credential" guard, so recall
    stays 1.0 / 0 forbidden hits (40/40). Contract and regression:
    `qa/tools/corpus/extraction-schema.js`, `qa/tests/engine/corpus-extraction-schema-smoke.js`.
    EXPANDED TO 102 BLOCKS / DONE (2026-10-23, Stage 4 completion): expanded `qa/tools/corpus/labels/0xdf-facts.json`
    from 40 to 102 human-reviewed blocks (259 expected facts across 21 tool families, including `certipy`,
    `smbmap`, `smbclient`, `mysql`, `mssql`, `hashcat`, `john`, `sqlmap`, `bloodhound`, `wfuzz`, `ffuf`,
    `gobuster`, `feroxbuster`, `rpcclient`, `sudo-l`, `secretsdump`, `netexec/cme`, `GetUserSPNs`,
    `GetNPUsers`, `kerbrute`, and `dig` / `dns`, plus negative/forbidden-kind anchors). All 102 blocks
    resolve against the live corpus with 259/259 expected facts minted (100.0% recall) and 0 forbidden-kind
    hits. `MIN_LABELS` in `qa/tests/engine/facts-axis-smoke.js` ratcheted from 30 to 100.
  - **failures**: DONE (2026-10-23; 27 reactive blocker doctors and all failure/outcome signatures shipped). Outcome/failure-and-success signatures
    derived and shipped from the corpus: a certutil usage/arg error mints `blocker.certutil_usage`
    (surfaces `certutil-usage-doctor`), a confirmed file transfer (certutil/wget/scp/bitsadmin/copy
    success) now mints a terminal `host.tool_staged` receipt, and a bare ini/conf credential field
    disclosed over HTTP or read on-host now mints a `config_secret` credential.candidate (see the Derived
    Artifacts Index below). The two items previously named pending were measured and set aside with
    reasons rather than built: auth-outcome success receipts are already covered by the authenticating
    moves' own proof (winrm.authenticated, access.admin via nxc-pwn3d, db.admin, credential.available),
    and curl-O/Invoke-WebRequest silent success is one or two corpus units with no positive token to key
    on. Labeled-plaintext leak blocks (admirer-style `[... account]` / `[credentials]` headers with a bare
    user line and a bare pass line, no config-field delimiter) are now CLOSED (2026-10-23): websource
    `_parse_labeled_creds` mints a `labeled_leak` credential.candidate (source 'labeled-leak') for that
    shape, guarded so a non-credential bracket section ([INFO], [options]), prose, a single line, or a
    placeholder/boolean value never mints (see the Derived Artifacts Index). HTTP error-body
    reachability, the remaining item on this axis, is now also CLOSED (2026-10-23) by the first Stage 5
    parser fix: `services.js` `_parse_http_metadata` mints `http.reachable` from a returned response body
    (HTML document or `"HTTP Error <code>"` wrapper), so `23708bbeb1b8` (curl 404) and `e0c783a21aa5`
    (proxychains curl 200) now both mint it, while the DNS-failure true-negative anchor (`f87b247fe3a8`,
    no body) stays silent (see `qa/tests/engine/http-reachable-body-smoke.js`).
  - **flow**: DONE (2026-08-20, refreshed 2026-10-11). Captured in
    `ranked-walkthroughs.json` as `techniques[]`, OS, `isAD`, OSCP tier, and score per box.
    Stage 7 move and ordering audit (2026-10-23) then spent it: the 194 boxes give a 100%
    directionally consistent pairwise precedence over the 11 technique tags; all 11 map to shipped
    moves (coverage complete), and the empirical order (recon/web -> foothold -> privesc/pivot; domain
    creds -> roasting -> DCSync) is enforced by eligibility gates, not phase labels. 8 coarse phase-proxy
    "inversions" were all false positives; proven via the real ranker and locked by
    `qa/tests/engine/stage7-flow-ordering-smoke.js`. No pack change required.
  - **vision / screenshot variance**: DONE (Stage 3 deep audit, 2026-10-23). After the initial 10-asset
    spot-check proved too small to rule out screenshot-only terminal output, Stage 3 ran a full
    194-walkthrough structural context sweep across all 2396 content captures (1861 `image-<timestamp>`
    + 535 legacy/named) and visually inspected 75 real `.png` screenshots across 63 boxes (50 high-suspicion
    captures with no adjacent code block + 25 stratified random captures). Findings: 73.9% (1375/1861) of
    captures have no fenced code block within 2 structural blocks (`!(idx +- 2)`), and 55.5% (1032) appear
    in leaf sections with zero code blocks. Of the 75 inspected screenshots, 19 (25.3% overall; 38.0% of
    high-suspicion, 4.0% of random) carry unique CLI commands, Jenkins Groovy/Pipeline scripts, ASPX webshell
    commands, Burp Repeater payloads, or `neofetch` system info absent from the Markdown prose/fenced blocks.
    `qa/tools/corpus/harvest-screenshots.js` now includes `scanWalkthroughImageContexts` (`--candidates` mode
    and `markdown_context` on every worklist item) to isolate the 382 high-signal no-adjacent-code captures,
    and 19 validated Stage 1 `fidelity: 'ocr'` records are locked in
    `qa/tools/corpus/labels/0xdf-screenshots-ocr.json` (plus `neofetch`/`hostnamectl` OS and kernel support in
    `assets/engine/parsers/host.js`), verified by `qa/tests/engine/stage3-screenshot-harvest-smoke.js`.
- **Derived so far**: the current move and pack content was built from the flow/technique
  pass. `qa/tools/verify-all-20-mined.js` asserts specific mined moves landed in the packs.
  All four axes (output, facts, failures, flow) plus the Stage 3 screenshot/OCR tier are now
  complete on the 0xdf OffSec snapshot: actionable enumeration coverage is at 97.5% (1796 minted /
  46 blind of 1842 units across 194 walkthroughs), the `facts`-axis ground-truth matrix holds 102
  labeled blocks (259 expected facts) at 100.0% recall and 0 forbidden hits, and 27 reactive blocker
  doctors cover all operational and authentication failure modes.
- **Status**: DONE (2026-10-23). Acquisition and all four axes (output, facts, failures, flow) plus
  Stage 3 vision/OCR calibration and extraction are complete and locked by regression suites. See
  Section 9 and Section 10 in [CORPUS-MINING.md](CORPUS-MINING.md).

### OffSec Proving Grounds Practice Collection (Snapshot 2026-10-29)

- **Location**: `E:\KaliFiles\obol\obol-site\corpus\pg-practice-2026-10-29\` (normalized staged corpus; raw shallow clones with full provenance preserved under `E:\KaliFiles\obol\obol-site\corpus\_upstream\`, builder at `E:\KaliFiles\obol\obol-site\corpus\stage-pg-practice.js`).
- **Upstream Sources & Provenance (retrieved 2026-10-29)**:
  - `pika5164/Offsec_Proving_Grounds` (`@ 32540a5`, `PG_Practice/` only; `PG_Play/` excluded)
  - `iamkashz/pg-writeups` (`@ 429d323`, numbered per-box chapters merged)
  - `santhoshkite/PG-write-up` (`@ 0f053c0`, `Active Directory/`, `Linux/`, `Windows/`)
  - `randalltr/oscp-pg-practice-writeups` (`@ 97d8af4`, `[PGP ...]` entries only; `41` `[HTB ...]` entries skipped)
  - `bipbopbup/bipbopbup` (`@ 4aa9f35`, `PG/AD/`, `PG/Linux/`, `PG/Windows/` + `Media/`)
  - `ajcriado/htb-writeups` (`@ 7885d9a`, `Boxes/Proving-Grounds/` extracted via `git cat-file` + merged per box)
  - `AaronCaiii/OSCP-Prepare-Proving-grounds-Practice` (`@ 8345230`, `PG/` fallback)
  - `Bsal13/Offensive-Security-Proving-Grounds-Boxes` (`@ 2ab3323`, fallback)
  - `G1xbro/OSCP-LABS` (`@ 3cd92dd`, fallback)
  - `MAX-P0W3R/OSCP-machine-generator` (`@ bca54fe`, `database1.txt` LainKusanagi PG Practice list + `database5.txt` PG Play exclusion list)
- **Scale & Deduplication**: **120 unique OffSec PG Practice machines** staged in `walkthroughs/<slug>.md` (plus **44** additional zero-screenshot pure-text alternate writeups in `alternates/<slug>--<repo>.md` for cross-operator command/tool variance), covering **60 / 61 (98.4%)** of the LainKusanagi PEN-200 / OSCP PG Practice list (only `Marketing` absent). **21** PG Play (VulnHub free tier) candidates across mixed repos were strictly quarantined in `excluded-non-practice.json`, and **41** HTB entries in `randalltr` were skipped.
  - **Tier A (0-screenshot pure terminal text & fenced-code Markdown)**: **101** boxes (`84.2%`)
  - **Tier B (fenced-code primary with supplementary screenshots)**: **8** boxes
  - **Tier C (screenshot-reliant fallback, queued for OCR)**: **11** boxes (`0` Tier D stubs)
  - **OCR Staging**: All **57** unbacked screenshot captures across **11** boxes (`no_step_adjacent_code`) are resolved locally (`0` unresolved paths) under `assets/<slug>/capture-*.png` with SHA-256 digests and surrounding prose/heading context in `ocr-worklist.json`. Inventory: `corpus-manifest.json` and `INDEX.md`.
- **Axes mined**:
  - **output**: NOT YET
  - **facts**: NOT YET
  - **failures**: NOT YET
  - **flow**: NOT YET
  - **vision / screenshot variance**: COMPLETE (`57 / 57` captures across `11` boxes visually transcribed into chronological Pass-2 `ocr-sidecars/*.json` and Principle-5-redacted `tools/corpus/labels/pg-practice-screenshots-ocr.json`, schema-validated `57/57` + pixel-audited across 21 raw PNGs)
- **Derived so far**: `tools/corpus/labels/pg-practice-screenshots-ocr.json` (`57` OCR records).
- **Status**: STAGED (OCR pre-flight complete; ready for Dual-Pass `v13.0` mining).

### OffSec PEN-200 Challenge Labs Collection (Snapshot 2026-10-29)

- **Location**: `E:\KaliFiles\obol\obol-site\corpus\pg-challenge-labs-2026-10-29\` (normalized multi-host staged corpus; raw shallow clones preserved under `E:\KaliFiles\obol\obol-site\corpus\_upstream\`, builder at `E:\KaliFiles\obol\obol-site\corpus\stage-challenge-labs.js`).
- **Upstream Sources & Provenance (retrieved 2026-10-29)**:
  - `santiagosj/Notas-OSCP` (`@ cafbf85`, Tier A pure-text winners for `Secura`, `Medtech`, `Relia` + alternates for `OSCP-A/B/C`)
  - `stephandellis/OSCP-Challenge-Labs` (`@ 60aea28`, Tier A pure-text winners for `Skylark`, `OSCP-A`, `OSCP-B`, `OSCP-C` + alternates for `Medtech`, `Relia`)
  - `wmshearer/Penetration-Testing` (`@ c13f5c8`, Tier B winners + locally resolved assets for `Zeus`, `Poseidon`, `Laser` + per-host breakdown for `OSCP-C`)
  - `w4rth0rtl3/Pentest` (`@ bae44e3`, SharpHound v5 BloodHound JSON collections for `Secura`, `Relia`, `OSCP-A`, `Zeus`, `Poseidon` + terminal logs)
  - `ajcriado/htb-writeups` (`@ 7885d9a`, `Boxes/Challenge-Labs/` per-host breakdown for `Skylark` + SharpHound bundles for `Medtech`, `Relia`, `OSCP-C`)
  - `n0veride/pwk` (`@ 9fee24b`, per-host breakdowns for `Secura`, `Medtech` + alternates)
  - `Hypothesis556/OSCP` (`@ f9d53d8`, per-host breakdown for `Relia` + `Laser` alternate)
  - `brito101/OSCP` (`@ 51be783`, per-host breakdowns for `OSCP-A`, `OSCP-B`)
  - `BJ1995/OSCP_PREP` (`@ 3f42f4b`), `AskCloud66/tech-blog` (`@ c56d578`), `cyb0rg-se/OSCP-notes` (`@ aef7379`), `fatalxs/oscp-cheatsheet` (`@ 713717e`), `laisongqing/OffSEC_OSCP_Challenge` (`@ 732379b`), `Nautilloid/bloggy` (`@ c1bce2f`)
- **Scale & Network Topology**: **10 / 10 official PEN-200 Challenge Labs** (`Secura` [3 hosts], `Medtech` [10 hosts], `Relia` [16 hosts], `Skylark` [21 hosts], `OSCP-A` [6 hosts], `OSCP-B` [6 hosts], `OSCP-C` [6 hosts], `Zeus` [3 hosts], `Poseidon` [3 hosts across `poseidon.yzx` + `sub.poseidon.yzx`], `Laser` [3 hosts]) covering **77 / 77 (100%) canonical target machines** with both unified lab `labs/<slug>/walkthrough.md` trajectories and per-host `labs/<slug>/hosts/<host>.md` files, **68** alternate writeup bundles (`19` pure-text `0`-image alternates), and **84** validated SharpHound v5 BloodHound JSON files across **7 / 10** labs (`11` collections).
  - **Tier A (0-screenshot pure terminal text & fenced-code Markdown)**: **7** labs (`secura`, `medtech`, `relia`, `skylark`, `oscp-a`, `oscp-b`, `oscp-c`)
  - **Tier B (fenced-code primary with 100% locally resolved supplementary screenshots)**: **3** labs (`zeus`, `poseidon`, `laser`; `0` Tier C, `0` Tier D)
  - **OCR Staging**: `0` unbacked screenshots in winning `walkthrough.md` files; **3** unbacked screenshots in supplementary per-host files (`medtech/hosts/web02-121.md` [1], `skylark/hosts/singapore06-225.md` [2]) staged locally (`0` unresolved paths) in `ocr-worklist.json`.
- **Axes mined**:
  - **output**: NOT YET
  - **facts**: NOT YET
  - **failures**: NOT YET
  - **flow**: NOT YET
  - **vision / screenshot variance**: COMPLETE (`24 / 24` staged captures visually inspected across `medtech`, `skylark`, `zeus`, `poseidon`, and `laser`; `18` unique-signal captures transcribed into chronological `ocr-sidecars/*.json` and Principle-5-redacted `tools/corpus/labels/pg-challenge-screenshots-ocr.json`, schema-validated `18/18`)
- **Derived so far**: `tools/corpus/labels/pg-challenge-screenshots-ocr.json` (`18` OCR records).
- **Status**: STAGED (2026-10-29).

---

## Source Backlog (Where We Want To Pull From)

The portfolio we intend to pull is detailed in [CORPUS-MINING.md](CORPUS-MINING.md) Section 5.
Status is PLANNED until the agent pulls it into the corpus root, at which point it moves into
Sources above with full provenance. **Pull order follows leverage** (how much a pull helps the
weak, high-value tools the blind-spot report names), not convenience.

- **PLANNED, parser-first (cheap, ground-truthed):** tool-shipped test fixtures and sample
  output (nmap, and projects with a `testdata/` dir); other parser projects' fixtures; canonical
  format pages (hashcat example-hashes wiki, NetExec/Impacket/ffuf/feroxbuster READMEs);
  asciinema casts; our own lab re-runs.
- **PLANNED, failures:** tool source-code error strings; issue trackers and forums (r/oscp,
  r/hackthebox, NetSecFocus).
- **PLANNED, commands and moves:** GTFOBins, LOLBAS, Atomic Red Team, HackTricks,
  PayloadsAllTheThings, tldr-pages, cheat.sh.
- **PLANNED, flow (vision tier):** more writeup archives (Hacking Articles, Rana Khalil, 0xrick,
  HTB official, GitHub CTF-writeup repos). The local 0xdf screenshots were calibrated by Stage 3
  (web-app GUI, not terminal output: no new shape); a future archive whose screenshots DO carry
  terminal output is run through `harvest-screenshots.js` as before.

## Derived Artifacts Index

Where mined value has landed, so "what came from the corpus" is always traceable:

- `qa/data/packs/*.json` and `qa/data/field-notes.js`: moves and guidance (from the 0xdf flow
  axis).
- `qa/ranked-walkthroughs.json` (in the corpus dir): the technique ranking.
- `qa/tests/corpus/*` (specifically `tests/corpus/0xdf-oscp/`): local offline corpus directory not tracked in git; shipped corpus-free regression suites live in `qa/tests/engine/*-smoke.js`.
- `qa/tools/verify-parser-corpus.js`: the harness that runs the real parser over fixtures and
  diffs observed facts against expected. Currently fed by hand-authored fixtures, not the
  0xdf corpus.
- `qa/tools/corpus/harvest-markdown.js` and `qa/tools/corpus/reports/0xdf-blindspots.json` +
  `0xdf-axes.json`: the Stage 2 harvester, its per-tool blind-spot report, and the per-axis
  opportunity report (prose as ground truth).
- FACTS axis, labeled set (2026-10-23): `qa/tools/corpus/facts-axis.js` (the grader, with
  `--worksheet` and `--show` modes), `qa/tools/corpus/labels/0xdf-facts.json` (102-block human ground
  truth across 21 tool families, grown from the initial 8-block and 40-block batches, no verbatim output),
  `qa/tools/corpus/reports/0xdf-facts-matrix.json` (the confusion matrix: 259 expected facts across 102 blocks, recall
  100.0%, 0 backlog misses, 0 forbidden hits), and
  `qa/tests/engine/facts-axis-smoke.js` (corpus-optional regression ratchet, floor 1.0, `MIN_LABELS = 100`).
  The matrix supersedes the harvester's binary signal for labeled blocks. All three stricter-floor backlog
  items are now CLOSED: `23708bbeb1b8` (curl 404) and `e0c783a21aa5` (proxychains curl 200) by the
  `_parse_http_metadata` response-body fix (`qa/tests/engine/http-reachable-body-smoke.js`), and
  `100754e619b9` (ftp listing -> loot.files) by the `_parse_ftp_output` directory-listing fix
  (`qa/tests/engine/ftp-listing-loot-smoke.js`). The facts-axis backlog is empty.
- FACTS axis, first miss closed (2026-10-23): the batch's one miss (admirer freeform credential leak)
  drove a parser fix. `assets/engine/parsers/websource.js` gained `_parse_labeled_creds`: a bracket
  header naming a credential (`account`/`login`/`credential`/`creds`/`password`) followed by a bare
  username and a bare password now mints a `labeled_leak` credential.candidate (source 'labeled-leak').
  `data/parser-signatures.js` websource `looksFor`/`regex` updated to document the shape; no new fact
  kind (credential.candidate already shipped). Regression: `qa/tests/engine/labeled-leak-cred-smoke.js`
  (5 true positives across curl and on-host reads, 6 false-positive guards). This is a shipped engine
  change: qa assets re-stamped, then synced to prod on request (2026-10-23). The prod mirror got
  the four changed runtime files (websource.js, parser-signatures.js, the re-stamped lazy.js and
  index.html); prod's cache-bust chain was independently re-verified (each file's sha1 matches its
  stamped ref). prod git commit and push are done by hand, not here.
- OUTCOME axis, first fix shipped (2026-10-22): a certutil usage/arg error now mints
  `blocker.certutil_usage` and surfaces a `certutil-usage-doctor` with the correct -urlcache
  -split -f download and -encode/-decode transfer forms. Files: `assets/engine/parsers/blockers.js`
  (recognizer), `data/parser-signatures.js` (registered), `data/packs/shells_2026_09.json` (the
  doctor move), `data/field-notes.js` (1:1 guidance), `tests/engine/outcome-parsers-smoke.js`
  (regression). Full gauntlet green: 82 engine suites, parser corpus 81/81, rankers 0 violations.
  Note: the fresh doctor ranks just below the standing on-host enum (same as the existing egress
  doctor), not #1; whether a freshly pasted blocker should headline is a separate ranker question
  worth revisiting. Synced to prod in the 2026-10-22 full runtime mirror (verified: clean browser boot).
- OUTPUT axis, first fix shipped (2026-10-22): interactive smbclient "smb: \>" ls/dir directory
  listings now mint loot.files. Files: `assets/engine/parsers/directory.js` (`_parse_share_inventory`
  listing branch + `_SMB_LS_ROW_RE`/`_SMB_LS_FOOTER_RE`), `assets/engine/parsers/index.js` (content
  sniff so a bare "ls"/"dir" unit routes to the parser), `tests/engine/smb-ls-parser-smoke.js`
  (regression). 106 of 145 interactive smbclient corpus units now mint; the rest are correctly inert.
  Synced to prod in the 2026-10-22 full runtime mirror (verified: clean browser boot).
- OUTPUT axis, second fix shipped (2026-10-22): native on-host directory listings now mint
  loot.files: cmd `dir`, PowerShell Get-ChildItem, and Invoke-Command { ls }. The dispatcher sniffs
  the "Directory of"/"Directory:"/"Mode LastWriteTime Length Name" header anchors (the unit command
  carries no tool token) and `_parse_fs_listing` anchors each row to its header. SMB-share and
  shell-listing minting share one `_emit_file_loot` helper, so sensitive-file flagging, GPP cpassword
  extraction, and config.review emission run identically on both paths (no new fact kind). Files:
  `assets/engine/parsers/directory.js` (`_parse_fs_listing` + `_emit_file_loot` refactor),
  `assets/engine/parsers/index.js` (header-anchor sniff), `data/parser-signatures.js` (prose),
  `tests/engine/win-dir-parser-smoke.js` (regression, 20 cases incl. false-positive guards). Full
  gauntlet green (76 engine suites, rankers 0 violations, replay/OSCP/e2e/multi-target). Synced to
  prod the same day (parser files copied, prod re-stamped to matching hashes), verified by a clean
  browser boot and a live in-page parse.
- OUTCOME axis, second fix shipped (2026-10-22, synced to prod 2026-10-22, verified live): a confirmed file
  transfer that stages a tool onto the host now mints a terminal `host.tool_staged` receipt - certutil
  URLCache, wget "... saved [n/n]", scp "name 100% rate", bitsadmin "Transfer complete", and a Windows
  "N file(s) copied". The `host.` prefix makes it terminal in decisionmap (no move wiring, no gap-report
  flag); failed/in-progress transfers, certutil arg errors, and web-enum curls mint nothing. Files:
  `assets/engine/parsers/directory.js` (`_parse_transfer_success`), `assets/engine/parsers/index.js`
  (dispatch), `data/parser-signatures.js` (files lens + emit), `assets/engine/pack.js` (FRIENDLY),
  `tests/engine/outcome-parsers-smoke.js` (regression). Full gauntlet green.
- STATE-CHANGE axis, first fix shipped (2026-10-22, synced to prod 2026-10-22, verified live): a bare Windows
  `whoami` identity line (DOMAIN\user, host\administrator, nt authority\system) now mints
  foothold.windows (+ access.system for SYSTEM), the Windows parity of a bare `id`. index.js previously
  routed only exec-tool commands to the command-execution reader, so a plain `whoami` paste minted
  nothing; the dispatch now also fires on a `whoami` command whose output carries a Windows identity
  (_WHOAMI_ID_RE). No new fact kind. `whoami /priv` and Linux `whoami` (root) do not trip it. Files:
  `assets/engine/parsers/index.js` (dispatch), `tests/engine/outcome-parsers-smoke.js` (regression).
  Full gauntlet green.
- RANKER axis, settlement regression fixed (2026-10-22): crack-tgs now settles once a terminal
  escalation (access.admin/system/root or loot.ntds) is held, and hasAdSignal now counts downstream AD
  progress (ad.control_paths/acl_lead/attack_paths/domain_control, loot.ntds) so eligible AD follow-ons
  like dcsync reach Ready Now without a discovery-phase port/domain fact. Files:
  `assets/engine/pack.js` (Action.settled crack guard), `assets/ui/routes/path.js` (hasAdSignal). This
  cleared both standing gauntlet failures (verify-replay-goldens Active Stage 5,
  verify-oscp-practice-exams OSCP A 1.5 DC01); full gauntlet 100% green. Synced to prod in the
  2026-10-22 full runtime mirror (verified: clean browser boot).
- OUTCOME + LOOT axis, config-field credential fix shipped (2026-10-23, synced to prod and LIVE):
  a bare ini/conf credential field (`password = "..."`, `DBPassword=...`, `db_pass = ...`,
  `cascadeLegacyPwd = ...`) disclosed over HTTP (curl/wget) or read on-host (cat/type/Get-Content) now
  mints a `config_secret` credential.candidate. A line-anchored `_INI_PW_RE` plus a `_valid_config_pw`
  guard (printable-ASCII only, no .NET dotted type name, no booleans) catches the unprefixed/unquoted
  config field the prior source-secret regexes missed, while rejecting gMSA SecureString/binary blobs,
  prose, comments, and `password_hash`/`bypass_`. No new fact kind; auto-dispatched via
  `_has_source_secret`, so it serves both axes. Corpus yield 7 newly caught of 13 config-field units
  (Cascade, FriendZone, Monitors/Cacti, Shibboleth/Zipper zabbix), 6 already covered. Files:
  `assets/engine/parsers/websource.js`, `data/parser-signatures.js` (websource prose),
  `tests/engine/config-field-cred-smoke.js` (15-case regression). Full gauntlet green (77 engine suites,
  parser corpus 81/81, rankers 0 violations, replay/OSCP/e2e/multi-target). Synced to prod 2026-10-23:
  the two changed runtime files (`assets/engine/parsers/websource.js`, `data/parser-signatures.js`)
  mirrored qa->prod byte-identical and prod re-stamped (new ?v hashes match qa exactly: websource.js
  c6015948, parser-signatures.js 41148c18; prod lazy.js and index.html now byte-identical to qa).
  Verified LIVE: clean prod browser boot (zero console errors), lazy parser group loads, and an in-page
  parse mints config_secret for both a curl-of-.ini (outcome) and a Get-Content on-host (loot) case while
  the boolean and comment false-positive guards mint nothing.
- OUTPUT axis, interactive db schema-enumeration fix shipped (2026-10-23): a `show databases;` /
  `show tables;` run inside a mysql/mariadb/mssql/psql sub-shell now mints `db.databases` / `db.tables`,
  fulfilling a declared-but-unimplemented database-parser signature. A new `_db_listing_names` helper reads
  both the boxed ASCII grid and the bare `mysql -e` newline list, strips header labels and status lines, and
  `_parse_database_output` mints only on an inventory verb with a single-column shape (describe/select
  grids, empty sets, and Query OK acknowledgements mint nothing). No new fact kind (`db.tables` already
  gates the `crack-identify` move; `db.databases` already carries a FRIENDLY label). Files:
  `assets/engine/parsers/database.js` (`_db_listing_names` + the minting block),
  `tests/engine/db-listing-parser-smoke.js` (15-case regression). Paired with a qa-only harvester-fidelity
  fix (`tools/corpus/harvest-markdown.js` now prepends the REPL tool token the product's ingest prepends,
  so REPL listings stop reading as false blinds; no stamp). Corpus effect: mysql minted 22 -> 28, blind
  31 -> 25; actionable aggregate blind 304 -> 298. Full gauntlet green (all linters 0, ranker-sim 0/25,
  ranker-sweep 0/4000, replay goldens, 18 OSCP targets, e2e, multi-target, all engine suites); database.js
  is a shipped engine change so qa assets were re-stamped last. prod sync is by hand, not done here. Open
  follow-ups: rpcclient AD user/group/SID enumeration (querygroup/lookupsids), and a mysql/mssql users-table
  `select` -> credential.candidate widening.
- OUTPUT axis, rpcclient AD SID/name resolution fix shipped (2026-10-23): raw `rpcclient $>` resolution and
  single-object detail dumps now feed the existing `ad.user_list` / `ad.group_list`. A new `_rpc_resolution`
  helper reads the four raw shapes nxc/enum4linux-ng never relabel: `lookupsids` (`<SID> DOMAIN\name (type)`,
  SID_NAME_USE 1 = user, 2/4/5 = group), `lookupnames` (`<name> <SID> (Label: type)`), `queryuser`
  (`User Name :`), and `querygroup` (`Group Name :`). Resolved users merge into the `ad.user_list` the
  function already mints (5 live consumers: asrep-roast, password-spray, online-brute-ssh/ftp/rdp); resolved
  groups into `ad.group_list`. `*unknown*`, non-user/-group classes, machine accounts (trailing `$`), and
  `NT_STATUS_NONE_MAPPED` mint nothing. No new fact kind (both already declared), so no signature or
  decisionmap change and `gap-report` stays at `orphanParserFacts: 0`. Files:
  `assets/engine/parsers/directory.js` (`_rpc_resolution` + its merge into the group and user minting sites),
  `tests/engine/rpc-resolution-parser-smoke.js` (14-case regression, incl. the no-false-positive guards and a
  no-regression enumdomusers+lookupsids merge). Corpus effect: rpcclient minted 6 -> 12, blind 15 -> 9
  (blindRate 0.71 -> 0.43); actionable aggregate blind 298 -> 292. Full gauntlet green (all linters 0,
  ranker-sim 0/25, ranker-sweep 0/4000, replay goldens, 18 OSCP targets, e2e, multi-target, 89 engine suites);
  directory.js is a shipped engine change so qa assets were re-stamped last. prod sync is by hand, not done
  here. Remaining rpcclient residue: `querygroupmem` (member RIDs with no names in-unit, needs cross-unit
  correlation), `setuserinfo2` password-restriction failures (failure axis), and the rare `enumprinters`
  comment password leak (loot axis).
- OUTPUT axis, feroxbuster no-method content-discovery fix shipped (2026-10-23): feroxbuster plain-text
  result rows now feed the existing `web.content_map` fact across both output formats. The dispatch and
  `_WEB_FEROX_RE` regex already existed, but the regex required a method column between the status code and
  the line count. Newer builds print one (`200  GET  6l  77w  3351c  URL`), older/default output omits it
  (`301  9l  28w  313c  URL`), so result-bearing walkthroughs on the no-method format (fingerprint, sense,
  writer, pikaboo, love, dynstr, and more) read as blind. The method is now optional, matched with
  `[A-Za-z]+` so it cannot swallow the leading `9l` line count when absent. No new fact kind
  (`web.content_map`, 8 live downstream consumers), so no signature or decisionmap change and `gap-report`
  stays at `orphanParserFacts: 0`. 404 rows, scan progress bars, and banner-only pastes still mint nothing.
  Files: `assets/engine/parsers/common.js` (`_WEB_FEROX_RE`), `assets/engine/parsers/index.js` (the matching
  widening in the text-shape dispatch fallback), `tests/engine/feroxbuster-nomethod-parser-smoke.js`
  (9-case regression, incl. the no-false-positive guards and a no-regression GET-method merge). Corpus
  effect: feroxbuster minted 51 -> 80, blind 36 -> 7 (blindRate 0.41 -> 0.08, now level with gobuster);
  actionable aggregate blind 292 -> 263. Full gauntlet green (all linters 0, ranker-sim 0/25,
  ranker-sweep 0/4000, replay goldens, 18 OSCP targets, e2e, multi-target, 90 engine suites); common.js and
  index.js are shipped engine changes so qa assets were re-stamped last. prod sync is by hand, not done
  here. Remaining 7 feroxbuster blinds are all banner-only or 0xdf-snipped blocks with no result rows.
