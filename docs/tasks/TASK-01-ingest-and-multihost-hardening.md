# TASK-01: Interactive Session Splitter & Multi-Host Fact Scoping

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, or strings. Use commas, colons, parentheses, or hyphens (` - `).

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `assets/ui/ingest.js`
- `assets/engine/command.js`
- `tests/engine/session-import-smoke.js`
- `tools/verify-multi-target.js`

**Do NOT edit:** `data/packs/*.json`, `assets/engine/pack.js`, or `assets/engine/parsers/*.js`.

---

## 2. Part A: Interactive Sub-Shell Prompt Splitting (`assets/ui/ingest.js`)

### Problem
In `assets/ui/ingest.js` (`lines 345-391`), `splitSession(text)` splits a pasted terminal log into individual `{ command, stdout, ts }` segments using `_PROMPT_LINE` (`lines 345-349`). Currently `_PROMPT_LINE` only matches:
1. Kali two-line prompt (`└─$` / `└─#`)
2. Standard `user@host:cwd$ `
3. PowerShell (`PS C:\...>` and `*Evil-WinRM* PS C:\...>`)

When an operator pastes a multi-command interactive session from `impacket-mssqlclient` (`SQL (sa  dbo@master)>`), `mysql`/`MariaDB`, `psql` (`postgres=#`), `smbclient` (`smb: \>`), `rpcclient` (`rpcclient $>`), `ftp` (`ftp>`), or `meterpreter >`, `splitSession` fails to split the commands or drops the sub-shell commands.

### Exact Changes Required in `assets/ui/ingest.js`
1. **Expand `TOOL_HEAD` (`line 12`) and `TOOL_HINTS` (`lines 38-48`)**:
   - Add interactive sub-shell verbs to `TOOL_HINTS` so sub-shell commands are recognized:
     `'enable_xp_cmdshell xp_cmdshell exec sp_configure reconfigure select show use describe tables get mget put ls dir cd pwd enumdomusers enumalsgroups querydispinfo queryuser getdompwinfo lookupnames'`.
2. **Expand `_PROMPT_LINE` (`lines 345-349`)**:
   Add regex patterns for interactive tool prompts:
   ```javascript
   var _PROMPT_LINE = [
     /^\s*(?:┌──.*)?└─[#$]\s+(\S.*)$/,                                   // Kali two-line prompt (cmd on └─$)
     /^[\w.\-]+@[\w.\-]+:[^\s#$]*\s*[#$]\s+(\S.*)$/,                      // user@host:cwd$ cmd
     /^(?:\*?Evil-WinRM\*?\s+)?PS\s+[A-Za-z]:[^>]*>\s+(\S.*)$/,           // PowerShell PS C:\...> cmd, incl. *Evil-WinRM* PS prefix
     /^\s*SQL\s*\([^)]*\)\s*>\s*(\S.*)$/i,                                // impacket-mssqlclient: SQL (sa dbo@master)> cmd
     /^\s*(?:mysql|MariaDB\s*\[[^\]]*\])\s*>\s*(\S.*)$/i,                 // mysql> or MariaDB [db]> cmd
     /^\s*[a-zA-Z0-9_]+=[#>-]\s+(\S.*)$/,                                 // psql: postgres=# cmd or app=> cmd
     /^\s*smb:\s*\\[^>]*>\s*(\S.*)$/i,                                    // smbclient: smb: \> cmd
     /^\s*rpcclient\s*\$>\s*(\S.*)$/i,                                    // rpcclient $> cmd
     /^\s*ftp>\s*(\S.*)$/i,                                               // ftp> cmd
     /^\s*meterpreter\s*>\s*(\S.*)$/i,                                    // meterpreter > cmd
   ];
   ```
3. **Preserve Parent Tool Context for Sub-Shell Prompts in `splitSession` (`lines 368-391`)**:
   - When `_PROMPT_LINE` matches a sub-shell prompt (`SQL (...)>`, `smb: \>`, `rpcclient $>`, `mysql>`, `postgres=#`, `ftp>`), prefix the extracted `cmd` with the parent tool token if it is not already present (e.g., `'mssqlclient ' + cmd` for `SQL (...)>`, `'smbclient ' + cmd` for `smb: \>`, `'rpcclient ' + cmd` for `rpcclient $>`, `'mysql ' + cmd` for `mysql>`/`MariaDB`, `'psql ' + cmd` for `postgres=#`, `'ftp ' + cmd` for `ftp>`), so `parseActionOutput` routes each sub-shell segment to the right protocol parser (`database.js`, `directory.js`, `services.js`).
4. **Update `deriveCommand(text)` (`lines 13-28`)**:
   - Also check `_promptCmd(raw)` inside `deriveCommand` so single-paste sub-shell blocks derive their command properly.

### Required Regression Tests (`tests/engine/session-import-smoke.js`)
Add assertions to `tests/engine/session-import-smoke.js` verifying that:
1. A multi-step `impacket-mssqlclient` session (`SQL (sa  dbo@master)> enable_xp_cmdshell` followed by `SQL (sa  dbo@master)> xp_cmdshell whoami` returning `nt authority\system`) splits into 2 segments and mints `foothold.windows` + `access.system`.
2. A multi-step `smbclient` session (`smb: \> dir` showing shares/files) and `rpcclient` session (`rpcclient $> enumdomusers` showing `user:[svc-alfresco] rid:[0x450]`) split cleanly and mint `ad.user_list`.

---

## 3. Part B: Multi-Host vs. Domain Fact Scoping (`assets/engine/command.js`)

### Problem
In multi-host engagements (like the 3-host OSCP AD set `MS01`, `MS02`, `DC01`), `OBOL.store.factSet()` or host-filtered fact sets are passed to `commandContext(facts, opts)` in `assets/engine/command.js` (`lines 55-260`). If an engagement has facts from two hosts in the same `FactSet`, host-specific facts (`objective.flag_located_local`, `objective.flag_located_root`, `port:*`, `host.hostname`) must prefer facts whose `f.scope === 'host:' + target` when `opts.params.target` is set, while domain-wide facts (`ad.domain`, `ad.base_dn`, `hash.krbtgt`, domain credentials) remain shared across all hosts in the domain.

### Exact Changes Required in `assets/engine/command.js`
1. Inspect `commandContext(facts, opts)` in `assets/engine/command.js`:
   - Add a small helper `scopedValues(facts, kind, targetIp)` that, when `facts.facts` is available and `targetIp` is a non-empty IP (`opts && opts.params && opts.params.target`), filters `facts.facts` for `f.kind === kind && f.state === 'supported'` and:
     - If any matching fact has `f.scope === 'host:' + targetIp`, returns the `.value` of those host-matching facts first.
     - Otherwise falls back to `facts.values(kind)` (preserving backward compatibility with single-host tests that use `scope: 'host:target'` or `scope: 'global'`).
   - Use `scopedValues(facts, kind, targetIp)` for host-bound tokens: `objective.flag_located_local`, `objective.flag_located_root`, `objective.flag_located`, `host.hostname`, and `port:*` (`openPorts`).
2. Add a test case in `tools/verify-multi-target.js` confirming that when `Host A` (`10.10.10.10`) has `objective.flag_located_local` (`C:\Users\alice\Desktop\local.txt`) and `Host B` (`10.10.10.20`) has `objective.flag_located_local` (`C:\Users\bob\Desktop\local.txt`) in the same `FactSet`, calling `fillCommand` with `params: { target: '10.10.10.20' }` fills `C:\Users\bob\Desktop\local.txt` (never `alice`'s path).

---

## 4. Verification Checklist (Must All Pass Before Completion)

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tests/engine/session-import-smoke.js
node tests/engine/flag-path-fill-smoke.js
node tools/verify-multi-target.js
node tools/ranker-sim.js
node tools/gap-report.js --check
node tools/post-parse-audit.js --check
node tools/lint-study.js --check
node tools/stamp-assets.js
```
All commands must exit with code `0`.
