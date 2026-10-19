# TASK-03: Lead-Command Ordering Auditor & Service Version Upper-Bounds

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, or strings. Use commas, colons, parentheses, or hyphens (` - `).

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `tools/post-parse-audit.js`
- `assets/engine/parsers/nmap.js`
- `assets/engine/parsers/services.js`
- `data/packs/*.json` (only if `LEAD ORDER` flags a move whose `commands[0]` needs reordering)
- `data/field-notes.js` (if any move's `commands[]` is reordered, reorder `OBOL.FIELD_NOTES[id].commands` in lockstep)

---

## 2. Part A: Add Check #4 (`LEAD ORDER`) to `tools/post-parse-audit.js`

### Problem
Task #30 defined four checks for `tools/post-parse-audit.js`:
1. `MISSED GAIN` (built, 0 issues)
2. `PROBE RETIRE` (built, 0 issues)
3. `RE-OFFER` & `FAILURE GAP` (built, 0 issues)
4. `LEAD ORDER` (missing): When a move is unlocked ONLY by bare recon / unauthenticated facts (e.g., `port:445`, `http.reachable`, `ad.user_list`), its `commands[0]` should NOT require an earned token (`{{domain}}`, `{{basedn}}`, `{{user}}`, `{{password}}`, `{{nthash}}`, `{{dahash}}`, `{{krbtgt_hash}}`, `{{ca_name}}`, `{{cert_template}}`) if a later command in the same move (with the same locus) does NOT require that earned token! Otherwise, on a bare state, `commands[0]` either prints an unfilled token or gets hidden behind gating.

### Exact Changes Required in `tools/post-parse-audit.js`
1. In `tools/post-parse-audit.js`, inspect how `raw` actions are iterated (`around lines 120-210`).
2. Add an array `var leadOrder = [];`.
3. For each move `a` (skipping `a.sequence === true` where commands are an ordered pipeline):
   - Check if the move can become eligible without holding a credential or domain (`requires_all` has no `credential.*`, `ad.domain_known`, `ad.base_dn`, `hash.*`, `adcs.*`).
   - Check `cmd0 = (a.commands && a.commands[0] && a.commands[0].run) || ''`.
   - Extract `{{token}}` names from `cmd0`. Check if `cmd0` uses a high-gate token (`domain`, `basedn`, `user`, `password`, `nthash`, `dahash`, `krbtgt_hash`, `ca_name`, `cert_template`, `spn_host`) that is NOT guaranteed by `a.requires_all` or `a.requires_any`.
   - If `cmd0` requires such an unearned token AND another command `a.commands[j]` (`j > 0`, with the same locus as `commands[0]`) requires zero unearned tokens, push a summary string to `leadOrder`.
4. Print `section('WARN · LEAD ORDER — commands[0] requires an unearned token while a later command is immediately runnable', leadOrder);`.
5. If `leadOrder` flags any moves where `ranker-sim.js` or real usage benefits from putting the ungated command first, either reorder `commands` (and `data/field-notes.js` in lockstep) OR verify `preferredCommandIndex` / gating handles it cleanly.

---

## 3. Part B: Service Version Upper-Bound Guards (`assets/engine/parsers/nmap.js` & `services.js`)

### Problem
When Nmap or banner grabbing detects a service version, `nmap.js` and `services.js` should never mint a legacy CVE `vuln.*` fact if the banner version is clearly newer than the vulnerable range, and should verify version strings before minting:
- `vsftpd`: only `vsftpd 2.3.4` is vulnerable to the smiley backdoor (`vuln.vsftpd_234`). Verify `vsftpd 3.0.3` or `3.0.5` never mints `vuln.vsftpd_234`.
- `ProFTPD`: only `ProFTPD 1.3.5` (or `mod_copy`) is vulnerable to `vuln.proftpd_modcopy`. Verify `ProFTPD 1.3.6+` / `1.3.8` without `mod_copy` never mints `vuln.proftpd_modcopy`.
- `Samba`: `CVE-2007-2447` (`usermap_script`, `vuln.samba_usermap`) only affects `Samba 3.0.20` through `3.0.25rc3`. Verify `Samba 4.x` never mints `vuln.samba_usermap`.
- `Elasticsearch`: Groovy/MVEL RCE (`CVE-2015-1427` / `CVE-2014-3120`) only affects Elasticsearch `< 1.4.3`.

### Exact Changes Required
1. Inspect `assets/engine/parsers/nmap.js`, `assets/engine/parsers/services.js`, and `assets/engine/parsers/shape.js` where `vuln.vsftpd_234`, `vuln.proftpd_modcopy`, `vuln.samba_usermap` are minted.
2. Confirm that:
   - `vuln.vsftpd_234` only matches `vsftpd 2.3.4` (`/\bvsftpd\s+2\.3\.4\b/i`).
   - `vuln.proftpd_modcopy` only matches `ProFTPD 1.3.5` or explicit `mod_copy` (`/\bproftpd\s+1\.3\.5[a-z]?\b|\bmod_copy\b/i`).
   - `vuln.samba_usermap` only matches `Samba 3.0.20` - `3.0.25` (`/\bsamba\s+(?:smbd\s+)?3\.0\.2[0-5]/i` or `smb-vuln-cve2007-2447` `VULNERABLE`), and NEVER matches `Samba 4.x`.
3. Add a unit test block in `tests/engine/parser-shape-smoke.js` (or `tests/engine/parsers-smoke.js`) asserting that:
   - `21/tcp open ftp vsftpd 2.3.4` mints `vuln.vsftpd_234`, while `21/tcp open ftp vsftpd 3.0.3` does NOT.
   - `445/tcp open netbios-ssn Samba smbd 3.0.20-Debian` mints `vuln.samba_usermap`, while `445/tcp open microsoft-ds Samba smbd 4.9.5-Debian` does NOT.
   - `21/tcp open ftp ProFTPD 1.3.5 Server` mints `vuln.proftpd_modcopy`, while `21/tcp open ftp ProFTPD 1.3.8 Server` does NOT.

---

## 4. Verification Checklist (Must All Pass Before Completion)

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tools/post-parse-audit.js --check
node tools/gap-report.js --check
node tools/move-lint.js --check
node tools/gate-audit.js --check
node tools/ranker-sim.js
node tools/ranker-sweep.js
node tests/engine/parser-shape-smoke.js
node tools/stamp-assets.js
```
All commands must exit with code `0`.
