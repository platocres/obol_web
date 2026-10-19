# TASK-05: OSCP Report Pre-Flight Grader & Archetype E2E Replays

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, or strings. Use commas, colons, parentheses, or hyphens (` - `).

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `assets/engine/report.js`
- `assets/ui/routes/report.js`
- `assets/ui/routes/scoreboard.js`
- `tests/engine/report-preflight-smoke.js` (new test file)
- `tests/engine/linux-web-e2e-replay.js` (new test file)

**Do NOT edit:** `data/packs/*.json`, `assets/engine/pack.js`, or `assets/engine/parsers/*.js`.

---

## 2. Part A: OSCP Exam Report Pre-Flight Grader (`assets/engine/report.js`)

### Problem
OffSec's OSCP exam grading rules disqualify points on a machine if:
1. A captured flag (`local.txt` or `proof.txt`) does not have a proof output block showing the flag value alongside `whoami` and `ipconfig`/`ifconfig`/`ip a` in the same terminal capture.
2. A compromised host with a captured flag is missing step-by-step reproduction findings (Initial Access or Privilege Escalation when root flag is held).
3. Any command in the engagement's activity log used an exam-restricted tool (`sqlmap`, `metasploit` / `msfconsole` on more than one host, or Cruise `lab` mode).

### Exact Changes Required in `assets/engine/report.js`
1. Add a pure function `preflightCheck(ctx)` in `assets/engine/report.js` and export it on `OBOL.report.preflightCheck`:
   - Input: `ctx` returned by `OBOL.report.buildContext(state, profileId)`.
   - Returns: `{ ok: boolean, warnings: [{ level: 'error'|'warn', host: string, code: string, message: string }] }`.
   - Checks to perform:
     - **`MISSING_PROOF_CONTEXT` (`warn`)**: For each proof in `ctx.proofs`, inspect the activity in `ctx.activities` that captured that flag (or `proof.stdout` / matching `act.stdout`). Check if the same `stdout` contains both an identity output (`/\b(?:uid=\d+|root|[a-z0-9_.-]+\\[a-z0-9_.-]+|nt authority\\system)\b/i`) and an IP address (`/\b(?:\d{1,3}\.){3}\d{1,3}\b/`). If not, push `{ level: 'warn', host: proof.host, code: 'MISSING_PROOF_CONTEXT', message: 'Flag capture for ' + proof.host + ' (' + proof.kind + ') does not show whoami + IP address in the same terminal output block.' }`.
     - **`MISSING_WALKTHROUGH_CHAIN` (`warn`)**: For each host in `ctx.hosts` that has at least one proof in `ctx.proofs`:
       - Call `initialAccessFindings(host.findings, host.activities, host.facts)` and `privescFindings(host.findings, host.activities, host.facts)`.
       - If `initialAccessFindings` is empty, push `{ level: 'warn', host: host.ip, code: 'MISSING_INITIAL_ACCESS', message: 'Host ' + host.ip + ' has a captured flag but no Initial Access finding/command chain in the report.' }`.
       - If the host has an `objective.root_flag` proof and `privescFindings` is empty (and initial access did not land straight as root/SYSTEM), push `{ level: 'warn', host: host.ip, code: 'MISSING_PRIVESC', message: 'Host ' + host.ip + ' has a root/SYSTEM flag but no Privilege Escalation finding/command chain in the report.' }`.
     - **`EXAM_RESTRICTED_TOOL` (`error`)**: Scan `ctx.activities`. If any activity `command` matches `/\bsqlmap\b/i`, push `{ level: 'error', host: act.target || 'global', code: 'EXAM_RESTRICTED_TOOL', message: 'Activity log contains sqlmap, which is prohibited on the OSCP exam: ' + act.command }`.
2. **Surface in `assets/ui/routes/report.js` and `assets/ui/routes/scoreboard.js`**:
   - In `assets/ui/routes/report.js`, call `OBOL.report.preflightCheck(ctx)` and, if `warnings.length > 0`, render a clean collapsible `Report Readiness Pre-Flight` card above the report preview listing each warning with its host badge and plain-language fix. When `warnings.length === 0` and `ctx.proofs.length > 0`, show a calm `Pre-Flight Clean: all captured flags have proof context and reproduction chains` badge.
3. **Create `tests/engine/report-preflight-smoke.js`**:
   - Test `OBOL.report.preflightCheck(ctx)` on:
     1. A host with a flag paste lacking IP/`whoami` -> emits `MISSING_PROOF_CONTEXT`.
     2. A host with a complete `whoami; ip a; cat proof.txt` paste + initial access + privesc activities -> `ok: true, warnings.length === 0`.
     3. An activity containing `sqlmap -u http://10.10.10.5/item?id=1` -> emits `EXAM_RESTRICTED_TOOL`.

---

## 3. Part B: Linux Web-to-Root Stateful E2E Replay (`tests/engine/linux-web-e2e-replay.js`)

Create `tests/engine/linux-web-e2e-replay.js` modeled directly on `tests/engine/forest-e2e-replay.js` (pure Node, zero Playwright, testing `parseActionOutput -> FactSet -> nextActionsV2 -> fillAll -> report`):
1. **Stage 1 (Nmap Recon)**: Parse Nmap output with `22/tcp open ssh OpenSSH 8.2p1 Ubuntu-4ubuntu0.5` and `80/tcp open http Apache httpd 2.4.41 ((Ubuntu))` -> assert `host.os_family` is `linux`, `http.reachable` is minted, and web enumeration (`recon-web-triage` / `content-discovery`) ranks in top moves.
2. **Stage 2 (Web Content Discovery -> LFI/Command Exec -> Foothold)**: Parse `id` output (`uid=33(www-data) gid=33(www-data) groups=33(www-data)`) -> assert `foothold.linux` is minted, initial access moves (`recon-web-triage`, etc.) retire or deprioritize, and `flag-hunt-linux` / `linux-enum` rank at the top.
3. **Stage 3 (Linux Enum -> Sudo/Kernel/SUID Escalation)**: Parse `sudo -l` (`(ALL : ALL) NOPASSWD: /usr/bin/find`) and `uname -a` (`Linux web01 5.10.0-9-amd64 #1 SMP Debian x86_64 GNU/Linux`) -> assert `privesc.sudo_rights`, `host.kernel`, and `vuln.dirtypipe` are minted, and `sudo-abuse` / `dirtypipe` promote to `tier = 0` Ready Now.
4. **Stage 4 (Root & Proof Capture -> Report Verification)**: Parse combined `whoami; ip a; cat /home/www-data/local.txt; cat /root/proof.txt` with `root` and two 32-hex flags -> assert both `objective.local_flag` and `objective.root_flag` (plus `proof.captured`) mint, privesc moves retire once `access.admin` is held, and `OBOL.report.buildContext` produces both proofs and non-empty Initial Access & Privilege Escalation sections.

---

## 4. Verification Checklist (Must All Pass Before Completion)

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tests/engine/report-preflight-smoke.js
node tests/engine/linux-web-e2e-replay.js
node tests/engine/forest-e2e-replay.js
node tools/lint-study.js --check
node tools/gap-report.js --check
node tools/post-parse-audit.js --check
node tools/stamp-assets.js
```
All commands must exit with code `0`.
