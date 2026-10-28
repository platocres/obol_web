# OBOL Changelog

Release history and major feature milestones for OBOL (Offensive Box Operations Ledger).

---

## October 2026 (`v13.0`) - Operator Deck, Contextual Inference, Findings & Report Studio Overhaul

This release expands OBOL's deterministic methodology graph, rewrites the Cockpit around an identity-aware 5-tab Operator Deck, overhauls the Findings and Report Studio workspaces, and adds multi-domain BloodHound analysis, 11 offline Workbench studios, and a full in-app Operator Manual.

### Methodology & Pack Expansion
- **355 moves and 1,923 commands across 19 packs:** Expanded coverage across Active Directory ACL/GPO/ADCS/delegation chains, Linux and Windows privilege escalation, web injection and SSRF/LFI/deserialization workflows, database shells, lateral movement, and post-exploitation pillage.
- **100% 1:1 study and field-note coverage:** Every one of the 355 moves carries structured 4-pillar Field Notes (`Goal`, `Syntax`, `Gotchas`, `Pivot`) plus real-run study fixtures (`See It Run`).

### Deterministic Intelligence (`INFERENCE.md` & `RANKING.md`)
- **3-Tier Wittgensteinian Contextual Inference (`assets/engine/parsers/inference.js`):** Evaluates raw terminal pastes across 443 parser signals and 5 cross-domain contextual inference rules (Linux host privilege proof, Windows host privilege proof, authenticated AD principal capability, web RCE / file-read breakout, and multi-homed pivot boundary detection) with causal entailment gate synchronization. See [INFERENCE.md](INFERENCE.md).
- **7-Tier Causal Frontier & Bayesian Utility Ranker (`assets/engine/pack.js`):** Orders eligible moves from `Tier 6: Immediate Flag Capture` and `Tier 5: Credential / Access Frontier` down through verified exploits, contextual inference unlocks, service-matched openers, baseline enumeration, and speculative fallbacks. Scores combine AND/OR goal progress, 1-step forward enablement, keystone breadth, move reliability, context alignment, and closed-loop outcome dampening. See [RANKING.md](RANKING.md).

### Identity-Scoped Context & Truthful Outcome Receipts
- **Identity-Scoped Context (`assets/engine/context.js`):** Separates target host, target domain, authentication realm, principal, credential material, transport service, and execution locus (`On Kali` vs `On Target`). Switching targets or credentials re-projects commands and eligibility without leaking state across hosts.
- **Truthful Outcome Receipts (`assets/engine/outcomes.js`):** Distinguishes observation from completion across `success`, `duplicate`, `completed-negative`, `authorization-denied`, `rejected`, `environment-error`, and `partial`. Recognizes benign baselines (stock SUID binaries, unprivileged Windows tokens, zero-rule `sudo -l`) as dead ends and surfaces 16+ copy-ready Error & Trap Doctor remedies (Kerberos clock skew, FQDN SPN binding, OpenSSL 3 legacy FreeRDP TLS, WMI `Set-WSManQuickConfig` network-token blocks, non-TTY `sudo`, and ping-filtered Nmap scans) without falsely retiring blocked moves.

### 5-Tab Hero Operator Deck, Playbook & Multi-Command Paste
- **5-Tab Hero Operator Deck (`#/path`):** Persistent command deck at the top of the Cockpit covering `Flags & Proof` (inline `CMD`/`PS` toggles, proof screenshot checklist, and `Educated Guess` vs `Verified Path` badges), `Get On Host`, `Persistence & Accounts`, `Shares & File Transfer` (including a **13-Payload On-Host Tool Stager** generating matched Kali HTTP/SMB cradles and target pull-and-run commands for `winPEASx64.exe`, `linpeas.sh`, `SharpHound.exe`, `ligolo-agent`, `chisel`, `GodPotato.exe`, `PrintSpoofer64.exe`, `RunasCs.exe`, `Rubeus.exe`, `PowerView.ps1`, `mimikatz.exe`, `nc64.exe`, and `pspy64`), and `Cred & AD Ops`.
- **Persistent Campaign Playbook & Sequence Paste:** Track progress across `Initial Foothold -> Internal Enumeration -> Credential Harvesting -> Lateral & Domain Admin`, and paste multi-command terminal scrollback in one shot via the 4-stage session splitter (`Ctrl+V` QuickPaste or the Cockpit dropzone).

### Multi-Domain Client-Side BloodHound (`#/domain`)
- **Multi-domain forest & cross-trust support:** Drop SharpHound `.zip` bundles or BloodHound CE `.json` exports directly into the browser (parsed off-thread via Web Worker; nothing leaves your machine), or explore 3 built-in sample AD topologies (`Single-Domain ACL & Roasting`, `Multi-Domain Forest, Trusts & GPO`, `Delegation, RBCD, gMSA & Sessions`).
- **Interactive SVG Attack-Path Graph & Identity-Handoff Hop Commands:** Computes shortest paths from owned principals (plus click-to-toggle `What-If` principals) to Domain Admin, renders interactive SVG path filters, and generates numbered copy-ready commands (`bloodyAD`, `certipy`, `pygpoabuse.py`, `impacket-*`, `nxc`, `evil-winrm`) that automatically hand off compromised intermediate identities along multi-hop chains.

### Overhauled 5-Tab Findings & Blue-Team Suite (`#/findings`)
- **Findings Ledger:** Severity-ranked findings derived directly from proven facts and activity evidence, complete with CVSS v3.1 scores, CWE identifiers, remediation guidance, and per-host reproduction context.
- **Neon ATT&CK Matrix (`OBOL Scope` & `Full Enterprise`):** Color-coded Enterprise ATT&CK v15 matrix defaulting to `OBOL Scope` (the techniques reachable by OBOL's 355 moves and findings catalog) with crimson-amber glow badges on observed techniques and click-to-filter drill-downs.
- **Compliance & NIST CSF 2.0 Posture:** Executive NIST CSF 2.0 function posture strip (`GV`, `ID`, `PR`, `DE`, `RS`, `RC`) paired with expandable `<details>` control cards across NIST SP 800-53 Rev. 5, PCI-DSS v4.0, CIS Controls v8, ISO/IEC 27001:2022, and OWASP Top 10 / ASVS showing exact control definitions and triggering findings.
- **Interactive MITRE D3FEND & Blue-Team Hardening:** Dynamic 6-column MITRE D3FEND countermeasure matrix (`Model`, `Harden`, `Detect`, `Isolate`, `Deceive`, `Evict`) with click-to-filter remediation cards, Windows Security Event IDs, Sysmon telemetry, and copy-ready hardening commands.
- **CVEs & CISA KEV Tracking:** Automatic CVE extraction from version banners, vulnerability checks, and exploit moves, cross-referenced against the bundled CISA Known Exploited Vulnerabilities (KEV) catalog.

### AST-Paginated Multi-Profile Report Studio (`#/report`)
- **4 Quick Deliverable Profiles + Full Template Selector:** Switch live between `OffSec OSCP` (exam + flags), `HTB CPTS` (commercial pentest + CVSS/CWE), `TCM PNPT` (narrative AD/network assessment, no flags), `Client Pentest`, and `Executive Brief`.
- **Paginated Paper Preview & Multi-Format Export:** Deterministic AST block paginator prevents orphaned headings, splits long tables with repeated headers across sheets, pairs `local.txt` / `proof.txt` terminal screenshots with interactive proof context checks, supports one-click secret redaction, and exports to print-ready **PDF**, editable **Microsoft Word (`.docx`)**, **Markdown (`.md`)**, and standalone **HTML (`.html`)**, alongside an archive packaging helper (`7z` + SHA-256 verification commands).

### Tools Focus Lens (`#/tools`), 11-Studio Workbench (`#/workbench`), Onboarding & UX
- **Tools Grid & Focus Lens (`#/tools`):** Engagement-bound command stations (`Web Content Discovery`, `Crack Hashes`, `Port Scan`, `Database Shell`), downloadable `Get A Shell` and `Pivot And Tunnel` kits, and 50+ interactive tool builders with live flag-by-flag glossaries (`What Each Part Does`).
- **11-Studio Offline Workbench (`#/workbench`):** Live telemetry-bound builders for `Reverse Shells & TTY`, `File Transfer`, `Pivot & Tunnels`, `Hash ID & Extractors`, `JWT Studio`, `Spray Planner`, `Encode & Decode`, `Manual SQLi`, `Wordlists & Fuzzing`, `GTFOBins & LOLBAS`, and `Output & Error Doctor`.
- **Startup Hub (`#/start`), Learn (`#/study`), 5-Lens Library (`#/library`) & Operator Manual (`#/help/manual`):** Dedicated onboarding hub with 5 practice scenarios, 37 interactive cold-box simulations in Learn mode, a 355-move / 1,923-command / 117-tool Library with `Stuck?` diagnostics, and a 7-chapter searchable Operator Manual.
- **7 Skins, Focus Modes & Kali VM Motion Controls:** Instant theme switching across 7 WCAG-AA audited skins, collapsible rail Focus Mode, and reduced-motion / GPU-light controls tuned for Kali Linux VMs.

---

## Earlier Milestones (`v12.0` - `v12.9`)

- **`v12.9` - Trap Doctors & Two-Flag Endgame:** Added automatic trap diagnosis for common exam dead ends and enforced two-flag (`local.txt` + `proof.txt`) completion tracking with `whoami` / `ipconfig` / `ip a` proof context reminders.
- **`v12.8` - Both-Machine Pivot Wizard & Pivot Doctor:** Introduced matched two-host tunnel commands (`Ligolo-ng`, `Chisel`, `SSH Dynamic / Local / Remote`, `sshuttle`, `socat`, `netsh portproxy`) plus interactive tunnel troubleshooting (`Pivot Doctor`) when internal sweeps stall.
- **`v12.6` - `v12.7` - Known-Exploit Modules & Version Vulnmatch:** Added deterministic service-banner version matching (`vulnmatch`) and curated public exploit playbooks mapped to open ports and service fingerprints.
- **`v12.0` - `v12.5` - Engagement Hub, Virtual Working Directory & Cruise Pipeline:** Introduced multi-target IndexedDB engagements, virtual working directory (`OBOL.vfs`) path tracking for loot and scan artifacts, Arsenal Loadout verification (`#/loadout`), and the experimental multi-stage Cruise (`#/cruise`) script generator (`OSCP Exam Safe` and `Lab Stage Autopilot`).
