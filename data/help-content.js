/*!
 * data/help-content.js - OBOL.HELP, the content for the Help tab (assets/ui/routes/help.js).
 *
 * Help is the MAP of OBOL (what each surface is for, when to use it, OBOL's own vocabulary), never the
 * curriculum (how to pentest, which lives in Learn and the field notes). The index SKELETON mirrors the
 * real nav: the global sections, the engagement sub-nav groups (Work the Box / Analyze / Track &
 * Report, from ctxbar.js SUBNAV), and the Workbench tools. tests/engine/help-coverage.js asserts every
 * real surface has an entry here, so Help cannot drift from the app.
 *
 * House style: no em or en dashes; Title Case for titles and labels. Hand-authored.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // Charon introduces himself for the quick-start (H5 expands the card path).
  var CHARON_INTRO = 'I am Charon. In my day job I row the dead across the Styx, one obol a head. '
    + 'Off the clock I moonlight here: instead of ferrying souls to the far bank, I ferry the living to root. '
    + 'Same fee, better company. Let me show you the crossing.';

  // Four intent cards on the Help home (triage first, the Stuck? pattern).
  var TRIAGE = [
    { id: 'new', title: 'I Am New Here', body: 'Take the quick crossing with Charon: the four things that matter first.', goto: '#/help/start', href: '#/help/start', cta: 'Start With Charon' },
    { id: 'manual', title: 'Operator Manual', body: 'Step-by-step guide to the Cockpit, Operator Deck, epistemic path badges, sequence pastes, and multi-target workflows.', goto: '#/help/manual', href: '#/help/manual', cta: 'Read The Manual' },
    { id: 'box', title: 'I Am Working A Box', body: 'The loop: paste what you see, read the next move, reach for a tool, ask when stuck.', goto: '#/help/engagements', href: '#/help/engagements', cta: 'See The Workflow' },
    { id: 'find', title: 'I Am Looking For Something', body: 'Jump to any section by name, or look up a word OBOL uses.', goto: '#/help/glossary', href: '#/help/glossary', cta: 'Index And Glossary' },
  ];

  // Comprehensive Operator Manual chapters (rendered on #/help/manual and searchable across Help).
  var MANUAL = [
    {
      id: 'man-setup',
      title: '1. Getting Started, Profiles & Workspace Setup',
      summary: 'How to initialize an engagement, choose between Lab/Exam and Assessment profiles, scaffold your Kali working directory, and sync your tool loadout.',
      goto: '#/start',
      cta: 'Open Start Screen',
      items: [
        {
          title: 'Engagement Profiles: Lab & Exam vs Security Assessment',
          what: 'On the Start screen (#/start), pick Lab & Exam for OSCP, HTB, and Proving Grounds boxes where local.txt and proof.txt capture, exam points, and OSCP-legal command constraints apply. Pick Security Assessment for client engagements where findings severity, compliance mappings, and defensive remediation lead.',
          when: 'Every time you start a new machine, lab network, or client assessment.',
          tip: 'Keep one engagement per box or AD domain so facts, credentials, and run logs stay cleanly isolated.'
        },
        {
          title: 'Target, LHOST, Domain & Workspace Scaffold',
          what: 'Enter your Target IP, optional AD Domain / Hostname, and your Kali VPN IP (LHOST) plus default listener port (LPORT). OBOL generates a 1-click Workspace Scaffold command that creates scans/, loot/, creds/, www/, and exploits/ directories on Kali.',
          when: 'Immediately after creating an engagement, before running your first Nmap scan.',
          tip: 'Copy the working directory command from the Cockpit hero (.ws-compact) any time you open a fresh terminal tab.'
        },
        {
          title: 'Session Export, Import & Backup (.json)',
          what: 'Export your active engagement to a standalone JSON file or import a saved session from the Start screen or header menu. Every fact, credential, activity, and proof artifact travels in that single file.',
          when: 'When backing up exam progress, switching VMs, or archiving a completed box.',
          tip: 'Export a snapshot after every major milestone (initial foothold, domain user, and domain admin).'
        },
        {
          title: 'Attack VM Loadout (#/loadout)',
          what: 'Loadout generates a single verification and installation script for the exact CLI toolkit OBOL uses (NetExec/nxc, Impacket, bloodyAD, Certipy, Evil-WinRM, Ligolo-ng, Chisel, Hashcat, John, xfreerdp, and SecLists).',
          when: 'Once when preparing your Kali VM before an exam or lab sprint.',
          tip: 'Toggle installed tools in Loadout so OBOL knows your preferred local kit.'
        }
      ]
    },
    {
      id: 'man-cockpit',
      title: '2. The Cockpit (#/path) & How OBOL Ranks Moves',
      summary: 'How the causal frontier ranker orders moves, how to use the Coach Hero controls, and how to switch between Remote (From Kali) and On-Host Shell execution.',
      goto: '#/path',
      cta: 'Open Cockpit',
      items: [
        {
          title: 'Coach Hero Controls: Target Selector & Scope Lens (OSCP | All)',
          what: 'The top bar of the Cockpit lets you scope recommendations to All Targets or a specific host IP, toggle the Scope Lens between OSCP (core PEN-200 + modern AD ACL, DCSync, ADCS, and delegation paths while hiding exotic beyond-exam CVEs) and All, and inspect live readiness counters (Moves Ready, Coming Up, Opens Up Next, Derived Facts).',
          when: 'At the start of every box and whenever you pivot to a second host.',
          tip: 'Leave the Scope Lens on OSCP during exam prep so noisy unpatched-CVE checks never clutter your queue.'
        },
        {
          title: 'Focus Mode & Keep Cards Open Pill Toggles',
          what: 'Focus Mode streamlines the expanded move card so you see the #1 recommended command and paste box without secondary chrome. Keep Cards Open lets you expand multiple move cards simultaneously to compare techniques side by side.',
          when: 'Toggle Focus Mode when moving fast under exam time pressure; toggle Keep Cards Open when planning multi-prong enumeration.',
          tip: 'Both pill toggles persist per engagement and sit directly inside the Coach Hero utility row.'
        },
        {
          title: 'Causal Frontier Ranking & Sequential Multi-Step Moves',
          what: 'OBOL ranks moves by their position on your proven causal frontier, their goal distance to flags, and whether they have been tried in the current Access Epoch. When a multi-step move (such as SMB anonymous recon or Windows flag hunt) produces a new fact on Step 1, that card stays at #1 and automatically promotes Step 2 to Command #1.',
          when: 'Throughout the entire box lifecycle, from initial port scan to final root proof.',
          tip: 'You can follow a strict Always Run Command #1 on Card #1 workflow and OBOL will walk you through each multi-step chain in order.'
        },
        {
          title: 'Execution Locus Toggle: Remote (From Kali) vs On-Host Shell',
          what: 'Many moves offer both Remote commands (run from Kali over SMB, WinRM, LDAP, RPC, or SSH) and On-Host commands (run inside an interactive shell on the target). Flag-capture moves default to On-Host when an interactive shell path is open so your proof output includes whoami, hostname, and ipconfig in one frame.',
          when: 'When choosing between one-shot remote execution from Kali and running commands inside an open reverse shell, Evil-WinRM, or wmiexec session.',
          tip: 'If port 5985 and 3389 are closed and you have not confirmed admin rights yet, Windows Root Flag Hunt starts on Remote (nxc wmi probe) first, then switches to On-Host (impacket-wmiexec) once admin is proven.'
        },
        {
          title: '4-Pillar Field Notes, See It Run & Reactive Field Doctors',
          what: 'Every move and command carries a 4-pillar Field Note: What You Are Doing, How To Land It, What To Look For, and Common Mistakes. Click See It Run to inspect a realistic sample terminal transcript, or read the inline Field Doctor banner whenever a pasted error mints a blocker.* diagnostic.',
          when: 'Before running an unfamiliar command flag or immediately after a command returns an error.',
          tip: 'Field Doctors provide a 1-click copyable remediation command (for example, syncing Kerberos clock skew with ntpsec-ntpdate or chaining bloodyAD group join + add dcsync).'
        }
      ]
    },
    {
      id: 'man-deck',
      title: '3. The Hero Operator Deck & Epistemic Path Badges',
      summary: 'Using the 5-tab tactical Operator Deck, switching active identities, choosing tool/shell variants, and understanding Educated Guess vs Verified Path badges.',
      goto: '#/path',
      cta: 'Open Operator Deck',
      items: [
        {
          title: '5 Tactical Tabs & Active Identity Selector',
          what: 'Once you hold a credential, readable share, or foothold shell, the Hero Operator Deck unlocks with 5 tabs: Flags & Proof, Get On Host, Persistence & Accounts, Shares & File Transfer, and Cred & AD Ops. Use the Active Identity dropdown at the top of the deck to switch which discovered user (password or NT hash) fills every command.',
          when: 'As soon as you recover your first username/password, NT hash, readable SMB share, or shell.',
          tip: 'When an NT-hash-only identity is active, OBOL displays a Pass-the-Hash callout and rewrites every deck variant to use -H / -hashes / /pth automatically.'
        },
        {
          title: 'Tool & Shell Variant Pills (nxc, smbclient, wmiexec, cmd.exe, PowerShell, auto-search)',
          what: 'Each step in the Operator Deck offers clickable tool or shell variant pills. For example, on SMB Flag Hunt you can switch between nxc --spider, smbmap -R, and smbclient recurse for Step 1, and between smbclient get (saves locally and prints via cat user.txt), smbclient stdout, and nxc --get-file for Step 2.',
          when: 'When a target blocks one protocol or shell syntax (for example, switching from PowerShell to cmd.exe inside impacket-wmiexec).',
          tip: 'Never run semicolon-separated PowerShell commands inside cmd.exe or wmiexec; pick the cmd.exe or cmd.exe (auto-search) pill instead.'
        },
        {
          title: 'Epistemic Status Badges: Educated Guess vs Verified Path',
          what: 'OBOL never pretends a guessed file path is proven. Before you run a flag-locate step, any proof command that uses a default path (such as C:\\Users\\<user>\\Desktop\\user.txt or C:\\Users\\Administrator\\Desktop\\root.txt) displays an amber Educated Guess (Unverified Path) badge. Once you paste output from Step 1 (or a dir/Get-ChildItem locate sweep), OBOL extracts the real path into objective.flag_located and upgrades the badge to Ready - Verified Path.',
          when: 'When capturing user.txt, local.txt, root.txt, or proof.txt on Windows or Linux targets.',
          tip: 'Want to skip the separate locate step? Click the cmd.exe (auto-search), PowerShell (auto-search), or nxc auto-search (-x) variant pill, which carries Ready - Verified Path because it sweeps all C:\\Users\\*\\Desktop profiles automatically.'
        },
        {
          title: 'Choose Your Path Multi-Step Lanes on Move Cards',
          what: '26 complex move cards (including Windows/Linux Flag Hunt, Lateral Execution, BloodHound Collection, ACL Abuse, SMB Share Inventory, and Ligolo/Chisel Pivoting) render an interactive Choose Your Path workflow inside the card with Port/Method groups, Ready vs Locked lane badges, and ordered Step 1 -> Step 2 -> Step 3 chains.',
          when: 'When a move has multiple distinct execution lanes (for example, SMB Share vs WinRM vs WMI Shell vs Enable RDP).',
          tip: 'Locked lanes remain visible with a concise badge (such as Port 5985 Closed or Needs Admin) so you always see what will unlock if you enable that service or escalate privileges.'
        },
        {
          title: '13-Payload Tool Stager (shares-stage-tools)',
          what: 'Under the Shares & File Transfer tab, the Tool Stager lane (shares-stage-tools) provides a 13-payload catalog (WinPEAS / winPEASx64.exe, LinPEAS / linpeas.sh, pspy64, Ligolo-ng / ligolo-agent.exe, Chisel, SharpHound, Rubeus, Mimikatz, Potatoes including GodPotato and PrintSpoofer, Certify, PowerView, RunasCs, and nc64) with paired Step 1 (On Kali HTTP/SMB server) and Step 2 (On-Target certutil, iwr, IEX, curl, wget, or SMB push) staging cradles.',
          when: 'Whenever you need to stage an enumeration script, potato exploit, tunneling agent, or AD collector onto a compromised target.',
          tip: 'Select any tool pill in the Stage Tool row and OBOL updates both the Kali server prep command and the target pull-and-execute cradle automatically.'
        }
      ]
    },
    {
      id: 'man-paste',
      title: '4. The Evidence Loop, Sequence Pastes & Dry-Probe Recovery',
      summary: 'How OBOL parses terminal output into facts, handles multi-command sequence pastes, and rotates dry probes automatically.',
      goto: '#/evidence',
      cta: 'Open Evidence',
      items: [
        {
          title: 'Inline Paste, Quick-Paste Modal (Alt+P) & Evidence Station',
          what: 'You can paste terminal output in three places: inline inside any Move Card or Operator Deck step, via the global Paste modal in the top header (shortcut Alt+P), or on the Evidence tab (#/evidence). After every paste, a floating Outcome Pill summarizes the newly minted facts.',
          when: 'Immediately after running any command on Kali or on the target host.',
          tip: 'Include the command line or shell prompt when using Quick-Paste so OBOL can disambiguate bare outputs (such as an impacket-wmiexec C:\\> prompt or combined user.txt + root.txt reads).'
        },
        {
          title: 'Multi-Command Sequence Pastes & Implicit Prerequisite Completion',
          what: 'If you run Step 1, Step 2, and Step 3 back-to-back in your terminal and paste the entire scrollback into the card once, OBOL splits the transcript across prompt boundaries, parses every command in order, and marks all completed steps Done. If you jump straight to the final proof step and paste valid proof output, OBOL implicitly marks the prerequisite setup/connect steps Done as well.',
          when: 'When executing a multi-step lane (such as Locate Flag -> Read Flag, or Enable RDP -> Connect -> Capture Proof) in one terminal session.',
          tip: 'If you grab user.txt remotely over SMB (on_host: false), OBOL marks it captured but reminds you when you reach Admin to run the Combined User + Root On-Host Proof command for your exam screenshot.'
        },
        {
          title: 'Dry Probes (Ran - Nothing Found) & Automatic Card Rotation',
          what: 'When an enumeration command runs cleanly but returns zero findings (for example, bloodyAD get writable returning nothing, Impacket printing No entries found!, or pasting an empty prompt-to-prompt block), click Ran - Nothing Found or paste the output. OBOL classifies it as completed-negative, retires that command for the current epoch, and rotates the card below untried hypotheses so Card #2 automatically becomes Card #1.',
          when: 'Whenever a valid probe comes up empty on a box.',
          tip: 'Cross-card command deduplication ensures that if you run bloodyAD get writable on one card, sibling cards sharing that exact probe recognize it as already tried.'
        },
        {
          title: 'Safety Invariants: Environment Errors Never Demote a Card',
          what: 'Connection timeouts, DNS failures, syntax errors, and operational blockers (such as clock skew or anonymous bind denial) classify as environment-error or blocker diagnostics. They never increment dry-probe counters and never demote a card.',
          when: 'When a command fails due to a transient network issue, typo, or box policy.',
          tip: 'Fix the blocker using the inline Field Doctor command and re-run the step; productive output immediately resets any prior dry-probe count on that card.'
        },
        {
          title: '3-Tier Parser & Wittgensteinian Contextual Inference Engine (inference.js)',
          what: 'Every paste runs through a 3-tier parsing cascade: Tier 1 high-precision tool-signature parsers, Tier 2 structural shape matchers (shape.js), and Tier 3 Wittgensteinian Contextual Inference Engine (inference.js), which combines atomic co-occurrence families, dynamic 2D table/KV geometry, shell prompt telemetry, causal entailment, and 5 cross-domain inference rules (infer-ad-role-from-ports, infer-cred-reuse-frontier, infer-web-upload-to-rce, infer-mssql-priv-to-cmdshell, infer-containers-escape).',
          when: 'Automatically on every terminal paste, even when commands are omitted, columns reorder, or you jump ahead out of sequence.',
          tip: 'Paste raw outputs from custom tools or unfamiliar table formats directly; Tier 3 infers credentials, shares, privileges, and entailed service gates without needing a rigid regex match.'
        }
      ]
    },
    {
      id: 'man-multitarget',
      title: '5. Multi-Target Scoping, Credentials & Access Epochs',
      summary: 'Managing multi-host Active Directory or pivoted networks without cross-host fact bleeding.',
      goto: '#/targets',
      cta: 'Open Targets',
      items: [
        {
          title: 'Host-Scoped Isolation vs Domain-Scoped Inheritance',
          what: 'Every port, service, foothold, admin proof, and located flag path is strictly scoped to its host (host:<ip>). Domain-level facts (such as ad.domain_known or domain users) are scoped to domain:<fqdn> and inherited only by hosts proven to belong to that domain.',
          when: 'When working multi-host AD sets, pivoted internal subnets, or standalone + AD exam topologies.',
          tip: 'Use the Target dropdown in the Coach Hero to focus the Cockpit on one host IP at a time, or select All Targets to view target-badged cards across the whole engagement.'
        },
        {
          title: 'Credential Ledger (#/creds) & Target Memory',
          what: 'The Creds station lists every discovered username, password, NT hash, Kerberos ticket, and SSH key along with its validation status. Selecting a credential pins it for the active target; switching targets recalls each host\'s own pinned or best validated credential.',
          when: 'When testing credential reuse across SMB, WinRM, LDAP, MSSQL, RDP, and SSH.',
          tip: 'When DCSync or secretsdump recovers Administrator material, OBOL surfaces a persistent selection banner so you can switch to Administrator in one click.'
        },
        {
          title: 'Access Epochs & Re-Opening Enumeration Under New Privileges',
          what: 'An Access Epoch represents your current privilege and credential state on a host. Discovering a new credential, landing a foothold, or escalating to Admin advances the Access Epoch, which resets prior dry-probe demotions so enumeration moves can be re-run under your new privileges.',
          when: 'Automatically whenever a paste mints a new credential, foothold, or admin fact.',
          tip: 'Re-check SMB shares and AD ACLs whenever you advance to a new domain user epoch.'
        }
      ]
    },
    {
      id: 'man-builders',
      title: '6. Builders (#/tools, #/workbench), Learn (#/study) & Reporting (#/report)',
      summary: 'When to reach for Tools, the 13 Workbench studios, the Learn curriculum, Library/Stuck?, and the Exam Report generator.',
      goto: '#/workbench',
      cta: 'Open Workbench',
      items: [
        {
          title: 'Tools (#/tools) vs Workbench (#/workbench)',
          what: 'Use Tools (#/tools) when you want an interactive flag-by-flag CLI builder for Nmap, NetExec, Impacket, BloodHound, Certipy, ffuf, or Hashcat pre-filled with your active target. Use Workbench (#/workbench) when you need one of the 13 specialized client-side studios (Reverse Shell Studio, File Transfer, Tunnels & Pivot / Pivot & Tunnel Builder, Hash ID & Crack Pipeline, CyberChef Lite / Unified Codec & WAF Evasion, Encoder, Smart Decoder, JWT Studio, GTFOBins/LOLBAS, Wordlist Picker, Manual SQLi Studio, Output & Error Doctor, and Password Spray Planner).',
          when: 'Any time you need to craft a payload, stage a binary, build a Ligolo/Chisel tunnel, identify a hash, or decode an obfuscated blob.',
          tip: 'All Workbench studios run 100% offline in browser memory and automatically pull LHOST, LPORT, Target IP, and spotted SUID/privilege facts from your active engagement.'
        },
        {
          title: 'Learn (#/study) Interactive Curriculum & Cold-Box Simulator',
          what: 'Learn provides four study modes: Lane Map (step-by-step Watch & Practice workbenches with token-by-token flag breakdowns), Atlas (pan/zoom cross-lane dependency graph), By-Port Decision Map (what to run for every open TCP/UDP port), and Cold-Box Simulator (interactive retrieval practice on realistic lab scenarios).',
          when: 'When studying methodology between boxes or warming up before an exam.',
          tip: 'Switch a Learn node from Watch to Your Turn to practice choosing the next move and diagnosing terminal output without hints.'
        },
        {
          title: 'Scoreboard (#/scoreboard), Findings (#/findings) & Report (#/report)',
          what: 'Flags (#/scoreboard) tracks local.txt and proof.txt across every target and flags whether each proof was captured on-host. Findings (#/findings) maps proven facts to MITRE ATT&CK, D3FEND, Compliance controls, and CISA KEV CVEs. Report (#/report) compiles your chronological attack chain, proof screenshots, and redaction-safe Markdown report with an exam preflight checklist.',
          when: 'As you capture flags and before wrapping up your engagement documentation.',
          tip: 'Run the Report Preflight check before disconnecting from a lab or exam VPN to verify no required proof screenshot or IP/hostname frame is missing.'
        }
      ]
    }
  ];

  // The index: global sections, each with its sub-surfaces. `goto` and `href` point to hash routes.
  // `set` carries UI state the target needs (e.g. a Findings sub-view). scope groups the index headings.
  var SECTIONS = [
    { id: 'engagements', title: 'Engagements', scope: 'global', goto: '#/home', href: '#/home',
      what: 'Everything for working one box: paste what you see, get the next move, track what you proved.',
      when: 'The core loop. Start here whenever you are on a live target.',
      tip: 'Keep one engagement per box so facts and credentials stay isolated.',
      groups: [
        { group: 'Work The Box', subs: [
          { id: 'start', title: 'Start & Engagement Setup', goto: '#/start', href: '#/start',
            what: 'Create a new Lab/Exam or Security Assessment engagement, configure Target/LHOST/Domain, run the Kali workspace scaffold, or import/export .json sessions.',
            when: 'When starting a new box, switching engagements, or importing a saved session file.',
            tip: 'Choose Lab & Exam mode for OSCP/HTB/PG boxes to enable flag-first ranking and scoreboard tracking.' },
          { id: 'home', title: 'Hub', goto: '#/home', href: '#/home',
            what: 'The engagement home: your target, the phase you are in, and the single best next move at a glance.',
            when: 'When you open or return to an engagement and want instant situational awareness.',
            tip: 'Check the phase badge and suggested start before diving into commands.' },
          { id: 'targets', title: 'Targets', goto: '#/targets', href: '#/targets',
            what: 'Every host in scope, its open ports, services, and proven identity (IP and hostname).',
            when: 'When managing multi-host scopes or switching active target focus.',
            tip: 'Tag hostnames and domain names early so service commands fill with FQDNs.' },
          { id: 'path', title: 'Cockpit', goto: '#/path', href: '#/path',
            what: 'The operator cockpit. A ranked list of what to do next, the 5-tab Hero Operator Deck, Choose Your Path multi-step lanes, and 4-pillar Field Notes. The heart of OBOL.',
            when: 'Whenever you need to know what command to run next against your target.',
            tip: 'Use Focus Mode to hide command clutter and concentrate on the lead move.',
            subs: [
              { id: 'path-hero', title: 'Coach Hero, Target Scope & Scope Lens', goto: '#/path', href: '#/path',
                what: 'Top dashboard bar with Target switcher (All Targets vs single host), Scope Lens (OSCP | All), working directory copy bar, Keep Cards Open & Focus Mode pills, and live readiness counters.',
                when: 'When scoping recommendations to a specific host or toggling between OSCP-safe moves and all CVEs.',
                tip: 'Click the working directory snippet (.ws-compact) to copy your Kali cd/mkdir setup command.' },
              { id: 'path-deck', title: 'Hero Operator Deck & Epistemic Badges', goto: '#/path', href: '#/path',
                what: '5-tab post-credential command deck (Flags & Proof, Get On Host, Persistence & Accounts, Shares & File Transfer, Cred & AD Ops) with Active Identity switcher, tool/shell variant pills, and Educated Guess vs Verified Path badges.',
                when: 'Once you hold a valid credential, readable SMB share, foothold shell, or admin access.',
                tip: 'Switch to an (auto-search) variant pill whenever you want a self-locating flag proof command without running a separate locate step first.' },
              { id: 'path-chooser', title: 'Choose Your Path Multi-Step Lanes', goto: '#/path', href: '#/path',
                what: 'Interactive Port/Method groups and ordered Step 1 -> Step 2 -> Step 3 chains inside complex moves, supporting both step-by-step pastes and single-paste sequence completion.',
                when: 'When executing multi-step flag hunts, lateral movement, ACL chains, or Ligolo/Chisel pivots.',
                tip: 'Run all steps in a lane and paste the combined terminal output once into the final step to mark the whole chain Done.' },
              { id: 'path-cards', title: 'Ready Now Queue, Field Notes & Dry-Probe Rotation', goto: '#/path', href: '#/path',
                what: 'Ranked move cards with Remote vs On-Host toggle, 4-pillar Field Notes, See It Run examples, Reactive Field Doctors, and Ran - Nothing Found dry-probe rotation.',
                when: 'When working down your prioritized enumeration and exploitation queue.',
                tip: 'Click Ran - Nothing Found when a probe returns zero findings so OBOL rotates the next untried hypothesis to #1.' }
            ] },
          { id: 'evidence', title: 'Evidence', goto: '#/evidence', href: '#/evidence',
            what: 'Paste any tool output here. OBOL reads it, mints facts, and the Cockpit re-ranks. You never tell OBOL what you found, you show it.',
            when: 'After running any tool or discovery command on your Kali box or target shell.',
            tip: 'Paste raw, unmodified terminal output including banners and error messages.' },
        ] },
        { group: 'Analyze', subs: [
          { id: 'map', title: 'Map', goto: '#/map', href: '#/map',
            what: 'A visual graph of the engagement: hosts, services, and how you moved between them.',
            when: 'When visualizing pivot paths, credential reuse, and network topology.',
            tip: 'Click any node on the graph to inspect discovered ports and linked evidence.' },
          { id: 'domain', title: 'Domain', goto: '#/domain', href: '#/domain',
            what: 'Load a BloodHound collection and OBOL finds your route to Domain Admin, who to hunt next, and the exact abuse commands.',
            when: 'Once you obtain LDAP or SMB credentials in an Active Directory environment.',
            tip: 'Upload the raw BloodHound JSON zip file directly into the Domain station.' },
          { id: 'creds', title: 'Creds', goto: '#/creds', href: '#/creds',
            what: 'Every credential you have gathered, where it works, and whether it has been validated.',
            when: 'When checking collected passwords, hashes, Kerberos tickets, and SSH keys.',
            tip: 'Filter by Validated to see high-value accounts ready for lateral movement.' },
        ] },
        { group: 'Track And Report', subs: [
          { id: 'checklist', title: 'Checklist', goto: '#/checklist', href: '#/checklist',
            what: 'The methodology checklist for the box, ticking itself off as you prove each step.',
            when: 'When verifying coverage across standard enumeration and exploitation phases.',
            tip: 'Use the checklist before wrapping up a box to ensure no ports were missed.' },
          { id: 'findings', title: 'Findings', goto: '#/findings', href: '#/findings',
            what: 'Proof-bound findings across every host, plus the Frameworks view: ATT&CK, Defensive, Compliance and CVEs.',
            when: 'When reviewing vulnerabilities, reporting metrics, or studying detection counters.',
            tip: 'Export findings directly into your draft exam report.',
            subs: [
              { id: 'findings-list', title: 'Findings List', goto: '#/findings', href: '#/findings', set: { findingsView: 'findings' },
                what: 'The proof-bound findings, grouped by severity or by target.',
                when: 'When auditing discovered vulnerabilities and verified security flaws.',
                tip: 'Attach proof screenshots directly from the evidence ledger.' },
              { id: 'findings-attack', title: 'ATT&CK Matrix', goto: '#/findings', href: '#/findings', set: { findingsView: 'attack' },
                what: 'The MITRE ATT&CK matrix, lit by what you did. Hover a cell for the engagement evidence, or for the OBOL command that performs it.',
                when: 'When assessing tactical coverage against industry threat models.',
                tip: 'Hover cells to quickly view the exact commands mapped to techniques.' },
              { id: 'findings-defensive', title: 'Defensive (D3FEND)', goto: '#/findings', href: '#/findings', set: { findingsView: 'defensive' },
                what: 'How a blue team catches and stops what you did, and the OBOL command each countermeasure would block.',
                when: 'When reviewing blue team defenses, SIEM rules, and D3FEND mitigations.',
                tip: 'Use defensive insights to craft remediation guidance for client reports.' },
              { id: 'findings-compliance', title: 'Compliance', goto: '#/findings', href: '#/findings', set: { findingsView: 'compliance' },
                what: 'What your findings map to across NIST, CIS, PCI, CWE and OWASP, for the report.',
                when: 'When preparing compliance audits and regulatory risk summaries.',
                tip: 'Reference regulatory control IDs in executive summaries for leadership.' },
              { id: 'findings-cves', title: 'CVEs And KEV', goto: '#/findings', href: '#/findings', set: { findingsView: 'cves' },
                what: 'Detected CVEs, the actively-exploited ones (CISA KEV) first, with remediation.',
                when: 'When prioritizing exploits matching confirmed software versions.',
                tip: 'Focus on CISA KEV badges first as they represent reliable exploit paths.' },
            ] },
          { id: 'history', title: 'Run Log', goto: '#/history', href: '#/history',
            what: 'Everything you have run this engagement, in order, so nothing is lost.',
            when: 'When reviewing your command audit trail or reconstructing exploitation steps.',
            tip: 'Filter by status to quickly isolate commands that yielded new credentials.' },
          { id: 'scoreboard', title: 'Flags', goto: '#/scoreboard', href: '#/scoreboard',
            what: 'Every captured flag per target, with its real value one click from the clipboard. Points show only in exam mode.',
            when: 'When submitting proof flags or verifying point totals during exams and labs.',
            tip: 'Click a flag value to copy it immediately with proof hash attached.' },
          { id: 'report', title: 'Report', goto: '#/report', href: '#/report',
            what: 'Generates OSCP-style report content from your proven findings.',
            when: 'When compiling your final pentest documentation and exam deliverables.',
            tip: 'Run the preflight check to ensure all required proof artifacts are attached.' },
        ] },
      ] },
    { id: 'study', title: 'Learn', scope: 'global', goto: '#/study', href: '#/study',
      what: 'Structured practice: interactive kill-chain lanes, token-by-token command breakdowns, the By-Port decision map, the cross-lane Atlas, and the Cold-Box Simulator.',
      when: 'When you want to learn or revise a technique, away from a live box.',
      tip: 'Switch from Watch to Your Turn on any move node to test your recall on what to run next and how to read the output.' },
    { id: 'loadout', title: 'Loadout', scope: 'global', goto: '#/loadout', href: '#/loadout',
      what: 'Your installed tools. Generates one setup script that installs and checks the kit OBOL expects.',
      when: 'Once, when you set up your attack VM, and whenever a command says a tool is missing.',
      tip: 'Run the generated setup script inside your Kali VM to sync all missing tools.' },
    { id: 'tools', title: 'Tools', scope: 'global', goto: '#/tools', href: '#/tools',
      what: 'The command builders: pick a task and OBOL writes the exact command, filled from your target and parameters.',
      when: 'When you know what you want to run and want it filled in correctly.',
      tip: 'Switch between tool alternatives to find the best syntax for your target version.' },
    { id: 'workbench', title: 'Workbench', scope: 'global', goto: '#/workbench', href: '#/workbench',
      what: 'Client-side borrowed back ends: build a shell, identify a hash, encode a payload, and more. They fill from your engagement and also work standalone.',
      when: 'When you need a tool mid-box and do not want to leave OBOL.',
      tip: 'All workbench utilities run entirely in browser memory without sending data out.',
      subs: [
        { id: 'wb-revshell', title: 'Reverse Shell, TTY & Stager Studio', goto: '#/workbench/revshell', href: '#/workbench/revshell',
          what: 'Pick a shell, TTY stabilization recipe, msfvenom stager, or minimal webshell and OBOL fills your LHOST and LPORT.',
          when: 'When catching shells, stabilizing raw netcat sessions, or generating stagers.',
          tip: 'Use PowerShell Base64 encoded format to bypass complex quote escaping.' },
        { id: 'wb-transfer', title: 'File Transfer & Exfil Builder', goto: '#/workbench/transfer', href: '#/workbench/transfer',
          what: 'Paired Step 1 (On Kali) and Step 2 (On Target) commands for staging tools or exfiltrating loot over HTTP, SMB, SCP, or Base64.',
          when: 'When moving linpeas, winPEAS, chisel, or loot between Kali and the target.',
          tip: 'Use the Impacket SMB Server method on Windows when outbound HTTP is blocked or when executing binaries directly from a share.' },
        { id: 'wb-pivot', title: 'Pivot, Port-Forward & Tunnel Builder (Tunnels & Pivot)', goto: '#/workbench/pivot', href: '#/workbench/pivot',
          what: 'Scenario-first visual tunnel builder for localhost port forwards, internal subnet routing, and reverse shell relays via Chisel, Ligolo-ng, SSH, or Socat.',
          when: 'When netstat reveals a 127.0.0.1 service or ip route shows a hidden internal subnet.',
          tip: 'Pick the visual topology card that matches your goal and fill only the single required port or subnet field.' },
        { id: 'wb-hashid', title: 'Hash ID, Extractor & Crack Pipeline', goto: '#/workbench/hashid', href: '#/workbench/hashid',
          what: 'Paste a raw hash, user:hash, or secretsdump line; OBOL strips prefixes, names the mode, and writes the full Hashcat and John pipeline.',
          when: 'When cracking dumped hashes, Kerberos tickets, or protected archives/keys.',
          tip: 'Open the *2john File Extractor drawer when you have a protected id_rsa, .zip, .kdbx, or .pfx file.' },
        { id: 'wb-codec', title: 'Unified Codec & WAF Evasion (CyberChef Lite)', goto: '#/workbench/codec', href: '#/workbench/codec',
          what: 'Peels nested encodings automatically at the top and generates every encoding and WAF/filter evasion transform below with 1-click chaining.',
          when: 'When decoding obfuscated blobs or wrapping payloads for command injection, SQLi, or XSS filters.',
          tip: 'Click Chain -> Input on any output row to layer multiple encodings in sequence.' },
        { id: 'wb-encoder', title: 'Encoder', goto: '#/workbench/encoder', href: '#/workbench/encoder',
          what: 'Shows your input in every common encoding at once (base64, url, hex, base32, gzip, ROT, IFS evasion).',
          when: 'When crafting exploit payloads for web parameters, command injection, or filters.',
          tip: 'Compare encoding variants side by side to pick the right bypass format.' },
        { id: 'wb-decoder', title: 'Smart Decoder', goto: '#/workbench/decoder', href: '#/workbench/decoder',
          what: 'Paste anything encoded and OBOL peels the layers to show what it really is.',
          when: 'When analyzing obfuscated web responses, cookies, or base64 blobs.',
          tip: 'The smart decoder automatically recurses through nested encoding layers.' },
        { id: 'wb-jwt', title: 'JWT Studio (Decode, Edit & Sign)', goto: '#/workbench/jwt', href: '#/workbench/jwt',
          what: 'Decodes a JSON Web Token, lets you edit claims live, and forges alg:none or HMAC-SHA256 signed tokens alongside crack commands.',
          when: 'When inspecting or tampering with JWT tokens discovered in web headers, cookies, or local storage.',
          tip: 'Click Elevate Claims (role: admin) and Forge alg: none to test broken signature verification in one step.' },
        { id: 'wb-gtfobins', title: 'GTFOBins & Windows LOLBAS', goto: '#/workbench/gtfobins', href: '#/workbench/gtfobins',
          what: 'Searchable Linux GTFOBins and Windows LOLBAS privilege escalation and living-off-the-land recipes.',
          when: 'When discovering abnormal SUID binaries, sudo privileges, or restricted Windows shells.',
          tip: 'Binaries already spotted on your active target are highlighted at the top for 1-click selection.' },
        { id: 'wb-wordlists', title: 'Wordlist & Fuzz Command Picker', goto: '#/workbench/wordlists', href: '#/workbench/wordlists',
          what: 'The right SecLists wordlist floated to your detected stack, with ready ffuf, feroxbuster, gobuster, or dirsearch commands.',
          when: 'When selecting wordlists for directory fuzzing, vhost discovery, or custom list generation.',
          tip: 'Use the stack extension chips (PHP, ASPX/IIS, JSP, Backup/Config) to append the exact -e flag.' },
        { id: 'wb-sqli', title: 'Manual SQLi Payload Studio', goto: '#/workbench/sqli', href: '#/workbench/sqli',
          what: 'Strictly manual, exam-legal SQL injection studio covering Progressive UNION, Auth Bypass, Error/Blind probes, and File Read/RCE.',
          when: 'When probing web inputs for SQL injection without using banned automated tools.',
          tip: 'Switch between MySQL, PostgreSQL, MSSQL, SQLite, and Oracle to get exact dialect syntax.' },
        { id: 'wb-explain', title: 'Output & Error Doctor', goto: '#/workbench/explain', href: '#/workbench/explain',
          what: 'Triages any command output into Actionable Leads, Error Diagnosis + Fix Commands, Benign OS Baselines, and Minted Facts.',
          when: 'When a command fails with a cryptic error or when you want to know if SUID/privilege/cron output is stock OS noise.',
          tip: 'Paste find SUID, whoami /priv, or Kerberos/SMB errors to get an immediate verdict and copyable fix command.' },
        { id: 'wb-spray', title: 'Password Spray Planner', goto: '#/workbench/spray', href: '#/workbench/spray',
          what: 'Turns a domain lockout policy into a safe password-spray schedule and writes ready NetExec, Kerbrute, and timed loop commands.',
          when: 'When spraying domain credentials against SMB, Kerberos, or WinRM.',
          tip: 'Always leave at least 2 attempts of safety margin below the domain lockout threshold.' },
      ] },
    { id: 'library', title: 'Library', scope: 'global', goto: '#/library', href: '#/library',
      what: 'Browse everything OBOL knows: every move and every command, mapped onto MITRE ATT&CK, with Stuck? folded in. No ranking, no engagement needed.',
      when: 'When you want to explore the full lineup, look up a command, or find a path forward.',
      tip: 'Search by port or service to see all available attack vectors at once.',
      subs: [
        { id: 'library-moves', title: 'Moves', goto: '#/library/moves', href: '#/library/moves',
          what: 'A faceted card browser: filter every move by lane, phase, port, service, tool, or OS, then open one for its commands and field notes.',
          when: 'When exploring available techniques or checking prerequisites for a move.',
          tip: 'Filter by phase and service to discover new privilege escalation paths.' },
        { id: 'library-commands', title: 'Commands', goto: '#/library/commands', href: '#/library/commands',
          what: 'Every distinct command OBOL carries, deduped and grouped by tool and capability, with back-links to every move that uses it. Filled from your engagement when you have one.',
          when: 'When researching tool syntax or finding alternative command flags.',
          tip: 'Use the tool filter to see all NetExec or Impacket invocations in one place.' },
        { id: 'library-attack', title: 'ATT&CK', goto: '#/library/attack', href: '#/library/attack',
          what: 'A library-scoped matrix: every ATT&CK technique OBOL can perform, with the moves and commands behind each. What OBOL can do, versus the Findings matrix of what you have done.',
          when: 'When cross-referencing capabilities against threat emulation matrices.',
          tip: 'Click any technique cell to inspect all underlying moves and syntax.' },
        { id: 'library-stuck', title: 'Stuck?', goto: '#/library/stuck', href: '#/library/stuck',
          what: 'Lost in a box? Answer Charon a few quick questions about what you have and he hands you ranked options, no pasting needed.',
          when: 'When enumeration hits a dead end and you need fresh diagnostic questions.',
          tip: 'Walk through the prompt triage to uncover overlooked enumeration angles.' },
      ] },
    { id: 'cruise', title: 'Cruise', scope: 'global', goto: '#/cruise', href: '#/cruise',
      what: 'OBOL on autopilot, legally. It hands you a batch of safe moves to run, you paste the output back, and it advances to the next batch, round after round until flags. Experimental.',
      when: 'When you want OBOL to drive the next steps for you instead of reading them one at a time.',
      tip: 'Copy the entire multi-command cruise batch into your terminal at once.' },
    { id: 'paste', title: 'Paste', scope: 'global', goto: '#/evidence', href: '#/evidence',
      what: 'The Paste button in the header is the fastest way in: paste output from anywhere and OBOL mints facts from it, exactly like the Evidence box.',
      when: 'Any time you have output to show OBOL and do not want to navigate first.',
      tip: 'Use keyboard shortcut Alt+P to quickly open the global paste modal.' },
    { id: 'search', title: 'Search', scope: 'global', goto: '#/home', href: '#/home',
      what: 'The search button in the header jumps you to any command or surface by name.',
      when: 'When you know what you want and want to get there in one step.',
      tip: 'Press forward-slash (/) anywhere in the app to focus the global search bar.' },
  ];

  // OBOL-vocabulary glossary (H3 expands and cross-links). Pentest jargon stays in Learn / field notes.
  var GLOSSARY = [
    { term: 'Access Epoch', def: 'A discrete privilege tier on a target (unauthenticated, initial shell, local admin, domain user, domain admin). Commands untried in the active epoch take priority.', see: ['path', 'creds'] },
    { term: 'Active Identity', def: 'The currently selected credential (username + password or NT hash) in the Operator Deck and Cockpit that populates all command templates for the active target.', see: ['path', 'creds'] },
    { term: 'Blocker / Field Doctor', def: 'A reactive remedy triggered when tool output reveals an operational obstacle (such as CLM, AppLocker, clock skew, or an unreachable port). Surfaces fix commands immediately.', see: ['path', 'evidence'] },
    { term: 'Choose Your Path', def: 'An interactive multi-lane workflow inside complex Move Cards that groups alternative methods (such as SMB Share vs WinRM vs WMI Shell vs RDP) into ordered Step 1 -> Step 2 -> Step 3 chains.', see: ['path'] },
    { term: 'Cockpit', def: 'The operator cockpit screen: the ranked HUD, Hero Operator Deck, and move queue of what to do next. The heart of OBOL.', see: ['path'] },
    { term: 'Cruise Batch', def: 'A grouped sequence of independent, safe discovery or enumeration moves that can be copied and executed together during automated cruise rounds.', see: ['cruise', 'path'] },
    { term: 'Dry Probe (Ran - Nothing Found)', def: 'A valid enumeration command that executed cleanly on the target but returned zero findings. Recording a dry probe retires that command for the current Access Epoch and rotates the card below untried hypotheses.', see: ['path', 'evidence'] },
    { term: 'Earned Token', def: 'A parameter or credential placeholder filled strictly by proven facts in the ledger, never by speculative guesswork or manual assumptions.', see: ['evidence', 'path'] },
    { term: 'Educated Guess (Unverified Path)', def: 'An epistemic badge shown in the Operator Deck when a proof command uses a conventional default path (such as C:\\Users\\<user>\\Desktop\\user.txt) before the locate step has confirmed the exact file path in the ledger.', see: ['path'] },
    { term: 'Engagement', def: 'One box or lab network you are working. It holds its own ledger, targets, credentials and run log. You can keep several and export/import them as JSON.', see: ['engagements'] },
    { term: 'Fact', def: 'One proven thing about the target that OBOL minted from output you pasted (a port, a hash, a credential, a flag path). Facts drive everything; OBOL never guesses one.', see: ['evidence', 'path'] },
    { term: 'Frontier', def: 'The boundary between what you have already proven and what is reachable next. Moves on your active frontier are ranked highest in the Cockpit.', see: ['path', 'map'] },
    { term: 'Goal Distance', def: 'The number of dependent graph hops separating your current ledger state from full host or domain compromise.', see: ['path', 'domain'] },
    { term: 'Hero Operator Deck', def: 'The 5-tab tactical command deck at the top of the Cockpit (Flags & Proof, Get On Host, Persistence & Accounts, Shares & File Transfer, Cred & AD Ops) that unlocks as soon as you hold a credential, readable share, or shell.', see: ['path'] },
    { term: 'Keystone Move', def: 'A high-leverage action (like BloodHound ingest, credential dumps, or port discovery) that unlocks a broad set of downstream execution paths.', see: ['path', 'domain'] },
    { term: 'Locus (Remote / On-Host)', def: 'The execution environment for a command: Remote (from your Kali attack machine) or On-Host (inside a target shell or session).', see: ['path', 'workbench'] },
    { term: 'Move', def: 'A single step the Cockpit can recommend, with the commands to run it and a 4-pillar field note. Moves become available as the facts they need are proven.', see: ['path'] },
    { term: 'Phase', def: 'Where you are in the box: recon, enum, creds, access, escalate, loot. The Cockpit leads with moves that fit your phase.', see: ['home', 'path'] },
    { term: 'Proof Discipline', def: 'The requirement to prove each prerequisite fact before advancing, ensuring every command you run is verified and defensible for your report.', see: ['evidence', 'report'] },
    { term: 'Proof Gated', def: 'A move or command only appears once you have proven the facts it needs. OBOL will not hand you a step you cannot yet run.', see: ['path'] },
    { term: 'Ready - Verified Path', def: 'An epistemic badge shown in the Operator Deck when a flag path has been proven in the ledger (objective.flag_located) or when using a self-locating (auto-search) command variant.', see: ['path'] },
    { term: 'Scope Lens (OSCP | All)', def: 'The 2-state filter in the Cockpit hero: OSCP keeps all core PEN-200 and modern AD paths (ACL abuse, DCSync, ADCS, delegation) while hiding exotic unpatched CVEs; All shows every move in the library.', see: ['path'] },
    { term: 'Sequence Paste', def: 'Pasting terminal scrollback from multiple consecutive steps at once. OBOL splits the transcript across shell prompts, mints facts from every command, and marks all completed steps Done.', see: ['path', 'evidence'] },
    { term: 'Settled', def: 'A question a move answered. Once a fact is proven, the probe that asked for it drops away so OBOL never nags you about it again.', see: ['path'] },
    { term: 'Settled Command', def: 'A probe or command that has fulfilled its objective (for example, confirming a port or extracting an initial share list) and is hidden from the Cockpit.', see: ['path', 'evidence'] },
    { term: 'Speculative Move', def: 'A contingency probe tested when standard deterministic paths are exhausted, attempting educated checks based on partial service fingerprints.', see: ['path', 'library'] },
    { term: 'Station', def: 'A dedicated UI view or tool workspace focused on a specific phase of the engagement lifecycle (such as Pivot Station, Findings, or Workbench).', see: ['workbench', 'engagements'] },
    { term: 'The Cockpit', def: 'The ranker and HUD behind the Cockpit tab. It reads your facts and orders the moves by what helps most right now, and explains why.', see: ['path'] },
    { term: 'The Ledger', def: 'The running set of facts for an engagement. Everything OBOL shows is a view over this one ledger.', see: ['evidence', 'creds'] },
    { term: 'Workbench', def: 'The global set of 13 client-side studios (shell builder, file transfer, pivot builder, hash ID, codec, JWT, GTFOBins/LOLBAS, wordlists, manual SQLi, error doctor, spray planner) that fill from your engagement and also work standalone.', see: ['workbench'] },
  ];

  // The Charon quick-start card path (H5 expands; these are the first four things that matter).
  var QUICKSTART = [
    { id: 'q1', title: 'Set Your Loadout', charon: 'Every ferryman keeps his tools dry. Check your kit before the crossing.', body: 'Install and check the tools OBOL expects. One setup script prepares your attack VM so every command runs with all dependencies in place.', goto: '#/loadout', href: '#/loadout', cta: 'Open Loadout' },
    { id: 'q2', title: 'Create An Engagement & Target', charon: 'Name your crossing and the far bank you mean to take.', body: 'Create an engagement for your box and set the target IP and hostname. OBOL scopes every command, credential, and path to this target.', goto: '#/targets', href: '#/targets', cta: 'Open Targets' },
    { id: 'q3', title: 'Run & Paste Your First Scan', charon: 'Hand me a coin, or in your case, some output.', body: 'Run a port scan, then paste the full output into Evidence. OBOL reads it, mints proven facts, and advances the Cockpit automatically.', goto: '#/evidence', href: '#/evidence', cta: 'Open Evidence' },
    { id: 'q4', title: 'Follow The Cockpit To Proof', charon: 'The current is mapped. Follow it to root.', body: 'The Cockpit ranks what to do next. Open the top move, run the command, paste the result, and follow the verified path all the way to flags.', goto: '#/path', href: '#/path', cta: 'Open Cockpit' },
  ];

  OBOL.HELP = { charonIntro: CHARON_INTRO, triage: TRIAGE, manual: MANUAL, manualChapters: MANUAL, sections: SECTIONS, glossary: GLOSSARY, quickstart: QUICKSTART };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.HELP; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
