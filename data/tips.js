/*!
 * OBOL data - tips.js - the calm tip feed lineup (OBOL.TIPS).
 * Short, positive, one-line nudges that point at non-obvious features or gently warn about common
 * pitfalls. The feed (assets/ui/tips.js) cycles them slowly next to the Focus button. House style:
 * no em or en dashes. "Ctrl+K" is swapped to "⌘K" on a Mac by the feed. Edit freely, order does not
 * matter (the feed loops).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.TIPS = [
    // Core workflow & Paste loop
    { text: 'Hit Paste, top right, on any screen. OBOL reads your terminal output, mints proven facts, and re-ranks your next moves.', href: '#/evidence', cta: 'Open Evidence' },
    { text: 'Press Ctrl+K anywhere to search and jump to any command, tool, or move across the entire arsenal.', href: '#/library/commands', cta: 'Browse Commands' },
    { text: 'If a command runs cleanly with no output, click Paste Output -> Ran - Nothing Found on its Cockpit card so OBOL marks it dry and rotates #1.', href: '#/path', cta: 'Open Cockpit' },
    { text: 'Have a shell on the box? Toggle a Cockpit card from Remote (Kali) to On-Host Shell to switch from remote tools to local shell commands.', href: '#/path', cta: 'Open Cockpit' },
    { text: 'Stuck on a box? Open Library -> Stuck? to get ranked recovery ideas from a few quick questions, no pasting needed.', href: '#/library/stuck', cta: 'Open Stuck?' },
    // Features that are easy to miss
    { text: 'Paste mysterious errors or scan lines into Output & Error Doctor in the Workbench to see what they mean and how to fix them.', href: '#/workbench/explain', cta: 'Open Output Doctor' },
    { text: 'Working an AD set or multi-box network? Add every host in the Targets tab inside one engagement so domain credentials share across machines.', href: '#/targets', cta: 'Open Targets' },
    { text: 'Activate an NT hash in the sidebar Credentials list and OBOL automatically rewrites nxc, impacket, evil-winrm, bloodyAD, and certipy for Pass-the-Hash.', href: '#/creds', cta: 'Open Creds' },
    { text: 'Set LHOST and LPORT in the sidebar once, and every reverse shell, file transfer, and tunnel command comes pre-filled.', href: '#/workbench/revshell', cta: 'Open Reverse Shells' },
    { text: 'Need a Chisel, Ligolo-ng, or SSH tunnel? The Pivot & Tunnels builder in the Workbench generates both the Kali and target commands.', href: '#/workbench/pivot', cta: 'Open Pivot Builder' },
    { text: 'Drop a BloodHound zip on the Domain tab to compute your shortest ACL or delegation route to Domain Admin.', href: '#/domain', cta: 'Open Domain Tab' },
    { text: 'Have a password candidate and a user list? The Spray Planner in the Workbench calculates safe timing around the domain lockout threshold.', href: '#/workbench/spray', cta: 'Open Spray Planner' },
    { text: 'Found a SUID binary, sudo rule, or Windows binary? Look up instant privilege escalation escapes in Workbench -> GTFOBins & LOLBAS.', href: '#/workbench/gtfobins', cta: 'Open GTFOBins & LOLBAS' },
    { text: 'The Creds tab can filter to Proven So Far only, mark a login as tried and failed, and export your loot table to CSV.', href: '#/creds', cta: 'Open Creds' },
    { text: 'The Loadout tab builds a single script that stocks your Kali box with the exact tools OBOL references and syncs your installed paths.', href: '#/loadout', cta: 'Open Loadout' },
    // Gentle pitfall & setup nudges
    { text: 'In Loadout or the Cockpit setup banner, copy the Prompt Stamp so OBOL can split a full terminal session paste and auto-fill your VPN IP.', href: '#/loadout', cta: 'Open Loadout' },
    { text: 'Want OBOL to batch safe enumeration? Cruise groups non-intrusive checks to run together, then advances when you paste the output back.', href: '#/cruise', cta: 'Open Cruise' },
    { text: 'OBOL never executes anything on your behalf. It fills commands for you to review and run yourself, keeping it 100% exam legal.', href: '#/help', cta: 'Open Help' },
    { text: 'Switching to a completely separate exam or lab? Use the Engagement picker at the top of the left sidebar to keep each lab isolated.', href: '#/home', cta: 'Open Hub' },
  ];
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.TIPS; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
