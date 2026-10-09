/*!
 * obol data — tips.js — the calm tip feed lineup (OBOL.TIPS).
 * Short, positive, one-line nudges that point at non-obvious features or gently warn about common
 * pitfalls. The feed (assets/ui/tips.js) cycles them slowly next to the Focus button. House style:
 * no em or en dashes. "Ctrl+K" is swapped to "⌘K" on a Mac by the feed. Edit freely, order does not
 * matter (the feed loops).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  OBOL.TIPS = [
    // Workflow
    'Hit Paste, top right, on any screen. obol reads your output and sharpens every next step.',
    'Press Ctrl+K anywhere to jump to any command, tool, or move.',
    'Not sure what is next? Next Steps ranks your move from what you have proven, and re-ranks each time you paste.',
    'Stuck on a box? The Stuck? tab hands you ranked options from a few quick questions, no pasting needed.',
    'Want obol to drive? Cruise batches safe moves to run, then advances when you paste the output back.',
    // Features that are easy to miss
    'The Workbench has a reverse shell builder, hash identifier, encoder and more, all pre-filled from your engagement.',
    'Set LHOST and LPORT in the sidebar once, and every reverse shell and listener command comes ready to run.',
    'Drop a BloodHound zip on the Domain tab to see your shortest route to Domain Admin and what to run next.',
    'The Loadout tab builds one script that stocks your Kali box with the exact tools obol references.',
    'Paste into Explain This Output, in the Workbench, to see what each line proves, and what it does not.',
    'The Creds tab can show Proven So Far only, flag a credential as tried and failed, and export to CSV.',
    'Click a credential in the sidebar to make it active, and every command fills with that login.',
    'New to a screen? The Help tab maps every part of obol, section by section.',
    // Gentle pitfall nudges
    'obol never runs anything. It hands you commands to review and run yourself, which keeps it exam legal.',
    'A run is not a win. Paste the real output so obol can prove the result, then advance.',
    'A command marked "needs: ..." is waiting on a fact you have not proven yet. It fills in the moment you paste it.',
    'In Loadout, turn on the prompt stamp so obol can stitch a whole session paste and auto-fill your VPN IP.',
    'The active Target pill routes a paste with no host of its own to that target. Switch it anytime.',
    'Working several boxes? Switch between them with the Engagement picker, top left.',
  ];
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.TIPS; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
