/*!
 * data/help-content.js — OBOL.HELP, the content for the Help tab (assets/ui/routes/help.js).
 *
 * Help is the MAP of obol (what each surface is for, when to use it, obol's own vocabulary), never the
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

  // Three intent cards on the Help home (triage first, the Stuck? pattern).
  var TRIAGE = [
    { id: 'new', title: 'I Am New Here', body: 'Take the quick crossing with Charon: the four things that matter first.', goto: '#/help/start', cta: 'Start With Charon' },
    { id: 'box', title: 'I Am Working A Box', body: 'The loop: paste what you see, read the next move, reach for a tool, ask when stuck.', goto: '#/help/engagements', cta: 'See The Workflow' },
    { id: 'find', title: 'I Am Looking For Something', body: 'Jump to any section by name, or look up a word obol uses.', goto: '#/help/glossary', cta: 'Index And Glossary' },
  ];

  // The index: global sections, each with its sub-surfaces. `goto` is a hash route; `set` carries UI
  // state the target needs (e.g. a Findings sub-view). scope groups the index headings.
  var SECTIONS = [
    { id: 'engagements', title: 'Engagements', scope: 'global', goto: '#/home',
      what: 'Everything for working one box: paste what you see, get the next move, track what you proved.',
      when: 'The core loop. Start here whenever you are on a target.',
      groups: [
        { group: 'Work The Box', subs: [
          { id: 'home', title: 'Hub', goto: '#/home', what: 'The engagement home: your target, the phase you are in, and the single best next move at a glance.' },
          { id: 'targets', title: 'Targets', goto: '#/targets', what: 'Every host in scope, its open ports, services, and proven identity (IP and hostname).' },
          { id: 'path', title: 'Next Steps', goto: '#/path', what: 'The coach. A ranked list of what to do next, each move expanding to the exact commands and a field note. The heart of obol.' },
          { id: 'evidence', title: 'Evidence', goto: '#/evidence', what: 'Paste any tool output here. obol reads it, mints facts, and the coach re-ranks. You never tell obol what you found, you show it.' },
        ] },
        { group: 'Analyze', subs: [
          { id: 'map', title: 'Map', goto: '#/map', what: 'A visual graph of the engagement: hosts, services, and how you moved between them.' },
          { id: 'domain', title: 'Domain', goto: '#/domain', what: 'Load a BloodHound collection and obol finds your route to Domain Admin, who to hunt next, and the exact abuse commands.' },
          { id: 'creds', title: 'Creds', goto: '#/creds', what: 'Every credential you have gathered, where it works, and whether it has been validated.' },
        ] },
        { group: 'Track And Report', subs: [
          { id: 'checklist', title: 'Checklist', goto: '#/checklist', what: 'The methodology checklist for the box, ticking itself off as you prove each step.' },
          { id: 'findings', title: 'Findings', goto: '#/findings', what: 'Proof-bound findings across every host, plus the Frameworks view: ATT&CK, Defensive, Compliance and CVEs.',
            subs: [
              { id: 'findings-list', title: 'Findings List', goto: '#/findings', set: { findingsView: 'findings' }, what: 'The proof-bound findings, grouped by severity or by target.' },
              { id: 'findings-attack', title: 'ATT&CK Matrix', goto: '#/findings', set: { findingsView: 'attack' }, what: 'The MITRE ATT&CK matrix, lit by what you did. Hover a cell for the engagement evidence, or for the obol command that performs it.' },
              { id: 'findings-defensive', title: 'Defensive (D3FEND)', goto: '#/findings', set: { findingsView: 'defensive' }, what: 'How a blue team catches and stops what you did, and the obol command each countermeasure would block.' },
              { id: 'findings-compliance', title: 'Compliance', goto: '#/findings', set: { findingsView: 'compliance' }, what: 'What your findings map to across NIST, CIS, PCI, CWE and OWASP, for the report.' },
              { id: 'findings-cves', title: 'CVEs And KEV', goto: '#/findings', set: { findingsView: 'cves' }, what: 'Detected CVEs, the actively-exploited ones (CISA KEV) first, with remediation.' },
            ] },
          { id: 'history', title: 'Run Log', goto: '#/history', what: 'Everything you have run this engagement, in order, so nothing is lost.' },
          { id: 'scoreboard', title: 'Scoreboard', goto: '#/scoreboard', what: 'Your progress against the box: phases reached, flags captured, what is left.' },
          { id: 'report', title: 'Report', goto: '#/report', what: 'Generates OSCP-style report content from your proven findings.' },
        ] },
      ] },
    { id: 'study', title: 'Learn', scope: 'global', goto: '#/study',
      what: 'Structured practice: study cards and drills that teach the methodology behind each move.',
      when: 'When you want to learn or revise a technique, away from a live box.' },
    { id: 'loadout', title: 'Loadout', scope: 'global', goto: '#/loadout',
      what: 'Your installed tools. Generates one setup script that installs and checks the kit obol expects.',
      when: 'Once, when you set up your attack VM, and whenever a command says a tool is missing.' },
    { id: 'tools', title: 'Tools', scope: 'global', goto: '#/tools',
      what: 'The command builders: pick a task and obol writes the exact command, filled from your target and parameters.',
      when: 'When you know what you want to run and want it filled in correctly.' },
    { id: 'workbench', title: 'Workbench', scope: 'global', goto: '#/workbench',
      what: 'Client-side borrowed back ends: build a shell, identify a hash, encode a payload, and more. They fill from your engagement and also work standalone.',
      when: 'When you need a tool mid-box and do not want to leave obol.',
      subs: [
        { id: 'wb-revshell', title: 'Reverse Shell Builder', goto: '#/workbench/revshell', what: 'Pick a shell and obol fills your LHOST and LPORT, with the matching listener and one-click base64 or PowerShell -EncodedCommand.' },
        { id: 'wb-hashid', title: 'Hash Identifier', goto: '#/workbench/hashid', what: 'Paste a hash; obol names it, gives the hashcat mode and john format, and a ready crack command.' },
        { id: 'wb-encoder', title: 'Encoder', goto: '#/workbench/encoder', what: 'Shows your input in every common encoding at once (base64, url, hex, base32, gzip, ROT, IFS evasion).' },
        { id: 'wb-decoder', title: 'Smart Decoder', goto: '#/workbench/decoder', what: 'Paste anything encoded and obol peels the layers to show what it really is.' },
        { id: 'wb-jwt', title: 'JWT Decoder', goto: '#/workbench/jwt', what: 'Decodes a JSON Web Token and flags weak signing. A decode, not a verification.' },
        { id: 'wb-gtfobins', title: 'GTFOBins Browser', goto: '#/workbench/gtfobins', what: 'The exact SUID or sudo escape for a binary, from the bundled GTFOBins data.' },
        { id: 'wb-wordlists', title: 'Wordlist Picker', goto: '#/workbench/wordlists', what: 'The right wordlist for the task, floated to your detected stack, with a sample command filled from the target.' },
        { id: 'wb-sqli', title: 'Manual SQLi', goto: '#/workbench/sqli', what: 'A strictly manual, exam-legal SQL injection walkthrough: you run each query, obol writes the next.' },
        { id: 'wb-explain', title: 'Explain Output', goto: '#/workbench/explain', what: 'Paste tool output and obol highlights the lines that minted each fact, saying what each proves and does not prove.' },
        { id: 'wb-spray', title: 'Spray Planner', goto: '#/workbench/spray', what: 'Turns a lockout policy into a safe password-spray schedule so you do not lock accounts.' },
      ] },
    { id: 'stuck', title: 'Stuck?', scope: 'global', goto: '#/stuck',
      what: 'Lost in a box? Answer Charon a few quick questions about what you have and he hands you ranked options, no pasting needed.',
      when: 'When you are stuck and want a path forward fast.' },
    { id: 'playbooks', title: 'Playbooks', scope: 'global', goto: '#/playbooks',
      what: 'End-to-end walkthroughs for common box shapes and attack chains.',
      when: 'When you want the whole route for a scenario, start to finish.' },
    { id: 'paste', title: 'Paste', scope: 'global', goto: '#/evidence',
      what: 'The Paste button in the header is the fastest way in: paste output from anywhere and obol mints facts from it, exactly like the Evidence box.',
      when: 'Any time you have output to show obol and do not want to navigate first.' },
    { id: 'search', title: 'Search', scope: 'global', goto: '#/home',
      what: 'The search button in the header jumps you to any command or surface by name.',
      when: 'When you know what you want and want to get there in one step.' },
  ];

  // obol-vocabulary glossary (H3 expands and cross-links). Pentest jargon stays in Learn / field notes.
  var GLOSSARY = [
    { term: 'Fact', def: 'One proven thing about the target that obol minted from output you pasted (a port, a hash, a credential). Facts drive everything; obol never guesses one.', see: ['evidence', 'path'] },
    { term: 'Move', def: 'A single step the coach can recommend, with the commands to run it and a field note. Moves become available as the facts they need are proven.', see: ['path'] },
    { term: 'The Ledger', def: 'The running set of facts for an engagement. Everything obol shows is a view over this one ledger.', see: ['evidence', 'creds'] },
    { term: 'The Coach', def: 'The ranker behind Next Steps. It reads your facts and orders the moves by what helps most right now, and explains why.', see: ['path'] },
    { term: 'Proof Gated', def: 'A move or command only appears once you have proven the facts it needs. obol will not hand you a step you cannot yet run.', see: ['path'] },
    { term: 'Settled', def: 'A question a move answered. Once a fact is proven, the probe that asked for it drops away so obol never nags you about it again.', see: ['path'] },
    { term: 'Phase', def: 'Where you are in the box: recon, enum, creds, access, escalate, loot. The coach leads with moves that fit your phase.', see: ['home', 'path'] },
    { term: 'Engagement', def: 'One box you are working. It holds its own ledger, targets, credentials and run log. You can keep several.', see: ['engagements'] },
    { term: 'Next Steps', def: 'The coach screen: the ranked list of what to do next. The heart of obol.', see: ['path'] },
    { term: 'Workbench', def: 'The global set of client-side tools (shell builder, hash ID, encoders) that fill from your engagement and also work standalone.', see: ['workbench'] },
  ];

  // The Charon quick-start card path (H5 expands; these are the first four things that matter).
  var QUICKSTART = [
    { id: 'q1', title: 'Show obol What You See', charon: 'Hand me a coin, or in your case, some output.', body: 'Run a scan, then hit Paste in the header and drop the output in. obol reads it and mints facts. You never type what you found, you show it.', goto: '#/evidence', cta: 'Open Evidence' },
    { id: 'q2', title: 'Read The Next Move', charon: 'The current is mapped. Follow it.', body: 'Next Steps ranks what to do now. Open the top move for the exact command and a field note on how to land it.', goto: '#/path', cta: 'Open Next Steps' },
    { id: 'q3', title: 'Reach For A Tool', charon: 'Every ferryman keeps his tools dry.', body: 'Need a reverse shell, a hash identified, a payload encoded? The Workbench fills from your box and works standalone too.', goto: '#/workbench', cta: 'Open Workbench' },
    { id: 'q4', title: 'Ask When You Are Stuck', charon: 'Lost on the water? Call out. I know these banks.', body: 'Stuck? asks a few quick questions and hands you ranked options, no pasting needed. I will be there.', goto: '#/stuck', cta: 'Open Stuck?' },
  ];

  OBOL.HELP = { charonIntro: CHARON_INTRO, triage: TRIAGE, sections: SECTIONS, glossary: GLOSSARY, quickstart: QUICKSTART };
  if (typeof module !== 'undefined' && module.exports) { module.exports = OBOL.HELP; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
