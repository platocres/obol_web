/* Start Here (#/start) - the newcomer front door.
 * Four self-placement doors up top with distinct full-spectrum accents:
 *   1. Try A Guided Mini-Lab (#10b981 Emerald) - Coach Move Cards + Emulated Terminal + Hand-Drawn Arrows
 *   2. New To All This (#06b6d4 Cyan) - 3-part beginner onramp (Intro + 5-Stage Lifecycle + Budget Roadmap)
 *   3. I Know The Basics (#a855f7 Violet) - OBOL Study Coach + 6-card spectrum Kali lab setup + references
 *   4. Prepping For An Exam (#f59e0b Amber-Gold) - OSCP, CPTS, PNPT playbooks + skill checklists
 */
(function (G) {
  'use strict';
  var OBOL = G.OBOL = G.OBOL || {};
  OBOL.routes = OBOL.routes || {};
  var U = OBOL.util;
  var esc = U.esc;

  // Chosen track persists for the session; null until a door is clicked.
  var _track = null; // null | 'minilab' | 'new' | 'basics' | 'exam' | 'all'
  var _budgetTier = 'free'; // 'free' | 'sub' | 'cert' | 'all'
  var _expandedExams = {};  // examId -> boolean (all collapsed initially like Next Steps cards)

  // Interactive Multi-Step Guided Mini-Lab state
  var _labId = 'linux-web';
  var _stepIdx = 0;
  var _selectedCardId = null;
  var _termInputVal = '';
  var _lastRanCardId = null;
  var _lastTermOutput = '';
  var _pasteBoxVal = '';
  var _pastedCardId = null;
  var _cardStates = {};       // cardId -> 'suppressed' | 'doctored' | 'completed'
  var _completedSteps = {};   // stepIdx -> true
  var _tutorialSubStep = 1;   // 1: Copy Cmd, 2: Paste & Run in Term, 3: Copy Term Output, 4: Paste in OBOL
  var _showArrows = true;     // Auto-on for Phase 1, auto-off on Phase 2+ (toggleable)

  function getMiniLab(res) {
    var labs = (res && res.miniLabs) || [];
    for (var i = 0; i < labs.length; i++) {
      if (labs[i].id === _labId) return labs[i];
    }
    return labs[0] || null;
  }

  function getCurrentStep(lab) {
    if (!lab || !Array.isArray(lab.steps) || !lab.steps.length) return null;
    if (_stepIdx < 0 || _stepIdx >= lab.steps.length) _stepIdx = 0;
    return lab.steps[_stepIdx];
  }

  function findCard(step, cardId) {
    if (!step || !Array.isArray(step.cards)) return null;
    for (var i = 0; i < step.cards.length; i++) {
      if (step.cards[i].id === cardId) return step.cards[i];
    }
    return null;
  }

  function getSelectedCard(step) {
    if (!step || !Array.isArray(step.cards) || !step.cards.length) return null;
    if (_selectedCardId) {
      var found = findCard(step, _selectedCardId);
      if (found) return found;
    }
    for (var i = 0; i < step.cards.length; i++) {
      if (_cardStates[step.cards[i].id] !== 'suppressed') return step.cards[i];
    }
    return step.cards[0];
  }

  function resetMiniLabState(newLabId) {
    if (newLabId) _labId = newLabId;
    _stepIdx = 0;
    _selectedCardId = null;
    _termInputVal = '';
    _lastRanCardId = null;
    _lastTermOutput = '';
    _pasteBoxVal = '';
    _pastedCardId = null;
    _cardStates = {};
    _completedSteps = {};
    _tutorialSubStep = 1;
    _showArrows = true;
  }

  // Match a command typed or pasted into the emulated terminal against the current step's cards
  function matchCommandToCard(cmdStr, step) {
    var raw = String(cmdStr || '').trim();
    if (!raw || !step || !Array.isArray(step.cards)) return null;
    var low = raw.toLowerCase();
    var i, c;
    // 1. Exact or substring match
    for (i = 0; i < step.cards.length; i++) {
      c = step.cards[i];
      if (low === c.cmd.toLowerCase() || c.cmd.toLowerCase().indexOf(low) >= 0 || low.indexOf(c.cmd.toLowerCase()) >= 0) {
        return c;
      }
    }
    // 2. Match by first tool token
    var firstTok = low.split(/\s+/)[0].replace(/^\.\//, '');
    for (i = 0; i < step.cards.length; i++) {
      c = step.cards[i];
      var cardFirst = c.cmd.toLowerCase().split(/\s+/)[0].replace(/^\.\//, '');
      if (firstTok && firstTok === cardFirst) return c;
    }
    return step.cards[0] || null;
  }

  // Hand-drawn SVG curved arrow + callout pill for the Phase 1 interactive tour
  function handArrowCallout(num, text, dir) {
    var svgPath = dir === 'down'
      ? '<svg class="start-hand-svg" viewBox="0 0 54 36" fill="none" aria-hidden="true"><path d="M6 4 C 20 4, 34 10, 38 28" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-dasharray="4 2"/><path d="M31 23 L 38 30 L 44 21" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      : '<svg class="start-hand-svg" viewBox="0 0 54 36" fill="none" aria-hidden="true"><path d="M48 30 C 30 30, 18 22, 12 8" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-dasharray="4 2"/><path d="M6 15 L 11 6 L 20 12" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    return '<div class="start-hand-callout">' +
      '<span class="start-hand-step">Try It #' + esc(num) + '</span>' +
      '<span class="start-hand-text">' + esc(text) + '</span>' +
      svgPath +
    '</div>';
  }

  function resCard(r) {
    var rc = r.color || (r.free ? '#10b981' : '#a855f7');
    var cls = 'start-rescard' + (r.free ? ' free' : '');
    return '<a class="' + cls + '" style="--rc:' + U.attr(rc) + '" href="' + U.attr(r.url) + '" target="_blank" rel="noopener noreferrer">' +
      '<div class="start-rc-top">' +
        (r.badge ? '<span class="start-rc-badge">' + esc(r.badge) + '</span>' : '') +
        '<span class="start-rc-t">' + esc(r.name) + '</span>' +
        (r.cost ? '<span class="start-rc-cost">' + esc(r.cost) + '</span>' : '') +
      '</div>' +
      '<div class="start-rc-d">' + esc(r.blurb) + '</div>' +
      '<span class="start-rc-go">Visit site ' + OBOL.ic('ext') + '</span>' +
    '</a>';
  }

  // High-Level Intro to Ethical Hacking & OBOL ("New To All This")
  function introSection(res) {
    var list = (res && res.intro) || [];
    if (!list.length) return '';
    return '<section class="start-panel start-reveal" style="--way:#06b6d4">' +
      '<div class="start-panel-h">' + OBOL.ic('shield') + '<span>What Is Offensive Security &amp; How Does OBOL Help?</span></div>' +
      '<p class="start-lede">If you are brand new to cybersecurity or ethical hacking, start with these three core ideas before touching any tools:</p>' +
      '<div class="start-intro-grid">' +
        list.map(function (item) {
          var c = item.color || '#06b6d4';
          return '<div class="start-intro-card" style="--ic-col:' + U.attr(c) + '">' +
            '<div class="start-intro-top">' +
              '<span class="start-intro-icon">' + OBOL.ic(item.ic || 'shield') + '</span>' +
              '<span class="start-rc-badge" style="--rc:' + U.attr(c) + '">' + esc(item.badge || '') + '</span>' +
            '</div>' +
            '<h3 class="start-intro-t">' + esc(item.title) + '</h3>' +
            '<p class="start-intro-d">' + esc(item.body) + '</p>' +
          '</div>';
        }).join('') +
      '</div>' +
    '</section>';
  }

  function budgetStepCard(s) {
    var rc = s.color || '#10b981';
    var inner =
      '<div class="start-rc-top">' +
        '<div class="start-bstep-badges">' +
          (s.step ? '<span class="start-bstep-num">' + esc(s.step) + '</span>' : '') +
          (s.badge ? '<span class="start-rc-badge">' + esc(s.badge) + '</span>' : '') +
        '</div>' +
        '<span class="start-rc-t">' + esc(s.name || s.title || '') + '</span>' +
        (s.cost ? '<span class="start-rc-cost">' + esc(s.cost) + '</span>' : '') +
      '</div>' +
      '<div class="start-rc-d">' + esc(s.blurb || '') + '</div>';

    if (s.url) {
      return '<a class="start-rescard start-bstep-card" style="--rc:' + U.attr(rc) + '" href="' + U.attr(s.url) + '" target="_blank" rel="noopener noreferrer">' +
        inner +
        '<span class="start-rc-go">' + esc(s.actionLabel || 'Visit site') + ' ' + OBOL.ic('ext') + '</span>' +
      '</a>';
    }
    if (s.href) {
      return '<a class="start-rescard start-bstep-card" style="--rc:' + U.attr(rc) + '" href="' + U.attr(s.href) + '">' +
        inner +
        '<span class="start-rc-go">' + esc(s.actionLabel || 'Open in OBOL') + ' ' + OBOL.ic('arrow') + '</span>' +
      '</a>';
    }
    return '<button type="button" class="start-rescard start-bstep-card" style="--rc:' + U.attr(rc) + '" data-switch-track="' + U.attr(s.switchTrack || 'minilab') + '">' +
      inner +
      '<span class="start-rc-go">' + esc(s.actionLabel || 'Launch in OBOL') + ' ' + OBOL.ic('arrow') + '</span>' +
    '</button>';
  }

  // Interactive Budget Switcher + Clickable Step-by-Step Cards
  function budgetSection(res) {
    var tiers = (res && res.budgetTiers) || [];
    if (!tiers.length) return '';

    var tabsHtml = tiers.map(function (t) {
      var on = (_budgetTier === t.id) ? ' on' : '';
      var col = t.color || '#10b981';
      return '<button type="button" class="start-dry-tab start-budget-tab' + on + '" style="--way:' + U.attr(col) + '" data-budget-tier="' + U.attr(t.id) + '" aria-pressed="' + (_budgetTier === t.id ? 'true' : 'false') + '">' +
        '<span class="start-budget-tab-badge">' + esc(t.badge) + '</span>' +
        '<span class="start-ml-tab-t">' + esc(t.title) + '</span>' +
      '</button>';
    }).join('') +
    '<button type="button" class="start-dry-tab start-budget-tab' + (_budgetTier === 'all' ? ' on' : '') + '" style="--way:#38bdf8" data-budget-tier="all" aria-pressed="' + (_budgetTier === 'all' ? 'true' : 'false') + '">' +
      '<span class="start-budget-tab-badge">Compare All</span>' +
      '<span class="start-ml-tab-t">Show All 3 Budget Tracks</span>' +
    '</button>';

    var visibleTiers = (_budgetTier === 'all')
      ? tiers
      : tiers.filter(function (t) { return t.id === _budgetTier; });
    if (!visibleTiers.length) visibleTiers = [tiers[0]];

    var tiersBodyHtml = visibleTiers.map(function (t) {
      var col = t.color || '#10b981';
      return '<div class="start-budget-stage" style="--bcol:' + U.attr(col) + '">' +
        '<div class="start-budget-banner">' +
          '<span class="start-budget-badge">' + esc(t.badge) + '</span>' +
          '<div class="start-budget-banner-text">' +
            '<h3 class="start-budget-t">' + esc(t.title) + '</h3>' +
            '<p class="start-budget-sub">' + esc(t.sub) + '</p>' +
          '</div>' +
        '</div>' +
        '<div class="start-grid start-bstep-grid">' +
          (t.steps || []).map(budgetStepCard).join('') +
        '</div>' +
      '</div>';
    }).join('');

    return '<section class="start-panel start-reveal" style="--way:#10b981">' +
      '<div class="start-panel-h">' + OBOL.ic('coin') + '<span>How To Get Started Based On Your Budget</span></div>' +
      '<p class="start-lede">You do not need thousands of dollars to learn offensive security. Select your budget tab below to unlock a step-by-step sequence of interactive courses and tools with direct links:</p>' +
      '<div class="start-dry-tabs start-budget-tabs" role="tablist" aria-label="Select your budget tier">' + tabsHtml + '</div>' +
      tiersBodyHtml +
    '</section>';
  }

  // Door 1: Interactive Multi-Step Guided Mini-Lab Simulator
  function miniLabSection(res) {
    var labs = (res && res.miniLabs) || [];
    if (!labs.length) return '';
    var lab = getMiniLab(res);
    var step = getCurrentStep(lab);
    var selCard = getSelectedCard(step);
    if (!lab || !step || !selCard) return '';

    var isLastStep = (_stepIdx === lab.steps.length - 1);
    var pastedCard = _pastedCardId ? findCard(step, _pastedCardId) : null;
    var stepDone = !!_completedSteps[_stepIdx] || !!(pastedCard && pastedCard.kind === 'advance');

    var labTabsHtml = labs.map(function (l) {
      var on = (l.id === lab.id) ? ' on' : '';
      var lcol = l.color || '#10b981';
      return '<button type="button" class="start-dry-tab' + on + '" style="--way:' + U.attr(lcol) + '" data-minilab-select="' + U.attr(l.id) + '" data-dryrun-scenario="' + U.attr(l.id) + '" aria-pressed="' + (l.id === lab.id ? 'true' : 'false') + '">' +
        '<span class="start-ml-tab-t">' + esc(l.title) + '</span>' +
        '<span class="start-dry-ip">' + esc(l.target) + ' - ' + esc(l.os) + '</span>' +
      '</button>';
    }).join('');

    var stepperCols = ['#06b6d4', '#3b82f6', '#a855f7', '#f43f5e'];
    var stepperHtml = lab.steps.map(function (s, idx) {
      var isCur = (idx === _stepIdx);
      var isDone = !!_completedSteps[idx] || (isCur && stepDone);
      var scol = stepperCols[idx % stepperCols.length];
      var cls = 'start-ml-step-pill' + (isCur ? ' on' : '') + (isDone ? ' done' : '');
      return '<button type="button" class="' + cls + '" style="--way:' + scol + '" data-minilab-step="' + idx + '">' +
        '<span class="start-ml-step-num">' + (isDone ? 'COMPLETED' : ('Phase ' + (idx + 1))) + '</span>' +
        '<span class="start-ml-step-name">' + esc(s.title) + '</span>' +
      '</button>';
    }).join('');

    var factsHtml = (step.knownFacts || []).map(function (f) {
      return '<span class="start-ml-fact-chip">' + esc(f) + '</span>';
    }).join('');

    // Render authentic Coach Move Cards on the left pane
    var cardsHtml = (step.cards || []).map(function (c, cIdx) {
      var state = _cardStates[c.id] || '';
      var isSel = (c.id === selCard.id);
      var cCol = c.color || '#06b6d4';

      // If this card was tested and ruled out ('suppressed'), render a collapsed ruled-out strip!
      if (state === 'suppressed') {
        return '<div class="start-mcard start-mcard-suppressed" style="--mc:#64748b">' +
          '<div class="start-mc-sup-head">' +
            '<span class="start-mc-sup-badge">Ruled Out &amp; Suppressed</span>' +
            '<span class="start-mc-sup-title">' + esc(c.rank + ' ' + c.title) + '</span>' +
          '</div>' +
          '<p class="start-mc-sup-note">' + esc(c.suppressNote || 'Yielded no actionable lead; suppressed by OBOL.') + '</p>' +
        '</div>';
      }

      var showArrow1 = (_showArrows && _tutorialSubStep === 1 && cIdx === 0);
      var doctorBanner = '';
      if (state === 'doctored' && c.doctor) {
        doctorBanner =
          '<div class="start-mc-doctor">' +
            '<div class="start-mc-doc-h">' + OBOL.ic('shield') + '<span>' + esc(c.doctor.title) + '</span></div>' +
            '<p class="start-mc-doc-p"><b>Why it failed:</b> ' + esc(c.doctor.diagnosis) + '</p>' +
            '<p class="start-mc-doc-p"><b>OBOL Doctor Fix:</b> ' + esc(c.doctor.fix) + '</p>' +
            '<button type="button" class="start-mc-doc-btn" data-minilab-pick-optimal>' +
              OBOL.ic('zap') + '<span>Focus the Working Move Card (#1)</span>' +
            '</button>' +
          '</div>';
      }

      return '<div class="start-mcard' + (isSel ? ' on' : '') + (state === 'doctored' ? ' is-doctored' : '') + '" style="--mc:' + U.attr(cCol) + '" data-minilab-opt="' + U.attr(c.id) + '">' +
        (showArrow1 ? handArrowCallout('1', 'Click "Copy Command" on this Move Card (or select the command text)', 'down') : '') +
        '<div class="start-mc-head">' +
          '<span class="start-mc-rank">' + esc(c.rank || ('#' + (cIdx + 1))) + '</span>' +
          '<span class="start-mc-title">' + esc(c.title) + '</span>' +
          (state === 'completed' ? '<span class="start-mc-done-pill">Minted Facts!</span>' : '') +
        '</div>' +
        '<p class="start-mc-why">' + esc(c.why || '') + '</p>' +
        '<div class="start-mc-cmdbar">' +
          '<code class="start-mc-cmd">$ ' + esc(c.cmd) + '</code>' +
          '<div class="start-mc-cmd-btns">' +
            '<button type="button" class="start-mc-btn start-mc-copy" data-mc-copy="' + U.attr(c.id) + '">' +
              OBOL.ic('clip') + '<span>Copy Command</span>' +
            '</button>' +
            '<button type="button" class="start-mc-btn start-mc-fill" data-mc-fill="' + U.attr(c.id) + '" title="Auto-type and run in the emulated terminal">' +
              OBOL.ic('terminal') + '<span>Paste &amp; Run in Terminal</span>' +
            '</button>' +
          '</div>' +
        '</div>' +
        (c.fieldNote
          ? '<details class="start-mc-fn"><summary>Field Notes (What each flag does)</summary><div class="start-mc-fn-body">' + esc(c.fieldNote) + '</div></details>'
          : '') +
        doctorBanner +
      '</div>';
    }).join('');

    // Right Column: Emulated Kali Terminal + OBOL Paste Box
    var showArrow2 = (_showArrows && _tutorialSubStep === 2);
    var showArrow3 = (_showArrows && _tutorialSubStep === 3);
    var showArrow4 = (_showArrows && _tutorialSubStep === 4);

    var termDisplayCmd = _termInputVal || (_lastRanCardId ? (findCard(step, _lastRanCardId) || selCard).cmd : '');
    var termHistoryHtml = _lastTermOutput
      ? '<div class="start-term-out-wrap">' +
          (showArrow3 ? handArrowCallout('3', 'Click "Copy Output" (or highlight the terminal output below)', 'down') : '') +
          '<div class="start-term-out-bar">' +
            '<span class="start-term-out-lbl">Terminal Output (kali@kali):</span>' +
            '<div class="start-term-out-btns">' +
              '<button type="button" class="start-mc-btn" data-term-copy>' + OBOL.ic('clip') + '<span>Copy Output</span></button>' +
              '<button type="button" class="start-mc-btn start-mc-fill" data-term-send-obol>' + OBOL.ic('zap') + '<span>Auto-Paste Into OBOL</span></button>' +
            '</div>' +
          '</div>' +
          '<pre class="start-dry-pre" id="start-ml-term-pre">kali@kali:~$ ' + esc((findCard(step, _lastRanCardId) || selCard).cmd) + '\n' + esc(_lastTermOutput) + '</pre>' +
        '</div>'
      : '<div class="start-term-empty">' +
          'Terminal ready. Copy a command from a Move Card on the left, paste it into the <code>kali@kali:~$</code> prompt below (or click <b>Paste &amp; Run in Terminal</b>), and press <b>Enter</b>.' +
        '</div>';

    // Outcome callout when output is processed in OBOL
    var outcomeHtml = '';
    if (pastedCard && pastedCard.kind === 'advance' && pastedCard.explain) {
      var mintedHtml = (pastedCard.mintedFacts || []).map(function (f) {
        return '<li><code class="start-dry-fk">' + esc(f.kind) + '</code> <span>' + esc(f.detail) + '</span></li>';
      }).join('');
      var nextStep = (!isLastStep && lab.steps[_stepIdx + 1]) ? lab.steps[_stepIdx + 1] : null;
      outcomeHtml =
        '<div class="start-ml-outcome start-ml-explain">' +
          '<div class="start-ml-out-head">' +
            OBOL.ic('compass') +
            '<span>Pause &amp; Explain: What OBOL Just Learned &amp; Why</span>' +
          '</div>' +
          '<div class="start-dry-result">' +
            '<div class="start-dry-col">' +
              '<div class="start-dry-kicker">Step 2A: Facts OBOL Extracted From Your Paste</div>' +
              '<ul class="start-dry-facts">' + mintedHtml + '</ul>' +
              '<p class="start-dry-move-why"><b>What happened on the target:</b> ' + esc(pastedCard.explain.whatHappened) + '</p>' +
            '</div>' +
            '<div class="start-dry-col">' +
              '<div class="start-dry-kicker">Step 2B: How OBOL Helped &amp; Feature Spotlight</div>' +
              '<p class="start-dry-move-why">' + esc(pastedCard.explain.howObolHelped) + '</p>' +
              '<div class="start-ml-spotlight-box">' +
                '<span class="start-dry-kicker">OBOL Feature Spotlight</span>' +
                '<p class="start-dry-move-why">' + esc(pastedCard.explain.featureSpotlight) + '</p>' +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="start-dry-actions">' +
            (nextStep
              ? '<button type="button" class="start-spot-cta start-dry-btn" data-minilab-next>' +
                  '<span>Continue to ' + esc(nextStep.phase) + ': ' + esc(nextStep.title) + '</span>' + OBOL.ic('arrow') +
                '</button>'
              : '<div class="start-ml-complete-bar">' +
                  '<div class="start-ml-complete-msg">' +
                    '<b>Mini-Lab Compromised!</b> You took <code>' + esc(lab.target) + ' (' + esc(lab.hostname) + ')</code> from a cold IP to full root/SYSTEM and captured both <code>local.txt</code> and <code>proof.txt</code>.' +
                  '</div>' +
                  '<div class="start-ml-complete-btns">' +
                    '<button type="button" class="start-spot-cta start-dry-btn" data-minilab-launch="' + U.attr(lab.id) + '" data-dryrun-launch="' + U.attr(lab.id) + '">' +
                      '<span>Open This Target in Real OBOL (#/path)</span>' + OBOL.ic('arrow') +
                    '</button>' +
                    '<button type="button" class="start-dry-reset" data-minilab-reset data-dryrun-reset>Restart Mini-Lab</button>' +
                  '</div>' +
                '</div>') +
          '</div>' +
        '</div>';
    }

    return '<section class="start-panel start-reveal start-dryrun" style="--way:#10b981">' +
      '<div class="start-ml-header">' +
        '<div>' +
          '<div class="start-panel-h">' + OBOL.ic('zap') + '<span>Interactive Guided Mini-Labs (Cockpit Move Cards + Emulated Terminal)</span></div>' +
          '<p class="start-lede">Experience what working a box with OBOL actually feels like. Copy a command from an <b>OBOL Cockpit Move Card</b> on the left, paste &amp; run it in the <b>Emulated Kali Terminal</b> on the right, and paste the output back into OBOL to watch facts mint, dead-ends fall away, and Field Doctors diagnose roadblocks.</p>' +
        '</div>' +
        '<div class="start-ml-head-btns">' +
          '<button type="button" class="start-dry-reset' + (_showArrows ? ' on' : '') + '" data-minilab-arrows aria-pressed="' + (_showArrows ? 'true' : 'false') + '">' +
            'Tutorial Arrows: ' + (_showArrows ? 'ON' : 'OFF') +
          '</button>' +
          '<button type="button" class="start-dry-reset" data-minilab-reset data-dryrun-reset>Reset Mini-Lab</button>' +
        '</div>' +
      '</div>' +
      '<div class="start-dry-tabs start-ml-tabs" role="tablist" aria-label="Choose a guided mini-lab">' + labTabsHtml + '</div>' +
      '<div class="start-ml-summary">' +
        '<b>' + esc(lab.title) + '</b> (' + esc(lab.hostname) + ' / <code>' + esc(lab.target) + '</code>): ' + esc(lab.summary) +
      '</div>' +
      '<div class="start-ml-stepper" role="navigation" aria-label="Mini-lab phases">' + stepperHtml + '</div>' +
      '<div class="start-ml-workbench">' +
        '<div class="start-ml-coach">' +
          '<div class="start-dry-kicker">' + esc(step.phase) + ' - OBOL Cockpit</div>' +
          '<h3 class="start-ml-step-h">' + esc(step.title) + '</h3>' +
          '<p class="start-ml-prompt">' + esc(step.prompt) + '</p>' +
          '<div class="start-ml-known">' +
            '<span class="start-ml-known-lbl">Facts Minted So Far:</span> ' + factsHtml +
          '</div>' +
          '<div class="start-ml-cards-list">' + cardsHtml + '</div>' +
          ((step.cards || []).length === 1
            ? '<div class="start-ml-loop-guide">' +
                '<div class="start-dry-kicker">How the OBOL Workbench Loop Works (3 Steps)</div>' +
                '<div class="start-ml-loop-steps">' +
                  '<div class="start-ml-loop-item" style="--lcol:#06b6d4"><b>1. Copy Command</b><span>Copy the command from the Move Card above (or click Paste &amp; Run).</span></div>' +
                  '<div class="start-ml-loop-item" style="--lcol:#10b981"><b>2. Run in Terminal</b><span>Run it in the emulated Kali terminal on the right and copy the output.</span></div>' +
                  '<div class="start-ml-loop-item" style="--lcol:#a855f7"><b>3. Paste Into OBOL</b><span>Paste the output into the OBOL QuickPaste box to mint facts and unlock Phase 2!</span></div>' +
                '</div>' +
              '</div>'
            : '') +
        '</div>' +
        '<div class="start-ml-term-col">' +
          '<div class="start-term-window">' +
            '<div class="start-term-titlebar">' +
              '<span class="start-term-dots"><i></i><i></i><i></i></span>' +
              '<span class="start-term-title">kali@kali: ~ (' + esc(lab.target) + ')</span>' +
              '<button type="button" class="start-term-clear" data-term-clear>Clear</button>' +
            '</div>' +
            '<div class="start-term-body">' +
              (showArrow2 ? handArrowCallout('2', 'Paste the command here (Ctrl+V) and press Enter or click Run', 'down') : '') +
              '<div class="start-term-prompt-row">' +
                '<span class="start-term-ps1">kali@kali:~$</span>' +
                '<input type="text" id="start-ml-term-in" class="start-term-input" value="' + U.attr(termDisplayCmd) + '" placeholder="Paste command here (Ctrl+V) and press Enter..." autocomplete="off" spellcheck="false" />' +
                '<button type="button" class="start-term-run-btn" data-minilab-run>' + OBOL.ic('play') + '<span>Run</span></button>' +
              '</div>' +
              termHistoryHtml +
            '</div>' +
          '</div>' +
          '<div class="start-ml-pastebox">' +
            (showArrow4 ? handArrowCallout('4', 'Paste the terminal output here (Ctrl+V) and click Process Output in OBOL!', 'down') : '') +
            '<div class="start-ml-paste-head">' +
              '<span class="start-dry-kicker">OBOL QuickPaste Box (Paste Terminal Output Here)</span>' +
              (pastedCard ? '<span class="start-ml-pasted-badge">Processed: ' + esc(pastedCard.title) + '</span>' : '') +
            '</div>' +
            '<textarea id="start-ml-paste-ta" class="start-paste-ta" rows="4" placeholder="Paste the output from the emulated terminal here (Ctrl+V)...">' + esc(_pasteBoxVal) + '</textarea>' +
            '<div class="start-dry-prompt">' +
              '<button type="button" class="start-spot-cta start-dry-btn" data-minilab-paste data-dryrun-paste>' +
                OBOL.ic('zap') + '<span>Process Output in OBOL</span>' +
              '</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      outcomeHtml +
    '</section>';
  }

  function practiceSection(res) {
    var practice = (res && res.practice) || [];
    return '<section class="start-panel start-reveal" style="--way:#f59e0b">' +
      '<div class="start-panel-h">' + OBOL.ic('flag') + '<span>Live Practice Ranges (Where You Pair OBOL With Target Machines)</span></div>' +
      '<p class="start-lede">Once you are ready for hands-on targets, open any of these 12 practice ranges alongside OBOL to practice Linux CLI, PowerShell, web vulnerabilities, Active Directory, and full boot-to-root machines:</p>' +
      '<div class="start-grid start-practice-grid">' + practice.map(resCard).join('') + '</div>' +
      '<p class="start-verified">Links and pricing verified ' + esc(res.verified) + '.</p>' +
    '</section>';
  }

  function labSection(res) {
    var steps = (res && res.lab) || [];
    var ctx = (res && res.labContext) || {};
    return '<section class="start-panel start-reveal" style="--way:#3b82f6">' +
      '<div class="start-panel-h">' + OBOL.ic('terminal') + '<span>Set Up Your Own Local Kali Lab (When &amp; How)</span></div>' +
      '<p class="start-lede">Do you need to build a local virtual machine right now? Compare the two options below:</p>' +
      '<div class="start-lab-ctx-grid">' +
        '<div class="start-lab-ctx-card ctx-browser" style="--way:#10b981">' +
          '<div class="start-dry-kicker">Option A: Browser Terminals (0 Mins Setup)</div>' +
          '<p>' + esc(ctx.browserZeroSetup || '') + '</p>' +
        '</div>' +
        '<div class="start-lab-ctx-card ctx-vm" style="--way:#a855f7">' +
          '<div class="start-dry-kicker">Option B: Your Own Local Kali VM (~45 Mins Setup)</div>' +
          '<p>' + esc(ctx.localVmWhen || '') + '</p>' +
        '</div>' +
      '</div>' +
      '<div class="start-lab-cards">' +
        steps.map(function (s) {
          var scol = s.color || '#38bdf8';
          var ctaHtml = '';
          if (s.cta && s.cta.href) {
            var extAttrs = s.cta.external ? ' target="_blank" rel="noopener noreferrer"' : '';
            var icon = s.cta.external ? OBOL.ic('ext') : OBOL.ic('arrow');
            ctaHtml = '<div class="start-step-cta">' +
              '<a class="start-step-link" style="--way:' + U.attr(scol) + '" href="' + U.attr(s.cta.href) + '"' + extAttrs + '>' + esc(s.cta.label) + ' ' + icon + '</a>' +
            '</div>';
          }
          return '<div class="start-lab-card" style="--way:' + U.attr(scol) + '">' +
            '<div class="start-lab-card-top">' +
              '<span class="start-lab-step-num">' + OBOL.ic(s.ic || 'terminal') + ' <span>Step ' + esc(s.step || '') + '</span></span>' +
              (s.badge ? '<span class="start-rc-badge" style="--rc:' + U.attr(scol) + '">' + esc(s.badge) + '</span>' : '') +
            '</div>' +
            '<div class="start-step-t">' + esc(s.title) + '</div>' +
            '<div class="start-step-d">' + s.body + '</div>' +
            ctaHtml +
          '</div>';
        }).join('') +
      '</div>' +
    '</section>';
  }

  function examSection(res) {
    var wf = (res && res.examWorkflow) || [];
    var exams = (res && res.exams) || [];
    var wfHtml = wf.length
      ? '<section class="start-panel start-reveal" style="--way:#f59e0b">' +
          '<div class="start-panel-h">' + OBOL.ic('compass') + '<span>How To Use OBOL On Exam Day</span></div>' +
          '<p class="start-lede">OBOL runs 100% offline in your browser with zero external API calls or LLM queries, making it a deterministic reference and note-taking workbench. Follow this 4-step exam workflow:</p>' +
          '<div class="start-exam-wf-grid">' +
            wf.map(function (w) {
              var wcol = w.color || '#f59e0b';
              return '<div class="start-wf-card" style="--way:' + U.attr(wcol) + '">' +
                '<div class="start-wf-top">' +
                  (w.step ? '<span class="start-wf-step">' + esc(w.step) + '</span>' : '') +
                  '<span class="start-wf-title">' + esc(w.title) + '</span>' +
                '</div>' +
                '<p class="start-wf-body">' + esc(w.body) + '</p>' +
                (w.href ? '<a class="start-wf-link" href="' + U.attr(w.href) + '">' + esc(w.linkLabel || 'Open in OBOL') + ' ' + OBOL.ic('arrow') + '</a>' : '') +
              '</div>';
            }).join('') +
          '</div>' +
        '</section>'
      : '';

    var examsHtml = '<section class="start-panel start-reveal" style="--way:#f43f5e">' +
      '<div class="start-panel-h">' + OBOL.ic('award') + '<span>Certification Exam Playbooks (OSCP, CPTS &amp; PNPT)</span></div>' +
      '<p class="start-lede">Click any certification playbook card below to expand its full scoring breakdown, rules of engagement, Study skill-readiness checklist, and one-click mock exam layout:</p>' +
      '<div class="start-exam-deck">' +
        exams.map(function (ex) {
          var ecol = ex.color || '#f59e0b';
          var isOpen = !!_expandedExams[ex.id];
          var fmt = ex.format || {};
          var pillsHtml = (ex.pills || []).map(function (p) {
            return '<div class="start-exam-pill">' +
              '<span class="start-exam-pill-k">' + esc(p.label) + ':</span> ' +
              '<span class="start-exam-pill-v">' + esc(p.val) + '</span>' +
            '</div>';
          }).join('');
          var rulesHtml = (ex.rules || []).map(function (r) {
            return '<li>' + esc(r) + '</li>';
          }).join('');
          var skillsHtml = (ex.skills || []).map(function (sk) {
            return '<a class="start-exam-skill" style="--way:' + U.attr(ecol) + '" href="' + U.attr(sk.href) + '">' +
              OBOL.ic('book') + '<span>' + esc(sk.label) + '</span>' + OBOL.ic('arrow') +
            '</a>';
          }).join('');
          var tpl = ex.practiceTemplate;

          var expandedBody = isOpen
            ? '<div class="start-exam-body">' +
                '<div class="start-exam-meta-grid">' +
                  '<div class="start-exam-meta-box">' +
                    '<span class="start-dry-kicker">Time &amp; Format</span>' +
                    '<p>' + esc(fmt.time || '') + '</p>' +
                  '</div>' +
                  '<div class="start-exam-meta-box">' +
                    '<span class="start-dry-kicker">Passing Score</span>' +
                    '<p>' + esc(fmt.passingScore || '') + '</p>' +
                  '</div>' +
                  '<div class="start-exam-meta-box">' +
                    '<span class="start-dry-kicker">Environment Structure</span>' +
                    '<p>' + esc(fmt.structure || '') + '</p>' +
                  '</div>' +
                  '<div class="start-exam-meta-box">' +
                    '<span class="start-dry-kicker">Winning Strategy</span>' +
                    '<p>' + esc(fmt.winningMath || '') + '</p>' +
                  '</div>' +
                '</div>' +
                '<div class="start-exam-cols">' +
                  '<div class="start-exam-col">' +
                    '<div class="start-dry-kicker">Rules of Engagement &amp; Proof Requirements</div>' +
                    '<ul class="start-exam-rules">' + rulesHtml + '</ul>' +
                  '</div>' +
                  '<div class="start-exam-col">' +
                    '<div class="start-dry-kicker">Core Skill-Readiness Checklist (Open in Study)</div>' +
                    '<div class="start-exam-skills">' + skillsHtml + '</div>' +
                  '</div>' +
                '</div>' +
                (tpl
                  ? '<div class="start-exam-sim-bar">' +
                      '<div class="start-exam-sim-info">' +
                        '<b>Mock Practice Template: ' + esc(tpl.name) + '</b>' +
                        '<span>Scope: <code>' + esc(tpl.targets) + '</code> (' + esc(tpl.domain) + ') - ' + esc(tpl.note) + '</span>' +
                      '</div>' +
                      '<button type="button" class="start-spot-cta start-dry-btn" data-exam-launch="' + U.attr(ex.id) + '" data-box-launch="' + U.attr(ex.id) + '">' +
                        '<span>Launch Mock Exam Engagement</span>' + OBOL.ic('arrow') +
                      '</button>' +
                    '</div>'
                  : '') +
                (ex.listNote ? '<p class="start-exam-list">' + esc(ex.listNote) + '</p>' : '') +
              '</div>'
            : '';

          return '<div class="start-exam-card' + (isOpen ? ' open' : '') + '" style="--way:' + U.attr(ecol) + '">' +
            '<div class="start-exam-sum" data-exam-toggle="' + U.attr(ex.id) + '" role="button" tabindex="0" aria-expanded="' + (isOpen ? 'true' : 'false') + '">' +
              '<div class="start-exam-sum-top">' +
                '<div class="start-exam-sum-titles">' +
                  (ex.badge ? '<span class="start-rc-badge" style="--rc:' + U.attr(ecol) + '">' + esc(ex.badge) + '</span>' : '') +
                  '<span class="start-exam-name">' + esc(ex.name) + '</span>' +
                  '<span class="start-exam-kick">' + esc(ex.kicker) + '</span>' +
                '</div>' +
                '<div class="start-exam-sum-actions">' +
                  (tpl
                    ? '<button type="button" class="start-mc-btn start-mc-fill" data-exam-launch="' + U.attr(ex.id) + '">' +
                        OBOL.ic('zap') + '<span>Launch Mock Sim</span>' +
                      '</button>'
                    : '') +
                  '<span class="start-exam-expand-btn">' +
                    '<span>' + (isOpen ? 'Collapse Playbook' : 'Expand Playbook') + '</span>' +
                    '<span class="start-exam-chev">' + (isOpen ? '▾' : '▸') + '</span>' +
                  '</span>' +
                '</div>' +
              '</div>' +
              '<div class="start-exam-pills">' + pillsHtml + '</div>' +
            '</div>' +
            expandedBody +
          '</div>';
        }).join('') +
      '</div>' +
    '</section>';

    return wfHtml + examsHtml;
  }

  function deeperSection(res) {
    return '<section class="start-panel start-reveal" style="--way:#a855f7">' +
      '<div class="start-panel-h">' + OBOL.ic('layers') + '<span>Go Deeper (Walkthroughs, Video Indexes &amp; Methodology Guides)</span></div>' +
      '<p class="start-lede">Free educational blogs, searchable video walkthrough indexes, and visual methodology wikis to deepen your understanding when researching how an attack or protocol works:</p>' +
      '<div class="start-grid start-deeper-grid">' + res.deeper.map(resCard).join('') + '</div>' +
    '</section>';
  }

  function studySpotlight() {
    var tracks = [
      { title: 'Recon & Service Enum', sub: 'Nmap, SMB, SNMP, DNS & Banner Triage', col: '#06b6d4', href: '#/study/topic/recon' },
      { title: 'Web Exploitation', sub: 'Fuzzing, LFI, SQLi, Uploads & Auth Bypass', col: '#3b82f6', href: '#/study/topic/web-exploitation' },
      { title: 'Active Directory', sub: 'Kerberoast, ACLs, Delegation, ADCS & Lateral', col: '#a855f7', href: '#/study/topic/active-directory' },
      { title: 'Linux & Windows PrivEsc', sub: 'SUID, Sudo, Cron, SeImpersonate & Services', col: '#f43f5e', href: '#/study/topic/linux-privesc' },
      { title: 'Pivoting & Port Forwards', sub: 'Ligolo-ng Interfaces, Chisel & SOCKS', col: '#f59e0b', href: '#/study/topic/pivoting' },
      { title: 'Command Builder & Drills', sub: 'Flag-by-flag syntax breakdown & recall quiz', col: '#10b981', href: '#/study' }
    ];
    return '<section class="start-panel start-spotlight start-reveal" style="--way:#a855f7">' +
      '<div class="start-spot-left">' +
        '<div class="start-spot-head">' +
          '<div class="start-spot-ic">' + OBOL.ic('book') + '</div>' +
          '<div>' +
            '<div class="start-panel-h"><span>Start inside OBOL</span></div>' +
            '<h2 class="start-spot-h">Study - OBOL\'s built-in interactive technique coach</h2>' +
          '</div>' +
        '</div>' +
        '<p class="start-spot-d">Before you spin up a target VM, walk the core techniques right here in your browser. Inspect why each move works, explore flag-by-flag command breakdowns, and test your muscle memory in interactive Practice drills.</p>' +
        '<div class="start-spot-actions">' +
          '<a class="start-spot-cta" href="#/study"><span>Open Study Coach (#/study)</span>' + OBOL.ic('arrow') + '</a>' +
        '</div>' +
      '</div>' +
      '<div class="start-spot-tracks">' +
        tracks.map(function (t) {
          return '<a class="start-spot-track" style="--stcol:' + U.attr(t.col) + '" href="' + U.attr(t.href) + '">' +
            '<div class="start-spot-track-top">' +
              '<span class="start-spot-track-t">' + esc(t.title) + '</span>' +
              OBOL.ic('arrow') +
            '</div>' +
            '<span class="start-spot-track-d">' + esc(t.sub) + '</span>' +
          '</a>';
        }).join('') +
      '</div>' +
    '</section>';
  }

  function stageFor(track, res) {
    if (!track) return '';
    if (track === 'minilab') {
      return '<div class="start-stage">' +
        miniLabSection(res) +
        '<div class="start-cta start-reveal" style="--way:#10b981">' +
          '<button type="button" class="start-step-link" style="--way:#06b6d4" data-switch-track="new">' + OBOL.ic('compass') + '<span>New to pentesting? Open the Beginner &amp; Budget Roadmap</span>' + OBOL.ic('arrow') + '</button>' +
          '<a href="#/study" style="--way:#a855f7">' + OBOL.ic('book') + '<span>Explore Study Tracks (#/study)</span>' + OBOL.ic('arrow') + '</a>' +
          '<a href="#/home" style="--way:#f59e0b">' + OBOL.ic('flag') + '<span>Start a Real Engagement (#/home)</span>' + OBOL.ic('arrow') + '</a>' +
        '</div>' +
      '</div>';
    }
    if (track === 'new') {
      return '<div class="start-stage">' +
        introSection(res) +
        budgetSection(res) +
        practiceSection(res) +
        '<div class="start-cta start-reveal" style="--way:#06b6d4">' +
          '<button type="button" class="start-step-link" style="--way:#10b981" data-switch-track="minilab">' + OBOL.ic('zap') + '<span>Try the Guided Mini-Lab Simulator</span>' + OBOL.ic('arrow') + '</button>' +
          '<button type="button" class="start-step-link" style="--way:#3b82f6" data-switch-track="basics">' + OBOL.ic('terminal') + '<span>Set Up Your Local Kali Linux VM</span>' + OBOL.ic('arrow') + '</button>' +
          '<a href="#/study" style="--way:#a855f7">' + OBOL.ic('book') + '<span>Browse OBOL\'s Study Tracks (#/study)</span>' + OBOL.ic('arrow') + '</a>' +
        '</div>' +
      '</div>';
    }
    if (track === 'basics') {
      return '<div class="start-stage">' +
        studySpotlight() +
        labSection(res) +
        practiceSection(res) +
        deeperSection(res) +
        '<div class="start-cta start-reveal" style="--way:#a855f7">' +
          '<a href="#/loadout" style="--way:#f59e0b">' + OBOL.ic('package') + '<span>Set Up Your Kali Loadout (#/loadout)</span>' + OBOL.ic('arrow') + '</a>' +
          '<a href="#/home" style="--way:#10b981">' + OBOL.ic('compass') + '<span>Start Your First Engagement (#/home)</span>' + OBOL.ic('arrow') + '</a>' +
          '<button type="button" class="start-step-link" style="--way:#f43f5e" data-switch-track="exam">' + OBOL.ic('award') + '<span>Open Certification Exam Playbooks</span>' + OBOL.ic('arrow') + '</button>' +
        '</div>' +
      '</div>';
    }
    if (track === 'exam') {
      return '<div class="start-stage">' +
        examSection(res) +
        deeperSection(res) +
        '<div class="start-cta start-reveal" style="--way:#f59e0b">' +
          '<a href="#/home" style="--way:#10b981">' + OBOL.ic('compass') + '<span>Start an Exam-Mode Engagement</span>' + OBOL.ic('arrow') + '</a>' +
          '<a href="#/checklist" style="--way:#06b6d4">' + OBOL.ic('check') + '<span>Open the Phase Checklist</span>' + OBOL.ic('arrow') + '</a>' +
          '<a href="#/stuck" style="--way:#f43f5e">' + OBOL.ic('shield') + '<span>Open the Stuck / Circuit-Breaker Guide</span>' + OBOL.ic('arrow') + '</a>' +
        '</div>' +
      '</div>';
    }
    // 'all' - every section on one scroll for power browsers.
    return '<div class="start-stage">' +
      introSection(res) +
      budgetSection(res) +
      miniLabSection(res) +
      studySpotlight() +
      practiceSection(res) +
      labSection(res) +
      examSection(res) +
      deeperSection(res) +
      '<div class="start-cta start-reveal">' +
        '<a href="#/study" style="--way:#a855f7">' + OBOL.ic('book') + '<span>Explore Study (#/study)</span>' + OBOL.ic('arrow') + '</a>' +
        '<a href="#/loadout" style="--way:#f59e0b">' + OBOL.ic('package') + '<span>Set Up Your Kali Loadout (#/loadout)</span>' + OBOL.ic('arrow') + '</a>' +
        '<a href="#/home" style="--way:#10b981">' + OBOL.ic('compass') + '<span>Go to Engagements (#/home)</span>' + OBOL.ic('arrow') + '</a>' +
      '</div>' +
    '</div>';
  }

  function door(id, way, ic, title, sub, go) {
    var on = (_track === id) ? ' on' : '';
    var pressed = (_track === id) ? 'true' : 'false';
    return '<button type="button" class="sl-way start-door' + on + '" data-track="' + id + '" aria-pressed="' + pressed + '" style="--way:' + way + '">' +
      '<span class="sl-way-ic">' + OBOL.ic(ic) + '</span>' +
      '<span class="sl-way-t">' + esc(title) + '</span>' +
      '<span class="sl-way-d">' + esc(sub) + '</span>' +
      '<span class="sl-way-go">' + esc(go) + ' ' + OBOL.ic('arrow') + '</span>' +
    '</button>';
  }

  function render() {
    var res = OBOL.RESOURCES;
    if (!res) return '<div class="panel"><div class="panel-b">Resources data not loaded.</div></div>';
    var hint = _track
      ? 'Click another card to switch tracks, click the active card to collapse, or <button type="button" class="start-all" data-start-all aria-pressed="' + (_track === 'all' ? 'true' : 'false') + '">' + (_track === 'all' ? 'hide full view' : 'show everything at once') + '</button>.'
      : 'Pick the card that fits where you are today - or <button type="button" class="start-all" data-start-all aria-pressed="false">show me everything</button>.';
    return '<div class="start-wrap">' +
      '<div class="start-hero">' +
        '<h1 class="start-hero-h">Where are you starting from?</h1>' +
        '<p class="start-hero-sub">OBOL is a hands-on penetration testing cockpit and engagement workbench. Test-drive a simulated mini-lab right in your browser, explore the beginner &amp; budget roadmap, or open the certification exam playbooks.</p>' +
        '<div class="start-doors" role="group" aria-label="Choose your starting point">' +
          door('minilab', '#10b981', 'zap',      'Try A Guided Mini-Lab',  'Test-drive OBOL right in your browser with realistic Cockpit Move Cards and an emulated Kali terminal. Copy commands, paste output, and watch Field Doctors in action.', 'Launch simulator') +
          door('new',     '#06b6d4', 'compass',  'New To All This',        'Brand new to ethical hacking? Read what offensive security actually is, how OBOL coaches you through targets, and follow an interactive path built for your budget ($0 to Cert).', 'Show beginner roadmap') +
          door('basics',  '#a855f7', 'terminal', 'I Know The Basics',      'Comfortable with the command line and basic networking? Pair OBOL\'s Study Coach with browser terminals or build your own local Kali Linux VM.', 'Show lab & study setup') +
          door('exam',    '#f59e0b', 'award',    'Prepping For An Exam',   'Studying for OSCP, CPTS, or PNPT? Expand any exam playbook to inspect scoring math, banned-tool rules, exam-day OBOL workflow, and skill checklists.', 'Show exam playbooks') +
        '</div>' +
        '<p class="start-hint">' + hint + '</p>' +
      '</div>' +
      stageFor(_track, res) +
    '</div>';
  }

  // Execute a command inside the emulated terminal
  function executeInTerminal(cmdText, step) {
    var raw = String(cmdText || '').trim();
    var low = raw.toLowerCase();
    if (low === 'clear' || low === 'cls') {
      _termInputVal = '';
      _lastRanCardId = null;
      _lastTermOutput = '';
      return;
    }
    if (low === 'help') {
      _lastTermOutput = 'OBOL Mini-Lab Emulated Shell: Copy any command from the OBOL Cockpit Move Cards on the left, paste it here, and press Enter (or try whoami, id, ip a, clear).';
      return;
    }
    if (low === 'whoami' || low === 'id') {
      _lastTermOutput = 'uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo)';
      return;
    }
    var card = matchCommandToCard(raw, step);
    if (card) {
      _selectedCardId = card.id;
      _termInputVal = card.cmd;
      _lastRanCardId = card.id;
      _lastTermOutput = card.terminalOutput || '';
      if (_tutorialSubStep < 3) _tutorialSubStep = 3;
    }
  }

  // Process pasted terminal output into OBOL
  function processPasteInObol(pastedText, step) {
    if (!step || !Array.isArray(step.cards)) return;
    var card = null;
    if (_lastRanCardId) {
      card = findCard(step, _lastRanCardId);
    }
    if (!card && pastedText) {
      var pt = String(pastedText).trim();
      for (var i = 0; i < step.cards.length; i++) {
        if (step.cards[i].terminalOutput && step.cards[i].terminalOutput.indexOf(pt.slice(0, 24)) >= 0) {
          card = step.cards[i];
          break;
        }
      }
    }
    if (!card) card = getSelectedCard(step);
    if (!card) return;

    _selectedCardId = card.id;
    _lastRanCardId = card.id;
    _lastTermOutput = card.terminalOutput || '';
    _pasteBoxVal = card.terminalOutput || '';
    _pastedCardId = card.id;

    if (card.kind === 'deadend') {
      _cardStates[card.id] = 'suppressed';
    } else if (card.kind === 'doctor') {
      _cardStates[card.id] = 'doctored';
    } else if (card.kind === 'advance') {
      _cardStates[card.id] = 'completed';
      _completedSteps[_stepIdx] = true;
    }
  }

  function launchMiniLabEngagement(lab) {
    if (!lab) return;
    var step0 = (lab.steps && lab.steps[0]) || {};
    var card0 = (step0.cards && step0.cards[0]) || {};
    if (OBOL.store && OBOL.ingest && typeof OBOL.store.create === 'function') {
      OBOL.store.create('Mini-Lab: ' + lab.title, { platform: 'htb', mode: 'learning' });
      OBOL.store.update(function (e) {
        e.params = e.params || {};
        e.params.target = lab.target;
        e.targets = [{ ip: lab.target, hostname: lab.hostname || '', label: lab.title, addedAt: Date.now() }];
        e.activeTarget = lab.target;
      });
      if (OBOL.facts && OBOL.store.addFacts && lab.target) {
        OBOL.store.addFacts([OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + lab.target, source: 'minilab' })], 'facts');
      }
      Promise.resolve(OBOL.ingest.ensureParsers ? OBOL.ingest.ensureParsers() : true).then(function () {
        if (card0.terminalOutput) {
          OBOL.ingest.run({
            text: card0.terminalOutput,
            command: card0.cmd || ('nmap -sC -sV -Pn ' + lab.target),
            source: 'nmap-service',
            scope: 'host:' + lab.target
          });
        }
        if (G.location) G.location.hash = '#/path';
      });
    }
  }

  function launchExamTemplateEngagement(examId) {
    var res = OBOL.RESOURCES || {};
    var exams = res.exams || [];
    var ex = null;
    for (var i = 0; i < exams.length; i++) {
      if (exams[i].id === examId) { ex = exams[i]; break; }
    }
    if (!ex || !ex.practiceTemplate) return;
    var tpl = ex.practiceTemplate;
    if (OBOL.store && typeof OBOL.store.create === 'function') {
      OBOL.store.create(tpl.name, { platform: tpl.platform || 'oscp', mode: (tpl.platform === 'oscp' ? 'exam' : 'learning') });
      var ips = String(tpl.targets || '').split(/[\s,]+/).filter(Boolean);
      OBOL.store.update(function (e) {
        e.params = e.params || {};
        e.params.target = ips[0] || '10.10.10.50';
        if (tpl.domain) e.params.domain = tpl.domain;
        e.targets = ips.map(function (ip, idx) {
          return { ip: ip, label: 'Target ' + (idx + 1), addedAt: Date.now() };
        });
        e.activeTarget = ips[0] || null;
      });
      if (OBOL.facts && OBOL.store.addFacts && ips.length) {
        OBOL.store.addFacts(ips.map(function (ip) {
          return OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + ip, source: 'template' });
        }), 'facts');
      }
      if (G.location) G.location.hash = '#/home';
    }
  }

  function mounted(ctx) {
    var mount = ctx && ctx.mount;
    if (!mount || mount._startWired) return;
    mount._startWired = true;

    // Handle Enter key in the emulated terminal input and expandable exam cards
    if (mount.addEventListener) {
      mount.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && ev.target && ev.target.id === 'start-ml-term-in') {
          ev.preventDefault();
          var res = OBOL.RESOURCES || {};
          var step = getCurrentStep(getMiniLab(res));
          executeInTerminal(ev.target.value, step);
          OBOL.router.render();
          return;
        }
        if ((ev.key === 'Enter' || ev.key === ' ') && ev.target && ev.target.closest) {
          var exSum = ev.target.closest('[data-exam-toggle]');
          if (exSum && !ev.target.closest('[data-exam-launch]')) {
            ev.preventDefault();
            var exId = exSum.getAttribute('data-exam-toggle');
            if (exId) {
              _expandedExams[exId] = !_expandedExams[exId];
              OBOL.router.render();
            }
          }
        }
      });
    }

    mount.addEventListener('click', function (ev) {
      if (!ev.target || !ev.target.closest) return;
      var res = OBOL.RESOURCES || {};
      var curLab = getMiniLab(res);
      var curStep = getCurrentStep(curLab);

      var doorBtn = ev.target.closest('[data-track]');
      var swBtn = ev.target.closest('[data-switch-track]');
      var allBtn = ev.target.closest('[data-start-all]');
      var budgetTabBtn = ev.target.closest('[data-budget-tier]');
      var examToggleBtn = ev.target.closest('[data-exam-toggle]');
      var mlSelectBtn = ev.target.closest('[data-minilab-select]');
      var mlStepBtn = ev.target.closest('[data-minilab-step]');
      var mlArrowsBtn = ev.target.closest('[data-minilab-arrows]');
      var mcCopyBtn = ev.target.closest('[data-mc-copy]');
      var mcFillBtn = ev.target.closest('[data-mc-fill]');
      var termCopyBtn = ev.target.closest('[data-term-copy]');
      var termSendBtn = ev.target.closest('[data-term-send-obol]');
      var termClearBtn = ev.target.closest('[data-term-clear]');
      var mlOptBtn = ev.target.closest('[data-minilab-opt]');
      var mlRunBtn = ev.target.closest('[data-minilab-run]');
      var mlPasteBtn = ev.target.closest('[data-minilab-paste]');
      var mlPickOptBtn = ev.target.closest('[data-minilab-pick-optimal]');
      var mlNextBtn = ev.target.closest('[data-minilab-next]');
      var mlResetBtn = ev.target.closest('[data-minilab-reset]');
      var mlLaunchBtn = ev.target.closest('[data-minilab-launch]');
      var examLaunchBtn = ev.target.closest('[data-exam-launch]');
      var copyBtn = ev.target.closest('[data-copy-cmd]');

      if (budgetTabBtn) {
        ev.preventDefault();
        _budgetTier = budgetTabBtn.getAttribute('data-budget-tier') || 'free';
        OBOL.router.render();
        return;
      }
      if (examLaunchBtn) {
        ev.preventDefault();
        launchExamTemplateEngagement(examLaunchBtn.getAttribute('data-exam-launch'));
        return;
      }
      if (examToggleBtn) {
        ev.preventDefault();
        var exKey = examToggleBtn.getAttribute('data-exam-toggle');
        if (exKey) {
          _expandedExams[exKey] = !_expandedExams[exKey];
          OBOL.router.render();
        }
        return;
      }

      if (mlSelectBtn) {
        ev.preventDefault();
        resetMiniLabState(mlSelectBtn.getAttribute('data-minilab-select') || 'linux-web');
        OBOL.router.render();
        return;
      }
      if (mlArrowsBtn) {
        ev.preventDefault();
        _showArrows = !_showArrows;
        OBOL.router.render();
        return;
      }
      if (mlStepBtn) {
        ev.preventDefault();
        var idx = parseInt(mlStepBtn.getAttribute('data-minilab-step'), 10);
        if (!isNaN(idx)) {
          _stepIdx = idx;
          _selectedCardId = null;
          _termInputVal = '';
          _lastRanCardId = null;
          _lastTermOutput = '';
          _pasteBoxVal = '';
          _pastedCardId = null;
          if (_stepIdx > 0) _showArrows = false;
          OBOL.router.render();
        }
        return;
      }
      if (mcCopyBtn) {
        ev.preventDefault();
        var cid = mcCopyBtn.getAttribute('data-mc-copy');
        var cCard = findCard(curStep, cid);
        if (cCard) {
          _selectedCardId = cCard.id;
          _termInputVal = cCard.cmd;
          if (G.navigator && G.navigator.clipboard && G.navigator.clipboard.writeText) {
            G.navigator.clipboard.writeText(cCard.cmd);
          }
          if (_tutorialSubStep === 1) _tutorialSubStep = 2;
          OBOL.router.render();
        }
        return;
      }
      if (mcFillBtn) {
        ev.preventDefault();
        var fid = mcFillBtn.getAttribute('data-mc-fill');
        var fCard = findCard(curStep, fid);
        if (fCard) {
          _selectedCardId = fCard.id;
          _termInputVal = fCard.cmd;
          _lastRanCardId = fCard.id;
          _lastTermOutput = fCard.terminalOutput || '';
          if (_tutorialSubStep < 3) _tutorialSubStep = 3;
          OBOL.router.render();
        }
        return;
      }
      if (termCopyBtn) {
        ev.preventDefault();
        if (_lastTermOutput && G.navigator && G.navigator.clipboard && G.navigator.clipboard.writeText) {
          G.navigator.clipboard.writeText(_lastTermOutput);
        }
        _pasteBoxVal = _lastTermOutput;
        if (_tutorialSubStep < 4) _tutorialSubStep = 4;
        OBOL.router.render();
        return;
      }
      if (termSendBtn) {
        ev.preventDefault();
        _pasteBoxVal = _lastTermOutput;
        processPasteInObol(_pasteBoxVal, curStep);
        OBOL.router.render();
        return;
      }
      if (termClearBtn) {
        ev.preventDefault();
        _termInputVal = '';
        _lastRanCardId = null;
        _lastTermOutput = '';
        OBOL.router.render();
        return;
      }
      if (mlRunBtn) {
        ev.preventDefault();
        var termIn = (mount.querySelector && mount.querySelector('#start-ml-term-in')) || null;
        var cmdToRun = (termIn && termIn.value) || _termInputVal || (getSelectedCard(curStep) && getSelectedCard(curStep).cmd) || '';
        executeInTerminal(cmdToRun, curStep);
        OBOL.router.render();
        return;
      }
      if (mlPasteBtn) {
        ev.preventDefault();
        var pasteTa = (mount.querySelector && mount.querySelector('#start-ml-paste-ta')) || null;
        var pText = (pasteTa && pasteTa.value) || _pasteBoxVal || _lastTermOutput || '';
        processPasteInObol(pText, curStep);
        OBOL.router.render();
        return;
      }
      if (mlPickOptBtn) {
        ev.preventDefault();
        if (curStep && Array.isArray(curStep.cards)) {
          for (var i = 0; i < curStep.cards.length; i++) {
            if (curStep.cards[i].kind === 'advance') {
              _selectedCardId = curStep.cards[i].id;
              _termInputVal = curStep.cards[i].cmd;
              _lastRanCardId = curStep.cards[i].id;
              _lastTermOutput = curStep.cards[i].terminalOutput || '';
              _pasteBoxVal = curStep.cards[i].terminalOutput || '';
              processPasteInObol(_pasteBoxVal, curStep);
              break;
            }
          }
        }
        OBOL.router.render();
        return;
      }
      if (mlOptBtn && !ev.target.closest('details')) {
        var pickedCardId = mlOptBtn.getAttribute('data-minilab-opt');
        if (pickedCardId && pickedCardId !== _selectedCardId) {
          _selectedCardId = pickedCardId;
          var pCard = findCard(curStep, pickedCardId);
          if (pCard) _termInputVal = pCard.cmd;
          OBOL.router.render();
        }
        return;
      }
      if (mlNextBtn) {
        ev.preventDefault();
        if (curLab && _stepIdx < curLab.steps.length - 1) {
          _stepIdx++;
          _selectedCardId = null;
          _termInputVal = '';
          _lastRanCardId = null;
          _lastTermOutput = '';
          _pasteBoxVal = '';
          _pastedCardId = null;
          _showArrows = false; // Auto-hide tutorial arrows after Phase 1
          OBOL.router.render();
        }
        return;
      }
      if (mlResetBtn) {
        ev.preventDefault();
        resetMiniLabState(_labId);
        OBOL.router.render();
        return;
      }
      if (mlLaunchBtn) {
        ev.preventDefault();
        launchMiniLabEngagement(curLab);
        return;
      }
      if (examLaunchBtn) {
        ev.preventDefault();
        launchExamTemplateEngagement(examLaunchBtn.getAttribute('data-exam-launch'));
        return;
      }
      if (copyBtn) {
        ev.preventDefault();
        var cmdText = copyBtn.getAttribute('data-copy-cmd') || '';
        if (cmdText && G.navigator && G.navigator.clipboard && G.navigator.clipboard.writeText) {
          G.navigator.clipboard.writeText(cmdText);
        }
        copyBtn.textContent = 'Copied!';
        setTimeout(function () { copyBtn.textContent = 'Copy'; }, 1200);
        return;
      }

      if (!doorBtn && !swBtn && !allBtn) return;
      ev.preventDefault();
      var focusSel = null;
      if (doorBtn) {
        var picked = doorBtn.getAttribute('data-track');
        _track = (_track === picked) ? null : picked;
        focusSel = '.start-door[data-track="' + picked + '"]';
      } else if (swBtn) {
        var swPicked = swBtn.getAttribute('data-switch-track');
        _track = swPicked;
        focusSel = '.start-door[data-track="' + swPicked + '"]';
      } else if (allBtn) {
        _track = (_track === 'all') ? null : 'all';
        focusSel = '[data-start-all]';
      }
      OBOL.router.render();
      var stage = mount.querySelector('.start-stage');
      if (stage && stage.scrollIntoView) stage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      if (focusSel) {
        var nextFocus = mount.querySelector(focusSel);
        if (nextFocus && nextFocus.focus) nextFocus.focus();
      }
    });
  }

  OBOL.routes.start = { render: render, mounted: mounted };
})(typeof window !== 'undefined' ? window : globalThis);
