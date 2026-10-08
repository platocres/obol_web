/*!
 * obol ui, routes/stuck.js, the STUCK? tab, the Ferryman.
 *
 * For an exam-taker stranded in a lab. A warm cyberpunk guide (the ferryman: an obol is the coin you
 * pay to cross, so he carries you across to root) runs a short interview, one question at a time, to
 * place you, then drops you on a board of ranked move tiles (the same coach ranker and the same
 * expanding, glowing Next Steps tiles) with a calm, port-gated fact refiner.
 *
 * Two acts:
 *   Act 1 (interview): host up? -> pick open ports -> credential? -> shell? -> admin?  Each step seeds
 *     the sandbox. Skippable. Ports are foundational: they decide which lanes open later.
 *   Act 2 (board): ranked move tiles (ns-card, select to expand with glow + reflow), plus a refiner
 *     that only shows lanes your ports imply, so it never floods you.
 *
 * Boundaries: a throwaway sandbox FactSet (OBOL.stuck), never writes the active engagement unless you
 * opt in. Advisory ("based on what you told me"), deterministic, never forks the ranker.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function S() { return OBOL.stuck || {}; }

  var LANE_ORDER = ['Recon', 'Web', 'Windows And AD', 'Credentials', 'Access', 'Linux Privesc', 'Windows Privesc', 'Loot', 'Pivoting'];
  var PORT_LANE_ORDER = ['Common', 'Web', 'Windows', 'Database', 'Mail'];
  var STEPS = ['intro', 'host', 'ports', 'cred', 'shell', 'admin'];

  // ── module-local state (sandbox, never OBOL.store) ─────────────────────────────────────────────
  var _fs = null;
  var _stage = 'interview';   // 'interview' | 'board'
  var _step = 'intro';
  var _tried = {};
  var _sel = '';              // selected move id (expanded tile)
  var _params = { target: '', lhost: '', lport: '4444' };
  var _refineOpen = false;    // "explore other options" expander on the board
  var _mount = null;
  var _typeTimer = null;

  function scope() { return 'host:' + (_params.target || 'target'); }
  function pack() { return OBOL.packs.actions(); }
  function reset() { _fs = S().sandbox(); _stage = 'interview'; _step = 'intro'; _tried = {}; _sel = ''; _refineOpen = false; }
  function ensureFs() { if (!_fs) _fs = S().sandbox(); }
  function reducedMotion() { try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }

  // ── the ferryman: glowing eye + typewriter line ────────────────────────────────────────────────
  // Charon's visage: the cyberpunk-ferryman illustration (hero for the intro, a face avatar inline).
  function eyeHtml(small) {
    return small
      ? '<img class="charon-av" src="assets/img/charon-avatar.webp?v=1" width="46" height="46" loading="lazy" decoding="async" alt="Charon the ferryman">'
      : '<img class="charon-art" src="assets/img/charon.webp?v=1" width="220" height="220" loading="lazy" decoding="async" alt="Charon the ferryman, hooded with glowing red eyes in a skull boat on the green Styx">';
  }
  function typeInto(text) {
    var el = _mount && _mount.querySelector('.stuck-say');
    if (!el) return;
    if (_typeTimer) { clearInterval(_typeTimer); _typeTimer = null; }
    if (reducedMotion()) { el.textContent = text; return; }
    el.textContent = ''; var i = 0;
    _typeTimer = setInterval(function () {
      i += 2; el.textContent = text.slice(0, i);
      if (i >= text.length) { el.textContent = text; clearInterval(_typeTimer); _typeTimer = null; }
    }, 16);
  }

  // ── interview copy ─────────────────────────────────────────────────────────────────────────────
  var SAY = {
    intro: 'Hello, friend. You look stranded on the near shore. I am the ferryman, and I have carried a great many across to root. Tell me where you stand, and I will light the water.',
    host: 'First: is there even a far shore? Does the host answer a ping or a scan?',
    ports: 'Every crossing begins with the open doors. Mark each port you have found open. These decide which paths I can show you.',
    cred: 'Do you carry a key? A credential that truly turns a lock?',
    shell: 'Have you set foot on the far shore yet? A shell on the box, however small?',
    admin: 'And do you rule that shore? Are you admin, or root?',
  };
  function stepNumber(id) { var n = STEPS.indexOf(id); return n > 0 ? ('Question ' + n + ' of 5') : ''; }

  function ans(label, opts) {
    opts = opts || {};
    return '<button type="button" class="stuck-ans" data-goto="' + esc(opts.goto || '') + '"'
      + (opts.assert ? ' data-assert="' + esc(opts.assert) + '"' : '')
      + (opts.skip ? ' data-skip="1"' : '') + '>' + esc(label) + '</button>';
  }
  function hintDetails(summary, cmd) {
    return '<details class="stuck-hint"><summary>' + esc(summary) + '</summary>'
      + '<div class="stuck-cmd"><code>' + esc(cmd) + '</code>'
      + '<button class="btn-copy" data-copy="' + U.attr(cmd) + '" aria-label="Copy command">copy</button></div></details>';
  }

  function stepBodyHtml(id) {
    if (id === 'intro') {
      var seed = (OBOL.store && OBOL.store.active && OBOL.store.active())
        ? '<button type="button" class="stuck-ans ghost" data-seed>Start From My Active Engagement</button>' : '';
      return '<div class="stuck-answers">' + ans('Carry Me Across', { goto: 'host' })
        + '<button type="button" class="stuck-ans ghost" data-skip="1" data-goto="board">I Know The Way, Show The Board</button>'
        + seed + '</div>';
    }
    if (id === 'host') {
      return '<div class="stuck-answers">' + ans('Yes, It Is Up', { goto: 'ports', assert: 'host.up' })
        + ans('Not Sure Yet', { goto: 'ports' }) + '</div>'
        + hintDetails('Not sure? Check like this', 'nmap -sn ' + (_params.target || '<target>') + '   # or: ping -c1 ' + (_params.target || '<target>'));
    }
    if (id === 'ports') {
      return portPaletteHtml()
        + hintDetails('Not sure what is open? Scan like this', 'nmap -p- --min-rate 5000 -oN scans/allports.txt ' + (_params.target || '<target>'))
        + '<div class="stuck-answers"><button type="button" class="stuck-ans" data-goto="cred">Next: My Access</button></div>';
    }
    if (id === 'cred') {
      return '<div class="stuck-answers">' + ans('Yes, One That Logs In', { goto: 'shell', assert: 'credential.available,credential.validated' })
        + ans('A Hash Or A Maybe', { goto: 'shell', assert: 'credential.candidate' })
        + ans('Nothing Yet', { goto: 'shell' }) + '</div>';
    }
    if (id === 'shell') {
      return '<div class="stuck-answers">' + ans('Yes, On Linux', { goto: 'admin', assert: 'access.shell,foothold.linux' })
        + ans('Yes, On Windows', { goto: 'admin', assert: 'access.shell,foothold.windows' })
        + ans('Not Yet', { goto: 'board', skip: true }) + '</div>';
    }
    if (id === 'admin') {
      return '<div class="stuck-answers">' + ans('Yes, I Rule It', { goto: 'board', assert: 'access.admin' })
        + ans('Not Yet', { goto: 'board' }) + '</div>';
    }
    return '';
  }

  function interviewHtml() {
    var num = stepNumber(_step);
    return '<div class="stuck-stage-interview-inner">'
      + '<div class="stuck-ferry">' + eyeHtml(false)
      + '<div class="stuck-ferry-text">' + (num ? '<span class="stuck-step-n">' + esc(num) + '</span>' : '')
      + '<p class="stuck-say" data-say="' + U.attr(SAY[_step] || '') + '"></p></div></div>'
      + '<div class="stuck-step-body">' + stepBodyHtml(_step) + '</div>'
      + (_step !== 'intro' ? '<button type="button" class="stuck-skiplink" data-skip="1" data-goto="board">Skip the questions, take me to the board</button>' : '')
      + '</div>';
  }

  // ── port palette (interview step + board refiner) ──────────────────────────────────────────────
  function portPaletteHtml() {
    var ports = OBOL.STUCK_PORTS || [];
    var byLane = {};
    ports.forEach(function (p) { (byLane[p.lane] = byLane[p.lane] || []).push(p); });
    var lanes = PORT_LANE_ORDER.filter(function (l) { return byLane[l]; }).concat(Object.keys(byLane).filter(function (l) { return PORT_LANE_ORDER.indexOf(l) < 0; }));
    var groups = lanes.map(function (lane) {
      var btns = byLane[lane].map(function (p) {
        var on = S().portOn(_fs, p.port);
        return '<button type="button" class="stuck-port' + (on ? ' on' : '') + '" data-port="' + p.port + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
          + '<span class="stuck-port-n">' + p.port + '</span><span class="stuck-port-l">' + esc(p.label) + '</span></button>';
      }).join('');
      return '<div class="stuck-port-lane"><span class="stuck-port-lane-h">' + esc(lane) + '</span><div class="stuck-port-row">' + btns + '</div></div>';
    }).join('');
    return '<div class="stuck-ports">' + groups
      + '<div class="stuck-port-free"><label>Other Port<input id="stuck-port-free" type="text" inputmode="numeric" placeholder="e.g. 50000" autocomplete="off"></label>'
      + '<button type="button" class="stuck-port-add" data-portadd>Add</button></div></div>';
  }

  // ── Build In Workbench deep links (mirrors the Next Steps classifier) ───────────────────────────
  var WB_DIR_TOOLS = { gobuster: 1, ffuf: 1, feroxbuster: 1, dirb: 1, dirbuster: 1, wfuzz: 1 };
  function wbTargets(move) {
    if (!move) return [];
    var tools = {}; if (move.tool) tools[String(move.tool).toLowerCase()] = 1;
    (move.tools || []).forEach(function (t) { if (t) tools[String(t).toLowerCase()] = 1; });
    var produces = (move.produces || []).join(' ');
    var idt = (move.id || '') + ' ' + (move.title || '');
    var out = [], seen = {};
    function add(tab, label) { if (!seen[tab]) { seen[tab] = 1; out.push({ tab: tab, label: label }); } }
    if (/\bhash\./.test(produces) || tools.hashcat || tools.john || /roast|ntds|secretsdump|lsass|\bsam\b|dcsync|hashdump/i.test(idt)) add('hashid', 'Identify / Crack In Workbench');
    if (move.id === 'sudo-abuse' || move.id === 'suid-gtfobins' || /gtfobins/i.test(idt)) add('gtfobins', 'Open GTFOBins Browser');
    var usesDirTool = Object.keys(tools).some(function (k) { return WB_DIR_TOOLS[k]; });
    if (usesDirTool || /content discovery|directory brute|directory fuzz|web.?fuzz|virtual host|vhost|subdomain enum/i.test(idt)) add('wordlists/' + (/vhost|virtual host|subdomain/i.test(idt) ? 'subdomains' : 'dirs'), 'Pick A Wordlist');
    if (/foothold\.|access\.shell/.test(produces) || tools.nc || tools.ncat || tools.socat || tools.msfvenom || /reverse shell|listener|\brevshell\b/i.test(idt)) add('revshell', 'Build A Reverse Shell');
    if (/\bjwt\b|json web token/i.test(idt)) add('jwt', 'Decode The JWT');
    if (/sql injection|sqli|sql-inj/i.test(idt)) add('sqli', 'Build The SQLi');
    if (/command inj|cmdi|local file inclusion|\blfi\b|traversal|\bxss\b|cross-site script/i.test(idt)) add('encoder', 'Encode A Payload');
    return out.slice(0, 2);
  }

  // ── move tiles (reuse the Next Steps ns-card: select to expand, glow + reflow) ──────────────────
  function locusLabel(l) { return l === 'R' ? 'On Your Box' : (l === 'F' ? 'On The Target' : (l === 'I' ? 'Interactive' : '')); }
  function cardWhy(move) {
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, 0) : null;
    if (note && note.when) return note.when;
    if (move.proves) return move.proves;
    var prod = (move.produces || []).map(function (k) { return S().labelFor(k); }).filter(Boolean);
    return prod.length ? ('Gets you: ' + prod.slice(0, 2).join(', ')) : 'A lead worth trying next.';
  }
  function cmdRows(move) {
    var filled = [];
    try { filled = OBOL.command.fillAll(move, _fs, { params: _params }); } catch (e) { filled = []; }
    var cmds = (move.commands && move.commands.length) ? move.commands : (move.command ? [{ run: move.command }] : []);
    return cmds.map(function (c, i) {
      var text = (filled[i] && filled[i].filled) || c.run || '';
      if (!text) return '';
      return '<div class="stuck-cmd"><code>' + esc(text) + '</code>'
        + '<button class="btn-copy" data-copy="' + U.attr(text) + '" aria-label="Copy command">copy</button></div>'
        + (c.note ? '<p class="stuck-cmd-note">' + esc(c.note) + '</p>' : '');
    }).join('');
  }
  function noteBlock(move) {
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, 0) : null;
    if (!note) return '';
    var html = '';
    var land = (note.land || []).slice(0, 3);
    if (land.length) html += '<div class="stuck-fn"><span class="stuck-fn-l">How To Land It</span><ul>' + land.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></div>';
    if (note.win) html += '<div class="stuck-fn"><span class="stuck-fn-l">You Win When</span><p>' + esc(note.win) + '</p></div>';
    var miss = (note.mistakes || []).slice(0, 2);
    if (miss.length) html += '<div class="stuck-fn"><span class="stuck-fn-l">Common Mistakes</span><ul>' + miss.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul></div>';
    return html;
  }
  function wbBlock(move) {
    var t = wbTargets(move);
    if (!t.length) return '';
    return '<div class="stuck-wb"><span class="stuck-wb-l">Build In Workbench</span>'
      + t.map(function (x) { return '<a class="stuck-wb-link" href="#/workbench/' + esc(x.tab) + '">' + esc(x.label) + ' <span aria-hidden="true">&rarr;</span></a>'; }).join('') + '</div>';
  }
  function tileHtml(move, rank, suggested) {
    var ph = OBOL.phases.phaseOfAction(move);
    var selected = move.id === _sel;
    var loc = locusLabel(move.locus);
    var cls = 'ns-card stuck-move ns-ph-' + ph + (selected ? ' selected is-glow ns-bloom' : '');
    var head = '<div class="ns-card-head">'
      + (suggested ? '<span class="ns-suggested">Suggested Start</span>' : '')
      + '<span class="ns-chip ns-phase ph-' + esc(ph) + '">' + esc(U.titleCase(ph)) + '</span>'
      + (loc ? '<span class="ns-chip">' + esc(loc) + '</span>' : '') + '</div>';
    var foot = '<div class="ns-foot">' + esc(cardWhy(move)) + '</div>';
    var bodyInner = selected
      ? '<div class="ns-body">' + cmdRows(move) + noteBlock(move) + wbBlock(move)
        + '<button type="button" class="stuck-tried" data-tried="' + esc(move.id) + '">I Tried This, It Did Not Work</button></div>'
      : '';
    return '<article class="' + cls + '" tabindex="0" role="button" aria-expanded="' + (selected ? 'true' : 'false') + '"'
      + ' data-move="' + esc(move.id) + '" aria-label="' + U.attr(move.title + ', open its commands') + '">'
      + (rank ? '<span class="ns-rank">#' + rank + '</span>' : '') + head
      + '<h3 class="ns-title">' + esc(move.title || move.id) + '</h3>'
      + foot + bodyInner + '</article>';
  }
  function movesHtml() {
    var moves = [];
    try { moves = S().rankedMoves(_fs, pack(), { triedIds: Object.keys(_tried) }); } catch (e) { moves = []; }
    moves = moves.slice(0, 8);
    if (!moves.length) return '<p class="stuck-note">Mark a few more doors or details below and the crossings will appear here.</p>';
    var tiles = moves.map(function (m, i) { return tileHtml(m, i + 1, i === 0); }).join('');
    var triedN = Object.keys(_tried).length;
    var cleared = triedN ? '<button type="button" class="stuck-clear-tried" data-cleartried>Bring back the ' + triedN + ' I set aside</button>' : '';
    return '<div class="ns-grid stuck-grid">' + tiles + '</div>' + cleared;
  }

  // ── board refiner (port-gated findings) ────────────────────────────────────────────────────────
  function assertedChips() {
    var facts = (_fs && _fs.facts) || [], seen = {}, chips = [];
    facts.forEach(function (f) {
      if (seen[f.kind] || !S().isFinding(f.kind)) return; seen[f.kind] = 1;
      chips.push('<button type="button" class="stuck-chip on" data-drop="' + esc(f.kind) + '" title="Click to remove">' + esc(S().labelFor(f.kind)) + '<span class="stuck-chip-x" aria-hidden="true">x</span></button>');
    });
    if (!chips.length) return '';
    return '<div class="stuck-told"><span class="stuck-told-l">You Told The Ferryman</span><div class="stuck-chips">' + chips.join('') + '</div></div>';
  }
  function findingsHtml() {
    var cands = S().suggestFacts(_fs, pack(), { askable: S().isFinding });
    var byLane = {};
    cands.forEach(function (c) { var g = S().groupFor(c.kind) || 'More'; if (!S().laneActive(g, _fs)) return; (byLane[g] = byLane[g] || []).push(c); });
    var lanes = LANE_ORDER.filter(function (l) { return byLane[l]; }).concat(Object.keys(byLane).filter(function (l) { return LANE_ORDER.indexOf(l) < 0; }));
    if (!lanes.length) return '<p class="stuck-note">Pick the ports you found above and the questions worth asking will open up here.</p>';
    return lanes.map(function (lane) {
      var btns = byLane[lane].map(function (c) {
        return '<button type="button" class="stuck-fact" data-add="' + esc(c.kind) + '"><span class="stuck-fact-l">' + esc(c.label) + '</span>'
          + (c.detail ? '<span class="stuck-fact-h">' + esc(c.detail) + '</span>' : '') + '</button>';
      }).join('');
      return '<div class="stuck-lane"><h3 class="stuck-lane-h">' + esc(lane) + '</h3><div class="stuck-fact-grid">' + btns + '</div></div>';
    }).join('');
  }
  function paramsHtml() {
    function f(id, label, val, ph) {
      return '<label class="stuck-param"><span>' + esc(label) + '</span><input id="stuck-p-' + id + '" type="text" value="' + U.attr(val || '') + '" placeholder="' + U.attr(ph) + '" autocomplete="off" spellcheck="false"></label>';
    }
    return '<div class="stuck-params"><span class="stuck-params-l">Fill Your Details (Optional)</span>'
      + f('target', 'Target', _params.target, '10.10.10.5') + f('lhost', 'Your IP (LHOST)', _params.lhost, '10.10.14.2') + f('lport', 'Your Port (LPORT)', _params.lport, '4444') + '</div>';
  }

  function boardHtml() {
    var save = (OBOL.store && OBOL.store.active && OBOL.store.active()) ? '<button type="button" class="stuck-ghost" data-save>Save To My Engagement</button>' : '';
    return '<div class="stuck-board-head">'
      + '<div class="stuck-ferry sm">' + eyeHtml(true)
      + '<div class="stuck-ferry-text"><p class="stuck-say" data-say="' + U.attr('Here is the water. These are the crossings I would try, in order. Mark anything that fails and I will show you the next.') + '"></p></div></div>'
      + '<div class="stuck-board-actions">' + save + '<button type="button" class="stuck-ghost" data-restart>Back To Questions</button><button type="button" class="stuck-ghost" data-startover>Start Over</button></div>'
      + '</div>'
      + paramsHtml()
      + '<div id="stuck-moves" class="stuck-moves">' + movesHtml() + '</div>'
      + '<details class="stuck-refine" open><summary>Your Open Doors (Add Or Remove Ports)</summary>'
      + '<div id="stuck-doors">' + portPaletteHtml() + '</div></details>'
      + '<details class="stuck-refine"><summary>Tell The Ferryman More (Findings)</summary>'
      + '<div id="stuck-findings-wrap">' + assertedChips() + '<div id="stuck-findings">' + findingsHtml() + '</div></div></details>';
  }

  var HEAD = '<h1 class="sr-only">Stuck? The Ferryman</h1>';
  function body() { return _stage === 'interview' ? interviewHtml() : boardHtml(); }
  function render(ctx) { ensureFs(); return '<section class="stuck stuck-stage-' + _stage + '">' + HEAD + body() + '</section>'; }

  function afterRender() { var el = _mount && _mount.querySelector('.stuck-say'); if (el) typeInto(el.getAttribute('data-say') || ''); }
  function rebuild() { var el = _mount && _mount.querySelector('.stuck'); if (el) { el.className = 'stuck stuck-stage-' + _stage; el.innerHTML = HEAD + body(); afterRender(); } }
  function refreshMoves() { var el = _mount && _mount.querySelector('#stuck-moves'); if (el) el.innerHTML = movesHtml(); }
  function refreshDoors() { var el = _mount && _mount.querySelector('#stuck-doors'); if (el) el.innerHTML = portPaletteHtml(); }
  function refreshFindings() { var el = _mount && _mount.querySelector('#stuck-findings-wrap'); if (el) el.innerHTML = assertedChips() + '<div id="stuck-findings">' + findingsHtml() + '</div>'; }

  // ── seed / save ────────────────────────────────────────────────────────────────────────────────
  function seedFromEngagement() {
    _fs = S().sandbox();
    try {
      var efs = OBOL.store.factSet();
      (efs.facts || []).forEach(function (f) { if (f.state === OBOL.facts.ProofState.SUPPORTED) _fs.add(OBOL.facts.makeFact({ kind: f.kind, scope: f.scope, value: f.value, source: 'stuck', created_at: f.created_at })); });
      var p = (OBOL.store.active() || {}).params || {};
      if (p.target) _params.target = p.target; if (p.lhost) _params.lhost = p.lhost; if (p.lport) _params.lport = p.lport;
    } catch (e) {}
    _stage = 'board';
  }
  function saveToEngagement() {
    if (!(OBOL.store && OBOL.store.active && OBOL.store.active())) return;
    var n = 0;
    try {
      OBOL.store.update(function (e) {
        e.facts = e.facts || [];
        (_fs.facts || []).forEach(function (f) {
          if (f.state !== OBOL.facts.ProofState.SUPPORTED) return;
          var dup = e.facts.some(function (x) { return x.kind === f.kind && (x.scope || '') === (f.scope || ''); });
          if (!dup) { e.facts.push(OBOL.facts.factToJson(OBOL.facts.makeFact({ kind: f.kind, scope: f.scope, value: f.value, source: 'stuck-saved', created_at: f.created_at }))); n++; }
        });
      }, 'facts');
    } catch (e) {}
    U.toast(n ? ('Saved ' + n + ' to your engagement') : 'Nothing new to save', n ? '' : 'err');
  }

  // ── advance the interview ────────────────────────────────────────────────────────────────────
  function applyAnswer(assertCsv, goto, skip) {
    ensureFs();
    (assertCsv ? assertCsv.split(',') : []).forEach(function (k) { k = k.trim(); if (k) S().assert(_fs, k, { scope: scope() }); });
    if (goto === 'board' || skip) { _stage = 'board'; }
    else if (goto) { _step = goto; _stage = 'interview'; }
    rebuild();
  }

  // ── mount ──────────────────────────────────────────────────────────────────────────────────────
  function mounted(ctx) {
    _mount = ctx.mount;
    ensureFs();
    afterRender();

    U.on(_mount, 'click', '.btn-copy', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });

    // interview answers
    U.on(_mount, 'click', '.stuck-ans', function (e, t) {
      applyAnswer(t.getAttribute('data-assert'), t.getAttribute('data-goto'), t.getAttribute('data-skip'));
    });
    U.on(_mount, 'click', '[data-seed]', function () { seedFromEngagement(); rebuild(); });
    U.on(_mount, 'click', '.stuck-skiplink, [data-skip][data-goto="board"]', function () { _stage = 'board'; rebuild(); });
    U.on(_mount, 'click', '[data-restart]', function () { _stage = 'interview'; _step = 'intro'; rebuild(); });
    U.on(_mount, 'click', '[data-startover]', function () { reset(); rebuild(); });
    U.on(_mount, 'click', '[data-save]', function () { saveToEngagement(); });

    // port palette (shared: interview + board)
    U.on(_mount, 'click', '.stuck-port', function (e, t) {
      var port = parseInt(t.getAttribute('data-port'), 10); ensureFs();
      S().togglePort(_fs, port, scope());
      if (_stage === 'board') { refreshDoors(); refreshFindings(); refreshMoves(); }
      else { // just toggle this button's state in place to keep the step calm
        var on = S().portOn(_fs, port); t.classList.toggle('on', on); t.setAttribute('aria-pressed', on ? 'true' : 'false');
      }
    });
    U.on(_mount, 'click', '[data-portadd]', function () {
      var inp = _mount.querySelector('#stuck-port-free'); if (!inp) return; ensureFs();
      if (S().addPortNumber(_fs, inp.value, scope())) { inp.value = ''; if (_stage === 'board') { refreshDoors(); refreshFindings(); refreshMoves(); } else rebuild(); }
      else U.toast('Enter a port number 1 to 65535', 'err');
    });

    // move tiles: select to expand (ignore clicks inside the expanded body, which has its own controls)
    U.on(_mount, 'click', '.stuck-move', function (e, t) {
      if (e.target && e.target.closest && e.target.closest('.ns-body')) return;
      var id = t.getAttribute('data-move'); _sel = (_sel === id) ? '' : id; refreshMoves();
    });
    U.on(_mount, 'keydown', '.stuck-move', function (e, t) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
        if (e.target && e.target.closest && e.target.closest('.ns-body')) return;
        e.preventDefault(); var id = t.getAttribute('data-move'); _sel = (_sel === id) ? '' : id; refreshMoves();
      }
    });

    // tried / clear
    U.on(_mount, 'click', '.stuck-tried', function (e, t) { var id = t.getAttribute('data-tried'); if (id) { _tried[id] = true; if (_sel === id) _sel = ''; refreshMoves(); } });
    U.on(_mount, 'click', '[data-cleartried]', function () { _tried = {}; refreshMoves(); });

    // findings add / remove
    U.on(_mount, 'click', '.stuck-fact', function (e, t) { var k = t.getAttribute('data-add'); if (k) { ensureFs(); S().assert(_fs, k, { scope: scope() }); refreshFindings(); refreshMoves(); } });
    U.on(_mount, 'click', '.stuck-chip', function (e, t) { var k = t.getAttribute('data-drop'); if (k) { S().retract(_fs, k); refreshFindings(); refreshMoves(); } });

    // optional params fill
    ['target', 'lhost', 'lport'].forEach(function (k) { U.on(_mount, 'input', '#stuck-p-' + k, function (e, t) { _params[k] = t.value; refreshMoves(); }); });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.stuck = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
