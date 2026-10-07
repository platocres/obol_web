/*!
 * obol ui, routes/stuck.js, the STUCK? tab (global, standalone, sandboxed).
 *
 * For an exam-taker stuck in a lab: tell obol what you have by clicking human-phrased binary buttons
 * (no pasting), and it hands you ranked move cards, the SAME coach ranker as Next Steps, that expand to
 * commands with field notes. Progressive: the more you tell it, the more relevant options appear.
 *
 * Boundaries: runs in a throwaway sandbox FactSet (OBOL.stuck), never writes the active engagement
 * unless you opt to seed/save. Advisory by construction: every suggestion is framed "based on what you
 * told me." Presentation only: it never changes which command the coach ranks.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }
  function S() { return OBOL.stuck || {}; }

  // Lane order for the picker sections (recon-to-loot reading order, not raw score order).
  var LANE_ORDER = ['Recon', 'Web', 'Windows And AD', 'Credentials', 'Access', 'Linux Privesc', 'Windows Privesc', 'Loot', 'Pivoting'];

  // ── module-local sandbox state (never touches OBOL.store) ──────────────────────────────────────
  var _fs = null;          // sandbox FactSet
  var _triage = '';        // chosen triage id
  var _tried = {};         // move ids the user said did not work
  var _params = { target: '', lhost: '', lport: '4444' };
  var _showAll = false;    // picker shows the near-frontier batch first, then "show all" on request
  var _mount = null;
  var PICK_LIMIT = 18;     // how many fact buttons to show before "Show All"

  function scope() { return 'host:' + (_params.target || 'target'); }
  function pack() { return OBOL.packs.actions(); }
  function reset() { _fs = null; _triage = ''; _tried = {}; }

  // ── triage screen ──────────────────────────────────────────────────────────────────────────────
  function triageHtml() {
    var tris = (S().TRIAGE || []);
    var cards = tris.map(function (t) {
      return '<button type="button" class="stuck-tri" data-tri="' + esc(t.id) + '">'
        + '<span class="stuck-tri-l">' + esc(t.label) + '</span>'
        + '<span class="stuck-tri-n">' + esc(t.note || '') + '</span></button>';
    }).join('');
    var seed = OBOL.store && OBOL.store.active && OBOL.store.active()
      ? '<button type="button" class="stuck-seed" data-seed>Start From My Active Engagement Instead</button>' : '';
    return '<div class="stuck-intro">'
      + '<h1 class="route-h1">Stuck?</h1>'
      + '<p class="route-sub">Tell obol what you have and it hands you options, no pasting required. '
      + 'Everything here is advisory: it is based on what you tell it, not on proof, so treat the moves as leads to try.</p>'
      + '<div class="stuck-triage"><h2 class="stuck-q">What Do You Have Right Now?</h2>'
      + '<div class="stuck-tri-grid">' + cards + '</div>' + seed + '</div></div>';
  }

  // ── params bar (optional, contextual) ──────────────────────────────────────────────────────────
  function paramsHtml() {
    function f(id, label, val, ph) {
      return '<label class="stuck-param"><span>' + esc(label) + '</span>'
        + '<input id="stuck-p-' + id + '" type="text" value="' + U.attr(val || '') + '" placeholder="' + U.attr(ph) + '"'
        + ' autocomplete="off" spellcheck="false"></label>';
    }
    return '<div class="stuck-params">'
      + '<span class="stuck-params-l">Fill Your Details (Optional)</span>'
      + f('target', 'Target', _params.target, '10.10.10.5')
      + f('lhost', 'Your IP (LHOST)', _params.lhost, '10.10.14.2')
      + f('lport', 'Your Port (LPORT)', _params.lport, '4444')
      + '</div>';
  }

  // ── fact picker ──────────────────────────────────────────────────────────────────────────────
  function assertedChips() {
    var facts = (_fs && _fs.facts) || [];
    var seen = {}, chips = [];
    facts.forEach(function (f) {
      if (seen[f.kind]) return; seen[f.kind] = 1;
      if (!S().isAskable(f.kind)) return; // hide internal seed kinds like target.configured
      chips.push('<button type="button" class="stuck-chip on" data-drop="' + esc(f.kind) + '" '
        + 'title="Click to remove">' + esc(S().labelFor(f.kind)) + '<span class="stuck-chip-x" aria-hidden="true">x</span></button>');
    });
    if (!chips.length) return '';
    return '<div class="stuck-told"><span class="stuck-told-l">You Told obol</span>'
      + '<div class="stuck-chips">' + chips.join('') + '</div></div>';
  }

  function pickerHtml() {
    var all = S().suggestFacts(_fs, pack(), { askable: S().isAskable });
    // Progressive disclosure: lead with the near-frontier batch (top by relevance), hide the long tail
    // behind "Show All" so an opening board is not a wall of 80+ options.
    var total = all.length;
    var cands = _showAll ? all : all.slice(0, PICK_LIMIT);
    var byLane = {};
    cands.forEach(function (c) { var g = S().groupFor(c.kind) || 'More'; (byLane[g] = byLane[g] || []).push(c); });
    var lanes = LANE_ORDER.filter(function (l) { return byLane[l]; })
      .concat(Object.keys(byLane).filter(function (l) { return LANE_ORDER.indexOf(l) < 0; }));
    var sections = lanes.map(function (lane) {
      var btns = byLane[lane].map(function (c) {
        return '<button type="button" class="stuck-fact" data-add="' + esc(c.kind) + '">'
          + '<span class="stuck-fact-l">' + esc(c.label) + '</span>'
          + (c.detail ? '<span class="stuck-fact-h">' + esc(c.detail) + '</span>' : '') + '</button>';
      }).join('');
      return '<div class="stuck-lane"><h3 class="stuck-lane-h">' + esc(lane) + '</h3>'
        + '<div class="stuck-fact-grid">' + btns + '</div></div>';
    }).join('');
    var none = sections ? '' : '<p class="stuck-note">You have told obol plenty. Scan the moves on the right, and if one does not pan out, mark it and the next option appears.</p>';
    var more = '';
    if (!_showAll && total > PICK_LIMIT) more = '<button type="button" class="stuck-showall" data-showall>Show All ' + total + ' Options</button>';
    else if (_showAll && total > PICK_LIMIT) more = '<button type="button" class="stuck-showall" data-showless>Show Fewer</button>';
    return assertedChips() + sections + none + more;
  }

  // ── Build In Workbench deep links (presentation only; mirrors the Next Steps classifier) ────────
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

  // ── move cards ──────────────────────────────────────────────────────────────────────────────
  function locusLabel(l) { return l === 'R' ? 'On Your Box' : (l === 'F' ? 'On The Target' : (l === 'I' ? 'Interactive' : '')); }
  function cardWhy(move) {
    var note = OBOL.fieldNote ? OBOL.fieldNote(move, 0) : null;
    if (note && note.when) return note.when;
    if (move.proves) return move.proves;
    var prod = (move.produces || []).map(function (k) { return S().labelFor(k); }).filter(Boolean);
    return prod.length ? ('Gets you: ' + prod.slice(0, 2).join(', ')) : '';
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
      + t.map(function (x) { return '<a class="stuck-wb-link" href="#/workbench/' + esc(x.tab) + '">' + esc(x.label) + ' <span aria-hidden="true">&rarr;</span></a>'; }).join('')
      + '</div>';
  }
  function cardHtml(move) {
    var why = cardWhy(move), loc = locusLabel(move.locus);
    return '<details class="stuck-card">'
      + '<summary class="stuck-card-head">'
      + '<span class="stuck-card-title">' + esc(move.title || move.id) + '</span>'
      + (loc ? '<span class="stuck-card-locus">' + esc(loc) + '</span>' : '')
      + (why ? '<span class="stuck-card-why">' + esc(why) + '</span>' : '')
      + '</summary>'
      + '<div class="stuck-card-body">'
      + cmdRows(move)
      + noteBlock(move)
      + wbBlock(move)
      + '<button type="button" class="stuck-tried" data-tried="' + esc(move.id) + '">I Tried This, It Did Not Work</button>'
      + '</div></details>';
  }
  function movesHtml() {
    var moves = [];
    try { moves = S().rankedMoves(_fs, pack(), { triedIds: Object.keys(_tried) }); } catch (e) { moves = []; }
    moves = moves.slice(0, 8);
    var triedN = Object.keys(_tried).length;
    var cleared = triedN ? '<button type="button" class="stuck-clear-tried" data-cleartried>Show The ' + triedN + ' I Marked Again</button>' : '';
    if (!moves.length) return '<p class="stuck-note">Tell obol a bit more on the left and your options will appear here.</p>' + cleared;
    return moves.map(cardHtml).join('') + cleared;
  }

  // ── layout ──────────────────────────────────────────────────────────────────────────────────
  function mainHtml() {
    var save = OBOL.store && OBOL.store.active && OBOL.store.active()
      ? '<button type="button" class="stuck-save" data-save>Save These To My Engagement</button>' : '';
    return '<div class="stuck-head">'
      + '<div class="stuck-head-row"><h1 class="route-h1">Stuck?</h1>'
      + '<div class="stuck-head-actions">' + save + '<button type="button" class="stuck-startover" data-startover>Start Over</button></div></div>'
      + '<p class="route-sub">Based on what you told obol. These are leads to try, ranked the same way as Next Steps, not proof. '
      + 'Mark anything that does not work and the next option moves up.</p></div>'
      + paramsHtml()
      + '<div class="stuck-layout">'
      + '<section class="stuck-col stuck-col-facts" aria-label="What is true"><h2 class="stuck-col-h">What Is True So Far?</h2>'
      + '<div id="stuck-picker">' + pickerHtml() + '</div></section>'
      + '<section class="stuck-col stuck-col-moves" aria-label="Your options"><h2 class="stuck-col-h">Your Options</h2>'
      + '<div id="stuck-moves">' + movesHtml() + '</div></section>'
      + '</div>';
  }

  function body() { return _triage ? mainHtml() : triageHtml(); }
  function render(ctx) { return '<section class="stuck">' + body() + '</section>'; }

  function rebuild() { var el = _mount && _mount.querySelector('.stuck'); if (el) el.innerHTML = body(); }
  function refreshPicker() { var el = _mount && _mount.querySelector('#stuck-picker'); if (el) el.innerHTML = pickerHtml(); }
  function refreshMoves() { var el = _mount && _mount.querySelector('#stuck-moves'); if (el) el.innerHTML = movesHtml(); }

  // ── seed / save (opt-in only) ───────────────────────────────────────────────────────────────
  function seedFromEngagement() {
    _fs = S().sandbox();
    try {
      var efs = OBOL.store.factSet();
      (efs.facts || []).forEach(function (f) {
        if (f.state === OBOL.facts.ProofState.SUPPORTED) _fs.add(OBOL.facts.makeFact({ kind: f.kind, scope: f.scope, value: f.value, source: 'stuck', created_at: f.created_at }));
      });
      var p = (OBOL.store.active() || {}).params || {};
      if (p.target) _params.target = p.target;
      if (p.lhost) _params.lhost = p.lhost;
      if (p.lport) _params.lport = p.lport;
    } catch (e) {}
    _triage = 'seeded';
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

  // ── mount ──────────────────────────────────────────────────────────────────────────────────
  function mounted(ctx) {
    _mount = ctx.mount;

    U.on(_mount, 'click', '.btn-copy', function (e, t) {
      U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    // triage pick
    U.on(_mount, 'click', '.stuck-tri', function (e, t) {
      _fs = S().sandbox();
      _triage = t.getAttribute('data-tri') || 'nothing';
      _showAll = false; _tried = {};
      S().triageSeed(_fs, _triage, pack(), scope());
      rebuild();
    });
    U.on(_mount, 'click', '.stuck-seed', function () { seedFromEngagement(); rebuild(); });
    U.on(_mount, 'click', '.stuck-startover', function () { reset(); rebuild(); });
    U.on(_mount, 'click', '.stuck-save', function () { saveToEngagement(); });

    // add a fact
    U.on(_mount, 'click', '.stuck-fact', function (e, t) {
      var kind = t.getAttribute('data-add'); if (!kind || !_fs) return;
      S().assert(_fs, kind, { scope: scope() });
      refreshPicker(); refreshMoves();
    });
    // remove an asserted fact
    U.on(_mount, 'click', '.stuck-chip', function (e, t) {
      var kind = t.getAttribute('data-drop'); if (!kind || !_fs) return;
      S().retract(_fs, kind);
      refreshPicker(); refreshMoves();
    });
    // "I tried this" / clear
    U.on(_mount, 'click', '.stuck-tried', function (e, t) {
      var id = t.getAttribute('data-tried'); if (!id) return;
      _tried[id] = true; refreshMoves();
    });
    U.on(_mount, 'click', '.stuck-clear-tried', function () { _tried = {}; refreshMoves(); });
    // progressive disclosure of the fact picker
    U.on(_mount, 'click', '.stuck-showall[data-showall]', function () { _showAll = true; refreshPicker(); });
    U.on(_mount, 'click', '.stuck-showall[data-showless]', function () { _showAll = false; refreshPicker(); });

    // optional params fill (re-fill the commands live)
    ['target', 'lhost', 'lport'].forEach(function (k) {
      U.on(_mount, 'input', '#stuck-p-' + k, function (e, t) { _params[k] = t.value; refreshMoves(); });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.stuck = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
