/*!
 * obol ui - routes/study.js - Study mode (Learn methodology, interactive command workbench, and by-port decision map).
 *
 * Left: the active lane as a clickable, topically-grouped rail.
 * Center: WATCH (Before -> During -> After flow with the Unified Interactive Command & Terminal Workbench,
 * Switch & Argument Breakdown, and Next Move Command Previews) or YOUR TURN (retrieval practice).
 * Right: Operator Field Guide (Playbook & Tactical Variations, Signal & False Positives, If It Fails / Blockers).
 *
 * All content comes from OBOL.study + OBOL.STUDY_FIXTURES.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;

  var _view = 'map';             // 'map' (pick a lane) | 'atlas' (all lanes) | 'ports' | 'sim' | 'node' (study one step)
  var _from = 'map';             // where a node was opened from, so "back" returns there
  var _gear = 'watch';           // 'watch' | 'practice'
  var _sel = 'asrep-roast';      // selected lane node
  var _autolane = false;         // Watch: auto-advance through the whole chain
  var _autoplay = false;         // start the replay as soon as the next node mounts (chain mode)
  var _rpToken = null;
  var _rpIo = null;           // cancel token for the running replay's timers
  var _atlasPath = [];           // Atlas: the custom path being drawn (ordered node ids)
  var _scenario = null;          // Atlas: the active fixed scenario key (null = free-draw)
  var _az = null;                // Atlas pan/zoom state {tx,ty,k}; null = fit on mount
  var _path = [];                // the compiled path currently being studied
  var _pathName = 'Your custom path';
  var _pathMode = false;         // node view follows _path instead of the move's lane
  var _collapsed = {};           // Atlas: laneKey -> true when that lane band is folded shut
  var _evOpen = null;            // by-port: evidence-card key -> true when that card is expanded (persisted)
  function evOpen() { if (_evOpen) return _evOpen; _evOpen = {}; try { var s = localStorage.getItem('obol.evOpen'); if (s) _evOpen = JSON.parse(s) || {}; } catch (e) {} return _evOpen; }
  function evSave() { try { localStorage.setItem('obol.evOpen', JSON.stringify(_evOpen || {})); } catch (e) {} }
  var _evMode = 'cards';         // by-port: 'cards' (the ordered-move cards) | 'map' (the derived LTR decision forest)
  try { var _em = localStorage.getItem('obol.evMode'); if (_em === 'map' || _em === 'cards') _evMode = _em; } catch (e) {}
  var _atlasQuery = '';          // Atlas: current search text (dims non-matching steps)
  var _whyOverride = {};         // node: moveId -> true when the learner asked to show the reasoning anyway
  var _practiceMode = 'next';    // practice gear: 'next' (what to do) | 'read' (diagnose the output)
  var _recapPath = {};           // "how you got here": moveId -> selected lead-up path key
  var _rpSeen = {};              // Watch: moveId -> already auto-played once (so it plays on first scroll-in, not again)
  var _benchSel = {};            // field-notes bench: moveId -> selected technique index
  var _wbCmdIdx = {};            // unified workbench: moveId -> selected command index into cell.commands
  var _wbStage = {};             // unified workbench: moveId -> selected hub stage key ('all' or stage.key)
  var _wbStepIdx = {};           // unified workbench: moveId + ':' + cmdIdx -> selected step index in multi-step pipeline
  var _fgTab = {};               // operator field guide: moveId -> 'playbook' | 'signal' | 'blockers'
  var _railScroll = null;        // node view: rail (.study-graph) scrollTop to restore after a re-render
  var _railNodeSeen = null;      // node view: the move we last scrolled the rail to
  var _benchTok = null;          // field-notes bench: cancel token for the running demo animation
  var _simKey = null;            // cold-box sim: active scenario key (null = pick one)
  var _simStep = 0;              // cold-box sim: current step index
  var _simState = {};            // cold-box sim: stepIdx -> { pickedId, correct } answered state

  function esc(s) { return U.esc(String(s == null ? '' : s)); }
  function study() { return OBOL.study; }
  function human(k) { try { return (OBOL.pack && OBOL.pack.friendly) ? OBOL.pack.friendly(k) : k; } catch (e) { return k; } }

  var SMALL_WORDS = { a: 1, an: 1, the: 1, and: 1, or: 1, but: 1, nor: 1, of: 1, to: 1, in: 1, on: 1, at: 1, by: 1, for: 1, with: 1, from: 1, via: 1, per: 1, vs: 1 };
  function titleCase(str) {
    var first = true;
    return String(str == null ? '' : str).split(/(\s+)/).map(function (tok) {
      if (/^\s*$/.test(tok)) return tok;
      var isFirst = first; first = false;
      return tok.split('-').map(function (part, pi) {
        if (!part) return part;
        if (/^[A-Z0-9][A-Z0-9.]*$/.test(part) && part.length >= 2) return part;
        var lower = part.toLowerCase();
        if (!isFirst && pi === 0 && SMALL_WORDS[lower]) return lower;
        return part.charAt(0).toUpperCase() + part.slice(1);
      }).join('-');
    }).join('');
  }
  function factChips(list, cls) {
    return (list || []).map(function (x) { return '<button type="button" class="study-chip study-chip-fact ' + (cls || '') + '" data-fact="' + U.attr(x) + '" title="What produces ' + U.attr(human(x)) + ', and what it unlocks">' + esc(titleCase(human(x))) + '</button>'; }).join('');
  }
  function codeify(s) {
    var out = esc(String(s == null ? '' : s));
    out = out.replace(/`([^`]+)`/g, '<code class="study-ic">$1</code>');
    out = out.replace(/(\$[A-Za-z0-9$]{2,})/g, '<code class="study-ic">$1</code>');
    out = out.replace(/\b([a-z][a-z0-9]*(?:\.[a-z0-9_]+)+)\b/g, function (m) { return m.length >= 6 ? '<code class="study-ic">' + m + '</code>' : m; });
    out = out.replace(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b/g, '<code class="study-ic">$1</code>');
    return out;
  }

  function locusClass(rank) { return 'study-loc-' + rank; }
  function locusGlyph(label) { return label === 'REMOTE' ? OBOL.ic('box') : (label === 'OFFLINE' ? OBOL.ic('disk') : OBOL.ic('host')); }

  function laneKeyOf(moveId) { var e = study().laneEntry(moveId); return e ? e.laneKey : 'ad'; }
  function laneMeta(key) { var ls = study().lanes(); for (var i = 0; i < ls.length; i++) if (ls[i].key === key) return ls[i]; return { name: key, short: key }; }

  function detectPromptFor(cmdStr, toolName, whereHint, osHint) {
    if (study().detectPrompt) return study().detectPrompt(cmdStr, toolName, whereHint, osHint);
    return whereHint === 'host' ? 'target$' : 'kali$';
  }
  function isHostPrompt(pr, whereHint) {
    return whereHint === 'host' || (pr && pr !== 'kali$');
  }

  // ---- left: the current lane (or custom path) as a rail --------------------------------------
  function masteryGlyph(id) {
    var mk = study().mastery()[id] || {};
    if (mk.correct) return '<span class="study-gn-m done" title="You answered this correctly">✓</span>';
    if (mk.studied) return '<span class="study-gn-m seen" title="You\'ve watched this step">◐</span>';
    return '';
  }
  function graphPanel() {
    var html = '', header;
    if (_pathMode && _path.length) {
      header = _pathName + ' · click a step';
      _path.forEach(function (id, i) {
        var m = study().cellFor(id); if (!m) return;
        var lk = laneKeyOf(id);
        var cls = 'study-gnode lane-' + lk + (id === _sel ? ' active' : '') + (i > 0 ? ' linked' : '');
        html += '<button type="button" class="' + cls + '" data-node="' + U.attr(id) + '">'
          + '<span class="study-gn-t">' + esc(m.title) + masteryGlyph(id) + '</span>'
          + '<span class="study-gn-k">' + esc(laneMeta(lk).short) + (m.proves && m.proves.length ? ' · Gets you ' + esc(human(m.proves[0])) : '') + '</span>'
          + '</button>';
      });
    } else {
      var lk2 = laneKeyOf(_sel), lane = study().lane(lk2);
      header = laneMeta(lk2).name + ' · click a step';
      var groups = [], gmap = {};
      lane.forEach(function (n) { var p = n.category || n.phase || 'Steps'; if (!gmap[p]) { gmap[p] = []; groups.push(p); } gmap[p].push(n); });
      var ORDER = (study().CATEGORY_ORDER || []).concat(['Recon', 'Enumeration', 'Web', 'Foothold', 'Credentials', 'Escalate', 'Lateral', 'Active Directory', 'Persistence', 'Loot', 'Proof', 'Steps']);
      groups.sort(function (a, b) {
        var ia = ORDER.indexOf(a), ib = ORDER.indexOf(b);
        return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib);
      });
      var gi = 0;
      groups.forEach(function (p) {
        html += '<div class="study-phase">' + esc(p) + '</div>';
        gmap[p].forEach(function (n) {
          var cls = 'study-gnode lane-' + lk2 + (n.id === _sel ? ' active' : '') + (gi > 0 ? ' linked' : '');
          gi++;
          html += '<button type="button" class="' + cls + '" data-node="' + U.attr(n.id) + '">'
            + '<span class="study-gn-t">' + esc(n.title) + masteryGlyph(n.id) + '</span>'
            + (n.proves && n.proves.length ? '<span class="study-gn-k">Gets you ' + esc(human(n.proves[0])) + '</span>' : '')
            + '</button>';
        });
      });
    }
    return '<div class="study-panel study-graph-panel">'
      + '<p class="study-panel-h">' + esc(header) + '</p>'
      + '<div class="study-graph">' + html + '</div>'
      + '<button type="button" class="study-graph-all" data-graph>\u229e Open the Atlas (all lanes)</button>'
      + '</div>';
  }

  // ---- shared bits ----------------------------------------------------------------------------
  function chips(list, cls) {
    return (list || []).map(function (x) { return '<span class="study-chip ' + (cls || '') + '">' + esc(x) + '</span>'; }).join('');
  }
  function benchParams() {
    try { var eng = OBOL.store && OBOL.store.active && OBOL.store.active(); var p = (eng && eng.params) || {}; return p; } catch (e) { return {}; }
  }
  function benchFill(str) {
    var p = benchParams(), out = String(str == null ? '' : str), tgt = p.target || p.rhost;
    if (tgt) out = out.replace(/<target>/g, tgt);
    if (p.lhost) out = out.replace(/<lhost>/g, p.lhost);
    if (p.domain) out = out.replace(/<domain>/g, p.domain);
    return out;
  }
  function benchLive() { var p = benchParams(); return !!(p.target || p.rhost); }

  function renderCmdTokens(cmdObj, fallbackStr, toolName) {
    var toks = (cmdObj && cmdObj.tokens && cmdObj.tokens.length)
      ? cmdObj.tokens
      : (study().tokenizeCmd ? study().tokenizeCmd(fallbackStr || (cmdObj && cmdObj.run) || '', toolName || (cmdObj && cmdObj.tool) || '') : []);
    if (!toks || !toks.length) return esc(benchFill(fallbackStr || (cmdObj && cmdObj.run) || ''));
    return toks.map(function (t) {
      return '<span class="wb-tok wb-tok-' + esc(t.role || 'arg') + '">' + esc(benchFill(t.text)) + '</span>';
    }).join(' ');
  }

  function commandBlock(cmd, activeIdx) {
    var isSel = (activeIdx != null && cmd.cmdIdx != null && String(cmd.cmdIdx) === String(activeIdx));
    var idxAttr = cmd.cmdIdx != null ? ' data-wb-idx="' + U.attr(String(cmd.cmdIdx)) + '"' : '';
    var pr = cmd.prompt || detectPromptFor(cmd.run, cmd.tool, cmd.rank === 2 ? 'host' : 'local');
    var dispTool = cmd.label ? (cmd.label + ' · ' + (cmd.toolsLabel || cmd.tool)) : cmd.tool;
    var copyTxt = cmd.fullChainRun || cmd.run || '';
    return '<div class="study-cmd ' + locusClass(cmd.rank) + (isSel ? ' active-variant' : '') + '"' + idxAttr + '>'
      + '<div class="study-cmd-h"><span class="study-loc">' + locusGlyph(cmd.locus) + ' ' + esc(cmd.locus) + '</span>'
      + '<span class="study-cmd-tool">' + esc(dispTool) + '</span>'
      + '<span class="study-cmd-tag">' + esc(cmd.tag) + '</span>'
      + (cmd.cmdIdx != null ? '<button type="button" class="study-cmd-load' + (isSel ? ' on' : '') + '" data-wb-idx="' + U.attr(String(cmd.cmdIdx)) + '">' + (isSel ? '● Active in Workbench' : 'Load in Workbench') + '</button>' : '')
      + '<button type="button" class="study-cmd-copy" data-wb-copy="' + U.attr(benchFill(copyTxt)) + '">Copy</button>'
      + '</div>'
      + '<pre class="study-cmd-run"><span class="study-cmd-pr' + (isHostPrompt(pr, cmd.rank === 2 ? 'host' : 'local') ? ' host' : '') + '">' + esc(pr) + '</span> ' + renderCmdTokens(cmd, cmd.run, cmd.tool) + '</pre>'
      + (cmd.note ? '<div class="study-cmd-why">↳ ' + codeify(benchFill(cmd.note)) + '</div>' : '')
      + '</div>';
  }

  function osForMove(cell) {
    var lk = cell.laneKey || laneKeyOf(cell.id);
    if (lk === 'windows' || lk === 'ad') return 'windows';
    if (lk === 'linux') return 'linux';
    var blob = (cell.commands || []).map(function (c) { return (c.run || '') + ' ' + (c.tool || ''); }).join(' ').toLowerCase();
    if (/powershell|(^| )cmd |winrm|\.exe|certutil|evil-winrm|rubeus|mssql|xfreerdp|impacket|nxc (smb|ldap|winrm)/.test(blob)) return 'windows';
    return 'linux';
  }
  function connectCmd(os) {
    return os === 'windows'
      ? { tool: 'evil-winrm', run: "evil-winrm -i 10.10.10.10 -u <user> -p '<password>'", prompt: 'kali$', note: 'Open an interactive shell on the box over WinRM (5985), then run the on-target command in that shell.', locus: 'ON-TARGET', tag: 'Connect First', rank: 2 }
      : { tool: 'ssh', run: 'ssh <user>@10.10.10.10', prompt: 'kali$', note: 'Open an interactive shell on the box, then run the on-target command in that shell.', locus: 'ON-TARGET', tag: 'Connect First', rank: 2 };
  }

  function switchBreakdownHtml(switches, stepLabel) {
    var sw = switches || [];
    if (!sw.length) return '';
    var cards = sw.map(function (s) {
      var role = s.role || 'flag';
      return '<div class="wb-sw-card role-' + esc(role) + '">'
        + '<div class="wb-sw-top"><code class="wb-sw-tok">' + esc(benchFill(s.token)) + '</code>'
        + '<span class="wb-sw-badge role-' + esc(role) + '">' + esc(s.roleLabel || role) + '</span></div>'
        + '<div class="wb-sw-desc">' + esc(s.desc || '') + '</div>'
        + '</div>';
    }).join('');
    return '<div class="wb-switches-wrap">'
      + '<div class="wb-switches-head"><span class="wb-sw-title">Switch &amp; Argument Breakdown' + (stepLabel ? ' · ' + esc(stepLabel) : '') + '</span>'
      + '<span class="wb-sw-sub">Every flag, target, and parameter in the active command</span></div>'
      + '<div class="wb-switches">' + cards + '</div>'
      + '</div>';
  }

  function resolveActiveCmd(cell) {
    var cmds = (cell && cell.commands) || [];
    if (!cmds.length) return { activeCmd: null, activeIdx: 0, stageCmds: [], curStage: 'all' };
    var curStage = (cell.hub && _wbStage[cell.id]) ? _wbStage[cell.id] : 'all';
    var stageCmds = (curStage === 'all' || !cell.hub)
      ? cmds
      : cmds.filter(function (c) { return c.stage === curStage; });
    if (!stageCmds.length) stageCmds = cmds;

    var selIdx = _wbCmdIdx[cell.id];
    var activeCmd = null;
    if (selIdx != null) {
      for (var i = 0; i < cmds.length; i++) {
        if (String(cmds[i].cmdIdx) === String(selIdx) || i === selIdx) {
          activeCmd = cmds[i];
          break;
        }
      }
    }
    if (activeCmd && curStage !== 'all' && stageCmds.indexOf(activeCmd) === -1) {
      activeCmd = stageCmds[0];
    }
    if (!activeCmd) activeCmd = stageCmds[0] || cmds[0];
    var activeIdx = activeCmd ? (activeCmd.cmdIdx != null ? activeCmd.cmdIdx : 0) : 0;
    return { activeCmd: activeCmd, activeIdx: activeIdx, stageCmds: stageCmds, curStage: curStage };
  }

  // ---- Unified Interactive Command & Terminal Workbench (Center Column) -------------------------
  function workbenchPanel(cell) {
    var cmds = cell.commands || [];
    var remote = cmds.filter(function (c) { return c.rank === 0 || c.rank === 1; });
    var onhost = cmds.filter(function (c) { return c.rank === 2; });
    var resolved = resolveActiveCmd(cell);
    var activeCmd = resolved.activeCmd;
    var activeIdx = resolved.activeIdx;
    var stageCmds = resolved.stageCmds;
    var curStage = resolved.curStage;
    var activeLocus = (activeCmd && activeCmd.rank === 2) ? 'onhost' : 'remote';
    if (!remote.length && onhost.length) activeLocus = 'onhost';

    var rp = study().replayFor(cell.id, activeIdx, activeCmd ? activeCmd.rawRun : undefined);
    if (!rp) return '';

    // Locus toggle or single-locus badge in the workbench header
    var locusHead = '';
    if (remote.length && onhost.length) {
      locusHead = '<div class="rw-head">'
        + '<span class="rw-label">Run it from</span>'
        + '<button type="button" class="rw-tab' + (activeLocus === 'remote' ? ' on' : '') + '" data-runway="remote">' + OBOL.ic('box') + ' Your box · Remote <span class="rw-n">' + remote.length + '</span></button>'
        + '<button type="button" class="rw-tab' + (activeLocus === 'onhost' ? ' on' : '') + '" data-runway="onhost">' + OBOL.ic('host') + ' On the target · Shell <span class="rw-n">' + onhost.length + '</span></button>'
        + '</div>';
    } else if (remote.length) {
      locusHead = '<div class="rw-head"><span class="rw-label">Run it from</span>'
        + '<span class="rw-single">' + OBOL.ic('box') + ' Your box (Kali · Remote)</span></div>';
    } else if (onhost.length) {
      locusHead = '<div class="rw-head"><span class="rw-label">Run it from</span>'
        + '<span class="rw-single">' + OBOL.ic('host') + ' On the target (Foothold Shell)</span></div>';
    }

    // Hub Stage Filter Bar (for Multi-Stage Tool Hubs like NetExec & Scenario Umbrellas like ADCS)
    var hubBar = '';
    if (cell.hub && cell.hub.stages && cell.hub.stages.length) {
      var stageBtns = '<button type="button" class="wb-stage-btn' + (curStage === 'all' ? ' on' : '') + '" data-wb-stage="all">'
        + '<span class="wb-st-t">All Stages <span class="wb-st-n">' + cmds.length + '</span></span>'
        + '<span class="wb-st-sub">Full workflow</span></button>';
      cell.hub.stages.forEach(function (st) {
        var count = cmds.filter(function (c) { return c.stage === st.key; }).length;
        if (!count) return;
        stageBtns += '<button type="button" class="wb-stage-btn' + (curStage === st.key ? ' on' : '') + '" data-wb-stage="' + U.attr(st.key) + '">'
          + '<span class="wb-st-t">' + esc(st.label) + ' <span class="wb-st-n">' + count + '</span></span>'
          + (st.prereq ? '<span class="wb-st-sub">Needs: ' + esc(st.prereq) + '</span>' : '')
          + '</button>';
      });
      hubBar = '<div class="wb-hub-bar">'
        + (cell.hub.lead ? '<div class="wb-hub-lead">' + codeify(cell.hub.lead) + '</div>' : '')
        + '<div class="wb-stage-list" role="tablist">' + stageBtns + '</div>'
        + '</div>';
    }

    // Approach & Tool Combination selector cards (never identical mystery-meat buttons)
    var variantTabs = '';
    if (cmds.length > 1) {
      variantTabs = '<div class="wb-variants">'
        + '<div class="wb-var-head"><span class="wb-var-l">Approach &amp; Tool Combination (' + stageCmds.length + ')</span>'
        + '<span class="wb-var-hint">Pick a single-tool or multi-tool pipeline to compare syntax, flags, and output</span></div>'
        + '<div class="wb-var-grid">'
        + stageCmds.map(function (c, idx) {
            var cIdx = c.cmdIdx != null ? c.cmdIdx : idx;
            var isOn = String(cIdx) === String(activeIdx);
            var stepCount = (c.steps && c.steps.length > 1) ? c.steps.length : 0;
            var toolsTxt = c.toolsLabel || c.tool || '';
            var locShort = c.rank === 2 ? 'On-Target' : 'Remote';
            return '<button type="button" class="wb-var-pill' + (isOn ? ' on' : '') + ' ' + locusClass(c.rank) + '" data-wb-idx="' + U.attr(String(cIdx)) + '">'
              + '<span class="wb-vp-top">'
              + '<span class="wb-vp-num">' + (idx + 1) + '</span>'
              + '<span class="wb-vp-label">' + esc(c.label || c.tool) + '</span>'
              + '</span>'
              + '<span class="wb-vp-sub">'
              + '<span class="wb-vp-tool">' + esc(toolsTxt) + '</span>'
              + (stepCount ? '<span class="wb-vp-chain">' + stepCount + '-step chain</span>' : '')
              + '<span class="wb-vp-tag">' + esc(c.tag || locShort) + '</span>'
              + '</span>'
              + '</button>';
          }).join('')
        + '</div></div>';
    }

    // Active Approach Context Banner (Scenario Prerequisite, When to Pick, & Dedicated Goal Module Link)
    var approachCtx = '';
    if (activeCmd && (activeCmd.label || activeCmd.prereqNote || activeCmd.when || activeCmd.deepLink)) {
      // deepLink is authored as { id, title } (STUDY_APPROACHES); tolerate a bare move-id string too
      var dlId = activeCmd.deepLink ? (typeof activeCmd.deepLink === 'object' ? activeCmd.deepLink.id : activeCmd.deepLink) : '';
      var dlTitle = (activeCmd.deepLink && typeof activeCmd.deepLink === 'object' && activeCmd.deepLink.title) || '';
      var dlMove = dlId ? study().cellFor(dlId) : null;
      // a deepLink whose target is not a real move would open a blank/stale node page, so only offer it when the module exists
      if (!dlMove) dlId = '';
      approachCtx = '<div class="wb-approach-ctx">'
        + '<div class="wb-actx-top">'
        + '<span class="wb-actx-title">' + esc(activeCmd.label || activeCmd.tool) + '</span>'
        + (activeCmd.toolsLabel ? '<span class="wb-actx-tools">' + esc(activeCmd.toolsLabel) + '</span>' : '')
        + (activeCmd.prereqNote ? '<span class="wb-prereq-pill">Requires: ' + esc(activeCmd.prereqNote) + '</span>' : '')
        + (dlId ? '<button type="button" class="wb-deeplink" data-goto="' + U.attr(dlId) + '" title="Open dedicated Goal Module to compare all tools and alternatives for this goal">Dedicated Goal Module: ' + esc(dlMove ? dlMove.title : (dlTitle || dlId)) + ' -&gt;</button>' : '')
        + '</div>'
        + (activeCmd.when ? '<div class="wb-actx-when">' + codeify(benchFill(activeCmd.when)) + '</div>' : '')
        + '</div>';
    }

    var activeRun = (activeCmd && activeCmd.run) || rp.command || '';
    var activeTool = (activeCmd && (activeCmd.toolsLabel || activeCmd.tool)) || rp.tool || '';
    var activePrompt = (activeCmd && activeCmd.prompt) || rp.prompt || detectPromptFor(activeRun, activeTool, activeLocus === 'onhost' ? 'host' : 'local', osForMove(cell));

    var stepKey = cell.id + ':' + activeIdx;
    var activeSteps = (activeCmd && activeCmd.steps && activeCmd.steps.length > 1) ? activeCmd.steps : null;
    var selStepIdx = _wbStepIdx[stepKey] || 0;
    if (activeSteps && selStepIdx >= activeSteps.length) selStepIdx = 0;
    var inspectedStep = activeSteps ? (activeSteps[selStepIdx] || activeSteps[0]) : null;
    var activeSwitches = (inspectedStep && inspectedStep.switches && inspectedStep.switches.length)
      ? inspectedStep.switches
      : ((activeCmd && activeCmd.switches && activeCmd.switches.length) ? activeCmd.switches : (rp.switches || []));
    var switchStepLabel = inspectedStep ? ('Step ' + (selStepIdx + 1) + ': ' + (inspectedStep.title || inspectedStep.tool || '')) : '';

    var cmdBarBody = '';
    if (activeSteps) {
      cmdBarBody = '<div class="wb-pipeline">'
        + activeSteps.map(function (st, si) {
            var isInspected = si === selStepIdx;
            var stWhere = st.where || 'local';
            var stPrompt = st.prompt || detectPromptFor(st.command, st.tool, stWhere, osForMove(cell));
            var stHost = isHostPrompt(stPrompt, stWhere);
            var stLocLabel = stHost ? 'ON-TARGET (SHELL)' : 'YOUR BOX (KALI)';
            return '<div class="wb-pipe-step' + (isInspected ? ' active-step' : '') + '">'
              + '<div class="wb-ps-head">'
              + '<span class="wb-ps-badge">Step ' + (si + 1) + ' of ' + activeSteps.length + '</span>'
              + '<span class="wb-ps-title">' + esc(st.title || st.tool || ('Step ' + (si + 1))) + '</span>'
              + (st.tool ? '<span class="wb-ps-tool">' + esc(st.tool) + '</span>' : '')
              + '<span class="wb-ps-loc' + (stHost ? ' host' : '') + '">' + esc(stLocLabel) + '</span>'
              + '<div class="wb-ps-acts">'
              + '<button type="button" class="wb-ps-inspect' + (isInspected ? ' on' : '') + '" data-wb-step="' + si + '" data-wb-step-key="' + U.attr(stepKey) + '">' + (isInspected ? '● Inspecting Flags' : 'Inspect Flags') + '</button>'
              + '<button type="button" class="wb-act-btn" data-wb-copy="' + U.attr(benchFill(st.command)) + '">Copy Step</button>'
              + '</div></div>'
              + '<div class="' + (isInspected ? 'wb-cmdbar-code ' : '') + 'wb-ps-code">'
              + '<span class="' + (isInspected ? 'wb-prompt ' : '') + 'wb-ps-prompt' + (stHost ? ' host' : '') + '">' + esc(stPrompt) + '</span> '
              + '<span class="' + (isInspected ? 'wb-tokens ' : '') + 'wb-ps-tokens">' + renderCmdTokens(st, st.command, st.tool) + '</span>'
              + '</div>'
              + (st.teach ? '<div class="wb-ps-teach">↳ ' + codeify(benchFill(st.teach)) + '</div>' : '')
              + '</div>';
          }).join('<div class="wb-pipe-arrow">↓ feeds into next step</div>')
        + '</div>';
    } else {
      cmdBarBody = '<div class="wb-cmdbar-code"><span class="wb-prompt' + (isHostPrompt(activePrompt, activeLocus === 'onhost' ? 'host' : 'local') ? ' host' : '') + '">' + esc(activePrompt) + '</span> '
        + '<span class="wb-tokens">' + renderCmdTokens(activeCmd, activeRun, activeTool) + '</span></div>'
        + (activeCmd && activeCmd.note ? '<div class="wb-cmdbar-note">↳ ' + codeify(benchFill(activeCmd.note)) + '</div>' : '');
    }

    var fullCopyCmd = (activeCmd && activeCmd.fullChainRun) || activeRun;
    var activeCmdBar = '<div class="wb-cmdbar">'
      + '<div class="wb-cmdbar-top">'
      + '<span class="wb-cmdbar-loc ' + locusClass(activeCmd ? activeCmd.rank : 0) + '">' + locusGlyph(activeCmd ? activeCmd.locus : rp.locus) + ' ' + esc(activeCmd ? activeCmd.locus : rp.locus) + ' · ' + esc(activeTool) + (activeCmd && activeCmd.tag ? ' (' + esc(activeCmd.tag) + ')' : '') + '</span>'
      + '<div class="wb-cmdbar-actions">'
      + '<button type="button" class="wb-act-btn" data-wb-copy="' + U.attr(benchFill(fullCopyCmd)) + '">' + (activeSteps ? 'Copy Full Pipeline (' + activeSteps.length + ' Steps)' : 'Copy Command') + '</button>'
      + (rp.hasOutput ? '<button type="button" class="wb-act-btn wb-act-coach" data-wb-ingest title="Send this sample output to OBOL Cockpit to see what facts it mints">Send Sample to Cockpit -&gt;</button>' : '')
      + '</div></div>'
      + cmdBarBody
      + '</div>';

    var idle = rp.hasOutput
      ? 'Watch <b>' + esc(activeCmd && activeCmd.label ? activeCmd.label : activeTool) + '</b> run and the output stream in, with the key signal line highlighted.'
      : 'Watch <b>' + esc(activeCmd && activeCmd.label ? activeCmd.label : activeTool) + '</b> run. <span class="rp-nosample">See the command breakdown above and what this step proves below.</span>';
    var factsInit = (rp.proves && rp.proves.length)
      ? '<span class="rp-facts-l">New facts in hand</span>' + rp.proves.map(function (f) { return '<span class="study-chip proof">+ ' + esc(titleCase(human(f))) + '</span>'; }).join('')
      : '';

    // Runways reference panes (keeps .study-runways, .rw-pane[data-pane="remote"|"onhost"], .rw-connect, and .study-cmd intact)
    var runwaysBody = '';
    if (cmds.length) {
      var conn = connectCmd(osForMove(cell));
      if (remote.length && !onhost.length) {
        var rnote = (cell.locus === 'F' || cell.locus === 'I')
          ? '<div class="rw-when"><b>From your own box (Kali).</b> You stage the tool on Kali and run it against the target.</div>'
          : '<div class="rw-when"><b>From your own box (Kali).</b> This is a remote move: you run it over the network from Kali before or without needing a target shell.</div>';
        runwaysBody = '<div class="rw-pane" data-pane="remote">' + rnote + remote.map(function (c) { return commandBlock(c, activeIdx); }).join('') + '</div>';
      } else if (!remote.length && onhost.length) {
        var hnote = '<div class="rw-when"><b>On the target, once you have a foothold.</b> This reads or changes state that only lives on the box, so open a shell first, then run it in that shell.</div>';
        runwaysBody = '<div class="rw-pane" data-pane="onhost">' + hnote + '<div class="rw-connect">' + commandBlock(conn, -1) + '</div>' + onhost.map(function (c) { return commandBlock(c, activeIdx); }).join('') + '</div>';
      } else {
        var remoteWhen = '<div class="rw-when"><b>From Your Box (Remote):</b> Fast, leaves zero artifacts on disk, and needs no interactive shell. Reach for it first.</div>';
        var hostWhen = '<div class="rw-when"><b>On the Target (Shell):</b> Use when you already hold an interactive shell, when WinRM/SMB remote wrappers mangle quoting, or when running local enumeration binaries.</div>';
        var remotePane = remoteWhen + remote.map(function (c) { return commandBlock(c, activeIdx); }).join('');
        var hostPane = hostWhen + '<div class="rw-connect">' + commandBlock(conn, -1) + '</div>' + onhost.map(function (c) { return commandBlock(c, activeIdx); }).join('');
        runwaysBody = '<div class="rw-pane" data-pane="remote"' + (activeLocus === 'remote' ? '' : ' hidden') + '>' + remotePane + '</div>'
          + '<div class="rw-pane" data-pane="onhost"' + (activeLocus === 'onhost' ? '' : ' hidden') + '>' + hostPane + '</div>';
      }
    }

    return '<div class="study-workbench study-replay study-runways" data-move="' + U.attr(rp.id) + '" data-cmd-idx="' + U.attr(String(activeIdx)) + '">'
      + '<div class="study-replay-bar wb-header">'
      + '<span class="study-replay-title">▶ Interactive Command &amp; Terminal Workbench</span>'
      + (rp.multi ? '<span class="wb-multi-badge">' + OBOL.ic('branch') + ' ' + (rp.steps ? rp.steps.length + '-Step Pipeline' : 'Multi-Step Sequence') + '</span>' : '')
      + locusHead
      + '</div>'
      + hubBar
      + variantTabs
      + approachCtx
      + activeCmdBar
      + switchBreakdownHtml(activeSwitches, switchStepLabel)
      + '<div class="wb-term-wrap">'
      + '<div class="wb-term-head"><span class="wb-term-title">Emulated Terminal Replay' + (activeCmd && activeCmd.label ? ' · ' + esc(activeCmd.label) : '') + '</span><span class="study-replay-loc">' + locusGlyph(activeCmd ? activeCmd.locus : rp.locus) + ' ' + esc(activePrompt) + ' · ' + esc(activeTool) + '</span></div>'
      + '<div class="study-replay-term" id="rp-term"><div class="rp-idle">' + idle + '</div></div>'
      + '<div class="study-replay-facts" id="rp-facts" aria-live="polite">' + factsInit + '</div>'
      + '<div class="study-replay-ctrl">'
      + '<button type="button" class="study-rp-btn primary" data-rp="play">▶ Play</button>'
      + (rp.hasOutput ? '<button type="button" class="study-rp-btn" data-rp="skip">⏭ Skip to result</button>' : '')
      + '<button type="button" class="study-rp-btn" data-rp="restart">↺ Replay</button>'
      + '<button type="button" class="study-rp-btn study-rp-auto' + (_autolane ? ' on' : '') + '" data-rp="autolane">' + (_autolane ? '⏹ Stop auto-play' : '⏭ Auto-play the whole path') + '</button>'
      + '<span class="study-rp-prog"></span>'
      + '</div></div>'
      + (runwaysBody ? '<details class="wb-allcmds" open><summary class="wb-allcmds-sum">All Command Variants &amp; Locus Details (' + cmds.length + ')</summary>' + runwaysBody + '</details>' : '')
      + '</div>';
  }

  // the scope-safety badge (header) + callout (body) - teach when NOT to fire a move
  function scopeBadge(id) {
    var s = study().scopeSafety(id);
    if (s.level === 'destructive') return '<span class="study-badge b-danger">can break things</span>';
    if (s.level === 'loud') return '<span class="study-badge b-loud">loud</span>';
    return '';
  }
  function scopeCallout(id) {
    var s = study().scopeSafety(id);
    if (s.level === 'safe' || !s.note) return '';
    var lab = s.level === 'destructive' ? 'Can break things' : 'Loud';
    return '<div class="study-scope ' + s.level + '"><span class="study-scope-i">' + (s.level === 'destructive' ? OBOL.ic('stop') : OBOL.ic('sound')) + '</span>'
      + '<div><b>' + lab + '.</b> ' + esc(s.note) + ' On the exam, scope is the rule: do not nuke what you do not have to.</div></div>';
  }

  function whyPanel(cell) {
    if (!study().showWhy(cell.id) && !_whyOverride[cell.id]) {
      return '<button type="button" class="study-why-show" data-why-show>Show the reasoning</button>';
    }
    var authored = study().whyNow(cell.id);
    if (authored) {
      return '<div class="study-why"><div class="study-why-h">Why this, why now</div><p>' + codeify(authored) + '</p></div>';
    }
    var proves = (cell.proves || [])[0];
    var needs = cell.prereqFacts.length
      ? 'you are holding ' + cell.prereqFacts.map(function (f) { return '<b>' + esc(human(f)) + '</b>'; }).join(', ')
      : 'this is an opening move, so it needs nothing but a reachable target';
    var turns = proves ? ('it turns that into <b>' + esc(human(proves)) + '</b>') : 'it confirms the step worked';
    var mattersBit = (cell.opens && cell.opens.length) ? (', which is exactly what <b>' + esc(cell.opens[0].title) + '</b> needs next') : '';
    return '<div class="study-why"><div class="study-why-h">Why this, why now</div>'
      + '<p>You reach for this because ' + needs + ', and ' + turns + mattersBit + '.</p></div>';
  }

  // ---- "Before This Move: How you got here" ----------------------------------------------------
  var RECAP_COLORS = ['#4FC3F7', '#B088FF', '#FF9E5E', '#4DD6C1', '#FF8FB8'];
  function leadupPaths(moveId) {
    var raw = study().leadupFor(moveId); if (!raw) return [];
    if (raw[0] && raw[0].steps) return raw;
    return [{ key: 'default', label: '', steps: raw }];
  }
  function chosenPath(moveId) {
    var paths = leadupPaths(moveId); if (!paths.length) return null;
    var sel = _recapPath[moveId];
    return paths.filter(function (p) { return p.key === sel; })[0] || paths[0];
  }
  function recapSteps(moveId) {
    var out = [];
    var cp = chosenPath(moveId);
    if (cp) cp.steps.forEach(function (s) {
      out.push({ title: s.title || (s.tool || 'Recon'), tool: s.tool || '', where: s.where || 'local', cmd: s.cmd || '', sig: s.sig || '', teach: s.teach || '' });
    });
    return out;
  }
  function recapBlock() {
    if (!study().leadupFor(_sel)) return '';
    var steps = recapSteps(_sel); if (!steps.length) return '';
    var cur = study().cellFor(_sel);
    var paths = leadupPaths(_sel), cp = chosenPath(_sel);
    var rows = steps.map(function (s, i) {
      var pr = detectPromptFor(s.cmd, s.tool, s.where);
      var hostLike = isHostPrompt(pr, s.where);
      return '<div class="recap-step" data-recap="' + i + '">'
        + '<div class="recap-top"><span class="recap-n">' + (i + 1) + '</span><span class="recap-title">' + esc(s.title) + '</span>'
        + '<span class="recap-where">' + (hostLike ? 'On the Target' : 'Your Box') + '</span></div>'
        + '<div class="recap-cmd"><span class="recap-prompt' + (hostLike ? ' host' : '') + '">' + esc(pr) + '</span> ' + esc(benchFill(s.cmd)) + '</div>'
        + (s.sig ? '<div class="recap-sig">' + esc(benchFill(s.sig)) + '</div>' : '')
        + (s.teach ? '<div class="recap-cap">↳ ' + codeify(benchFill(s.teach)) + '</div>' : '')
        + '</div>';
    }).join('');
    var toggles = paths.length > 1
      ? '<div class="recap-paths" role="tablist">' + paths.map(function (p, i) {
          var col = RECAP_COLORS[i % RECAP_COLORS.length];
          return '<button type="button" class="recap-path' + (p.key === cp.key ? ' on' : '') + '" data-recap-path="' + U.attr(p.key) + '" style="--rpc:' + col + '">' + esc(p.label) + '</button>';
        }).join('') + '</div>'
      : '';
    var note = '<div class="recap-note">' + (paths.length > 1
      ? 'One plausible route to here, of several. Real engagements vary, so switch routes to see other ways in.'
      : 'One plausible route to here. Real engagements vary; this is an example, not the only way in.') + '</div>';
    var open = recapOpen();
    return '<div class="study-recap' + (open ? '' : ' collapsed') + '" id="study-recap">'
      + '<button type="button" class="recap-h" data-recap-toggle aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<span class="recap-chev">' + (open ? '▾' : '▸') + '</span>'
      + '<span class="recap-h-t">Before This Move: How you got here</span>'
      + (open ? '' : '<span class="recap-count">' + steps.length + ' steps that led here</span>')
      + '<span class="recap-showbtn">' + (open ? 'Hide ▴' : 'Show ▾') + '</span>'
      + '</button>'
      + '<div class="recap-body">'
      + note + toggles
      + '<div class="recap-steps">' + rows + '</div>'
      + '<div class="recap-here"><span class="recap-here-i">▾</span> You are here: <b>' + esc(cur.title) + '</b></div>'
      + '</div></div>';
  }
  function recapOpen() { try { return localStorage.getItem('obol.study-recap') === 'open'; } catch (e) { return false; } }
  function setRecapOpen(v) { try { localStorage.setItem('obol.study-recap', v ? 'open' : 'closed'); } catch (e) {} }

  // ---- Right-Hand Operator Field Guide (Playbook, Signal & False Positives, If It Fails) -------
  function hasDemoBench(id) { var h = study().howTo(id); return !!(h && h.items.some(function (it) { return it.demo && it.demo.length; })); }
  function hasFieldGuide(id) { return !!(study().howTo(id) || study().signalTell(id) || (study().blockersFor && study().blockersFor(id).length)); }

  function benchBody(h, moveId) {
    if (!h || !h.items || !h.items.length) return '<p class="howto-lead">No tactical variations recorded for this step.</p>';
    var sel = _benchSel[moveId] || 0; if (sel >= h.items.length) sel = 0;
    var list = h.items.map(function (it, i) {
      return '<button type="button" class="bench-item' + (i === sel ? ' on' : '') + '" data-bench="' + i + '">'
        + '<span class="bench-num">' + (i + 1) + '</span><span class="bench-it-t">' + esc(it.t) + '</span></button>';
    }).join('');
    return (h.lead ? '<p class="howto-lead">' + codeify(h.lead) + '</p>' : '')
      + '<div class="bench"><div class="bench-list">' + list + '</div>'
      + '<div class="bench-main" id="bench-main">' + benchMain(h.items, sel) + '</div></div>';
  }

  function fgSignalPane(cell) {
    var resolved = resolveActiveCmd(cell);
    var activeCmd = resolved.activeCmd;
    var t = study().signalTell(cell.id);
    var body = (activeCmd && activeCmd.teach) || (t && (t.teach || t.gist)) || '';
    var sig = (activeCmd && activeCmd.signal) || (cell.output && cell.output.signal) || (t && t.signal) || '';
    var s = study().scopeSafety(cell.id);
    var h = '<div class="fg-pane fg-signal-pane">';
    if (activeCmd && activeCmd.label) {
      h += '<div class="fg-card fg-card-active"><div class="fg-card-h">Active Approach: ' + esc(activeCmd.label) + '</div>'
        + (activeCmd.when ? '<p class="fg-card-p">' + codeify(benchFill(activeCmd.when)) + '</p>' : '')
        + '</div>';
    }
    if (activeCmd && activeCmd.steps && activeCmd.steps.length > 1) {
      h += '<div class="fg-card fg-card-sig"><div class="fg-card-h">Pipeline Step Signals (' + activeCmd.steps.length + ' Steps)</div>'
        + activeCmd.steps.map(function (st, si) {
            return '<div class="fg-step-sig"><div class="fg-ss-top"><b>Step ' + (si + 1) + ':</b> ' + esc(st.title || st.tool || '') + '</div>'
              + (st.sig ? '<pre class="fg-sig-code">' + esc(benchFill(st.sig)) + '</pre>' : '')
              + (st.teach ? '<p class="fg-card-p">' + codeify(benchFill(st.teach)) + '</p>' : '')
              + '</div>';
          }).join('')
        + '</div>';
    } else {
      if (sig) {
        h += '<div class="fg-card fg-card-sig"><div class="fg-card-h">Key Signal Line to Spot</div>'
          + '<pre class="fg-sig-code">' + esc(benchFill(sig)) + '</pre></div>';
      }
      if (body) {
        h += '<div class="fg-card fg-card-tell"><div class="fg-card-h">Reading the Result</div>'
          + '<p class="fg-card-p">' + codeify(benchFill(body)) + '</p></div>';
      }
    }
    if (cell.rulesOut) {
      h += '<div class="fg-card fg-card-trap"><div class="fg-card-h">⚠ False Positives &amp; What This Does NOT Prove</div>'
        + '<p class="fg-card-p">' + codeify(cell.rulesOut) + '</p></div>';
    }
    if (s && s.note) {
      h += '<div class="fg-card fg-card-scope"><div class="fg-card-h">OpSec &amp; Exam Scope Profile (' + esc(s.level || 'safe') + ')</div>'
        + '<p class="fg-card-p">' + esc(s.note) + '</p></div>';
    }
    h += '</div>';
    return h;
  }

  function fgBlockersPane(cell) {
    var list = (cell.blockers && cell.blockers.length) ? cell.blockers : (study().blockersFor ? study().blockersFor(cell.id) : []);
    if (!list.length) {
      return '<div class="fg-pane"><p class="howto-lead">No common blockers recorded for this move.</p></div>';
    }
    var cards = list.map(function (b) {
      var fixCmd = b.fixCmd || b.code || '';
      var errBadge = b.error ? '<span class="fg-blk-err">' + esc(b.error) + '</span>' : '';
      var bodyP = b.body ? '<p class="fg-blk-why">' + codeify(b.body) + '</p>' : '';
      return '<div class="fg-blocker-card">'
        + '<div class="fg-blk-top">' + errBadge
        + '<span class="fg-blk-title">' + esc(b.title) + '</span></div>'
        + (b.why ? '<p class="fg-blk-why">' + codeify(b.why) + '</p>' : '')
        + bodyP
        + (fixCmd ? '<div class="fg-blk-fix"><div class="fg-blk-fix-h"><span>Suggested Fix / Bypass Command</span><button type="button" class="study-cmd-copy" data-wb-copy="' + U.attr(benchFill(fixCmd)) + '">Copy</button></div><pre class="fg-blk-cmd">' + esc(benchFill(fixCmd)) + '</pre></div>' : '')
        + '</div>';
    }).join('');
    return '<div class="fg-pane fg-blockers-pane">'
      + '<p class="howto-lead">When this move fails in a lab or exam, match the error string below to recover or pivot cleanly:</p>'
      + cards
      + '</div>';
  }

  function howColumn() {
    var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
    if (!cell) return '';
    var resolved = resolveActiveCmd(cell);
    var activeCmd = resolved.activeCmd;
    var h = study().howTo(_sel);
    var blockers = (cell.blockers && cell.blockers.length) ? cell.blockers : (study().blockersFor ? study().blockersFor(_sel) : []);
    var tab = _fgTab[_sel] || 'playbook';
    var live = benchLive();
    var badge = live
      ? '<span class="bench-live">● filled from your engagement</span>'
      : '<span class="bench-live off">Example values, these fill in once you start an engagement</span>';
    var syncCard = '';
    if (activeCmd) {
      var activeSig = activeCmd.signal || (cell.output && cell.output.signal) || '';
      var activeRead = activeCmd.teach || activeCmd.when || '';
      syncCard = '<div class="fg-active-sync">'
        + '<div class="fg-as-top"><span class="fg-as-k">Synced with Workbench</span>'
        + '<span class="fg-as-t">' + esc(activeCmd.label || activeCmd.tool) + '</span></div>'
        + (activeSig ? '<div class="fg-as-sig"><span class="fg-as-sl">Signal:</span> <code>' + esc(benchFill(activeSig)) + '</code></div>' : '')
        + (activeRead ? '<div class="fg-as-read">' + codeify(benchFill(activeRead)) + '</div>' : '')
        + '</div>';
    }
    var tabsHtml = '<div class="fg-tabs" role="tablist">'
      + '<button type="button" class="fg-tab' + (tab === 'playbook' ? ' on' : '') + '" data-fg-tab="playbook">Playbook &amp; Variations</button>'
      + '<button type="button" class="fg-tab' + (tab === 'signal' ? ' on' : '') + '" data-fg-tab="signal">Signal &amp; Traps</button>'
      + '<button type="button" class="fg-tab' + (tab === 'blockers' ? ' on' : '') + '" data-fg-tab="blockers">If It Fails (' + blockers.length + ')</button>'
      + '</div>';
    var bodyHtml = '';
    if (tab === 'signal') bodyHtml = fgSignalPane(cell);
    else if (tab === 'blockers') bodyHtml = fgBlockersPane(cell);
    else bodyHtml = benchBody(h, _sel);

    return '<div class="study-benchcol">'
      + '<div class="study-panel benchpanel study-bench">'
      + '<div class="benchcol-h"><span class="benchcol-title">Operator Field Guide: how to actually do it</span></div>'
      + badge
      + syncCard
      + tabsHtml
      + '<div class="fg-body">' + bodyHtml + '</div>'
      + '</div>'
      + '</div>';
  }

  function benchMain(items, i) {
    var it = items[i]; if (!it) return '';
    var hasDemo = it.demo && it.demo.length;
    var h = '<div class="bench-tech"><div class="bench-t">' + esc(it.t) + '</div><div class="bench-d">' + codeify(it.d) + '</div></div>';
    if (hasDemo) {
      h += '<div class="bench-term" id="bench-term">' + benchTermStatic(it.demo) + '</div>'
        + '<div class="bench-ctrl"><button type="button" class="study-rp-btn primary" data-bench-play>▶ Play</button>'
        + '<button type="button" class="study-rp-btn" data-bench-replay>↺ Replay</button></div>';
    }
    h += (it.note ? '<div class="bench-note' + (hasDemo ? '' : ' bench-note-solo') + '"><span class="bench-note-i">↳</span> ' + codeify(it.note) + '</div>' : '');
    return h;
  }
  function benchTermStatic(demo) {
    return (demo || []).map(function (s) {
      var sig = benchFill(s.sig || '');
      var runStr = benchFill(s.run);
      var pr = detectPromptFor(runStr, '', '');
      var out = benchFill(s.out).split('\n').map(function (ln) {
        var hot = sig && ln.indexOf(sig) >= 0;
        return '<span class="bench-ln' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</span>';
      }).join('');
      return '<span class="bench-ln bench-cmd">' + esc(pr) + ' ' + esc(runStr) + '</span>' + out;
    }).join('');
  }
  function cancelBench() { if (_benchTok) { _benchTok.cancelled = true; _benchTok = null; } }
  function playBenchTerm(mount, demo) {
    cancelBench();
    var term = mount.querySelector('#bench-term'); if (!term) return;
    var tok = { cancelled: false }; _benchTok = tok;
    term.innerHTML = '';
    var steps = (demo || []).map(function (s) {
      var r = benchFill(s.run);
      return { cmd: r, prompt: detectPromptFor(r, '', ''), out: benchFill(s.out), sig: benchFill(s.sig || '') };
    });
    var si = 0;
    function nextStep() {
      if (tok.cancelled || si >= steps.length) return;
      var s = steps[si], cmdEl = document.createElement('span');
      cmdEl.className = 'bench-ln bench-cmd'; term.appendChild(cmdEl);
      var ci = 0;
      (function type() {
        if (tok.cancelled) return;
        if (ci <= s.cmd.length) { cmdEl.textContent = s.prompt + ' ' + s.cmd.slice(0, ci); ci++; setTimeout(type, 11); return; }
        var lines = s.out.split('\n'), li = 0;
        (function emit() {
          if (tok.cancelled) return;
          if (li < lines.length) {
            var el = document.createElement('span'), hot = s.sig && lines[li].indexOf(s.sig) >= 0;
            el.className = 'bench-ln' + (hot ? ' hot' : ''); el.textContent = lines[li] || ' '; term.appendChild(el);
            term.scrollTop = term.scrollHeight; li++; setTimeout(emit, 80); return;
          }
          si++; setTimeout(nextStep, 300);
        })();
      })();
    }
    nextStep();
  }

  function signalTellBlock(cell) {
    var resolved = resolveActiveCmd(cell);
    var activeCmd = resolved.activeCmd;
    var t = study().signalTell(cell.id);
    var body = (activeCmd && activeCmd.teach) || (t && (t.teach || t.gist)) || '';
    if (!body) return '';
    var title = (activeCmd && activeCmd.label) ? ('Reading the result · ' + activeCmd.label) : 'Reading the result';
    return '<div class="study-tell"><div class="study-tell-h">' + esc(title) + '</div>'
      + '<p>' + codeify(benchFill(body)) + '</p></div>';
  }

  function decisionPanel(cell) {
    var ds = study().decisionFor(cell.id); if (!ds.length) return '';
    return ds.map(function (d) {
      var detail = d.detail.map(function (o) {
        var m = study().cellFor(o.id);
        return '<div class="dec-opt"><button type="button" class="dec-opt-t" data-goto="' + U.attr(o.id) + '">' + esc(m ? m.title : o.id) + '</button>'
          + '<span class="dec-opt-when">' + esc(o.when) + '</span></div>';
      }).join('');
      return '<div class="study-decision"><div class="dec-q">' + esc(d.question) + '</div>'
        + '<div class="dec-tldr"><span class="dec-tldr-l">In short</span> Default to <b>' + esc(d.pick) + '</b>. ' + esc(d.rule) + ' <span class="dec-unless">Unless ' + esc(d.unless) + '</span></div>'
        + '<details class="dec-detail"><summary>The longer why, option by option</summary>' + detail + '</details>'
        + '</div>';
    }).join('');
  }

  function showFactPop(mount, fact) {
    var el = mount.querySelector('#study-factpop'); if (!el) return;
    var info = study().factInfo(fact);
    function list(arr, kind) {
      if (!arr.length) return '<p class="fp-none">' + (kind === 'from' ? 'No earlier step produces this. It comes from the environment itself, so you find it during recon, a port you scan open, a service banner, a form you spot while browsing the target, rather than earning it with a command.' : 'This is a goal in its own right. Nothing further depends on it; it is a result you bank.') + '</p>';
      return '<div class="fp-moves">' + arr.slice(0, 12).map(function (m) { return '<button type="button" class="fp-move lane-' + (laneKeyOf(m.id)) + '" data-goto="' + U.attr(m.id) + '">' + esc(m.title) + '</button>'; }).join('') + '</div>';
    }
    el.innerHTML = '<div class="fp-card">'
      + '<button type="button" class="fp-close" data-factpop-close aria-label="Close">×</button>'
      + '<div class="fp-fact">' + esc(titleCase(info.label)) + '</div>'
      + '<p class="fp-lead">Every move needs certain facts in hand before it makes sense, and hands you new ones when it lands. Here is where this fact fits in the chain.</p>'
      + '<div class="fp-sec"><div class="fp-sec-l">You get it from</div>' + list(info.producedBy, 'from') + '</div>'
      + '<div class="fp-sec"><div class="fp-sec-l">Once you have it, it unlocks</div>' + list(info.unlocks, 'to') + '</div>'
      + '</div>';
    el.hidden = false;
  }

  function nextPreviewsHtml(cell) {
    var list = (cell.nextPreviews && cell.nextPreviews.length) ? cell.nextPreviews : (study().nextPreviewFor ? study().nextPreviewFor(cell.id) : []);
    if (!list || !list.length) return '';
    return '<div class="study-next-previews">'
      + '<div class="snp-head">Next Move Command Preview</div>'
      + '<div class="snp-grid">'
      + list.map(function (np) {
          return '<div class="snp-card">'
            + '<div class="snp-top">'
            + '<button type="button" class="snp-title" data-goto="' + U.attr(np.id) + '">' + esc(np.title) + ' →</button>'
            + (np.when ? '<span class="snp-when">' + esc(np.when) + '</span>' : '')
            + '</div>'
            + (np.cmd ? '<pre class="snp-cmd"><span class="snp-pr">' + esc(np.prompt || 'kali$') + '</span> ' + esc(benchFill(np.cmd)) + '</pre>' : '')
            + '</div>';
        }).join('')
      + '</div></div>';
  }

  // ---- Center Column: WATCH (Before -> During -> After Flow) -----------------------------------
  function cellPanel() {
    var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
    if (!cell) return '<div class="study-panel"><p class="study-sub">This step is not available in this build.</p></div>';
    var h = '<div class="study-panel study-center-col">';
    h += '<div class="study-cell-h"><h2 class="study-cell-title">' + esc(cell.title) + '</h2>'
      + (cell.phase ? '<span class="study-badge b-phase">' + esc(cell.phase) + '</span>' : '')
      + (cell.scope ? '<span class="study-badge b-scope">' + esc(cell.scope === 'oscp' ? 'OSCP core' : cell.scope) + '</span>' : '')
      + (cell.locus ? '<span class="study-badge b-locus">' + esc(cell.locus === 'R' ? 'runs remotely' : (cell.locus === 'F' ? 'runs on the target' : 'interactive on the target')) + '</span>' : '')
      + scopeBadge(cell.id)
      + '</div>';
    if (cell.whatItIs) h += '<p class="study-cell-sub">' + codeify(cell.whatItIs) + '</p>';

    // 1. WHY THIS MOVE
    h += whyPanel(cell);

    // 2. BEFORE THIS MOVE (Starting From + How You Got Here)
    h += '<div class="study-startfrom"><span class="study-sf-l">Starting from</span> '
      + (cell.prereqFacts.length ? factChips(cell.prereqFacts, 'proven') : '<span class="study-dim">nothing. This is an opening move.</span>')
      + (cell.producedBy.length ? '<span class="study-via">you would have run ' + cell.producedBy.slice(0, 2).map(function (x) { return '<b>' + esc(x.title) + '</b>'; }).join(', ') + '</span>' : '')
      + '</div>';
    h += recapBlock();

    // 3. DURING THIS MOVE (Unified Interactive Command & Terminal Workbench)
    h += workbenchPanel(cell);

    // Reading the highlighted result line
    h += signalTellBlock(cell);

    // Tool selection tradeoffs
    h += decisionPanel(cell);

    // 4. AFTER THIS MOVE (What You Walk Away With + Unlocks Next + Concrete Command Previews)
    h += '<div class="study-seg study-outcome"><div class="study-seg-l">After This Move: What you walk away with <span class="study-seg-note">and the moves it unlocks</span></div>'
      + '<div class="study-flow">' + factChips(cell.proves, 'proof')
      + (cell.opens.length ? '<span class="study-arr">unlocks</span>' + cell.opens.slice(0, 4).map(function (x) { return '<button type="button" class="study-chip study-next" data-goto="' + U.attr(x.id) + '">' + esc(x.title) + ' →</button>'; }).join('') : '')
      + '</div>'
      + nextPreviewsHtml(cell)
      + '</div>';

    // 5. WATCH OUT & SCOPE SAFETY
    h += scopeCallout(cell.id);
    if (cell.rulesOut) h += '<div class="study-mistake"><span class="study-mi">⚠</span><div><b>Watch out:</b> ' + codeify(cell.rulesOut) + '</div></div>';

    h += '</div>';
    return h;
  }

  // ---- YOUR TURN (practice) -------------------------------------------------------------------
  function nextMovePanel() {
    var q = study().practiceFor(_sel, _pathMode && _path.length ? _path : null);
    if (!q) return '<div class="study-scn"><p>No practice for this step yet.</p></div>';
    var letters = 'ABCDEFGH';
    var h = '<div class="study-scn"><div class="study-scn-l">The situation</div><p>' + codeify(q.situation || 'Given where you are, what is your next move?') + '</p></div>';
    h += '<div class="study-q">What is your next move?</div><div class="study-choices">';
    q.choices.forEach(function (c, i) {
      var missingTxt = (c.missing || []).map(function (mk) { return /^one of:/.test(mk) ? ('one of: ' + mk.replace(/^one of:\s*/, '').split(' / ').map(human).join(' or ')) : human(mk); });
      var missing = missingTxt.length ? ' data-missing="' + U.attr(missingTxt.join('; ')) + '"' : '';
      h += '<button type="button" class="study-choice" data-verdict="' + U.attr(c.verdict) + '" data-cid="' + U.attr(c.id) + '"' + missing
        + (c.coach ? ' data-coach="' + U.attr(c.coach) + '"' : '') + '>'
        + '<span class="study-tag">' + letters[i] + '</span>'
        + '<span class="study-ct">' + esc(c.title) + '</span></button>';
    });
    h += '</div><div class="study-verdict" id="study-verdict" role="status" aria-live="polite"></div>';
    h += '<div class="study-reveal-slot" id="study-reveal-slot"></div>';
    return h;
  }
  function diagnosePanel() {
    var q = study().practiceDiagnose(_sel);
    if (!q) return '<div class="study-scn"><p>This step has no captured output to read yet. Try <b>What to do next</b> instead.</p></div>';
    var letters = 'ABCDEFGH';
    var term = q.output.split('\n').map(function (ln) { var hot = q.signal && ln.indexOf(q.signal) >= 0; return '<span class="study-ln' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</span>'; }).join('');
    var h = '<div class="study-q">You ran <b>' + esc(q.title) + '</b> and got this:</div>';
    h += '<div class="study-term dx-term">' + term + '</div>';
    h += '<div class="study-q">' + esc(q.question) + '</div><div class="study-choices">';
    q.choices.forEach(function (c, i) {
      h += '<button type="button" class="study-choice study-dx-choice" data-correct="' + (c.correct ? '1' : '0') + '">'
        + '<span class="study-tag">' + letters[i] + '</span><span class="study-ct">' + esc(c.label) + '</span></button>';
    });
    h += '</div><div class="study-verdict" id="study-verdict" role="status" aria-live="polite"></div>';
    h += '<div class="dx-why" id="dx-why" data-why="' + U.attr(q.why) + '" hidden></div>';
    return h;
  }
  function practicePanel() {
    var h = '<div class="study-panel">';
    h += '<div class="study-pmodes"><span class="study-pm-l">Test me on</span>'
      + '<button type="button" class="study-pm' + (_practiceMode !== 'read' ? ' on' : '') + '" data-pmode="next">What to do next</button>'
      + '<button type="button" class="study-pm' + (_practiceMode === 'read' ? ' on' : '') + '" data-pmode="read">Reading the output</button></div>';
    h += _practiceMode === 'read' ? diagnosePanel() : nextMovePanel();
    return h + '</div>';
  }

  // ---- the Learn landing's building blocks -----------------------------------------------------
  function barCard(o) {
    var isLink = !!o.href;
    var open = isLink ? '<a class="sl-way ' + o.mod + '" href="' + o.href + '">'
      : '<button type="button" class="sl-way ' + o.mod + '" ' + (o.trig || '') + '>';
    var close = isLink ? '</a>' : '</button>';
    return open
      + '<span class="sl-way-top"><span class="sl-way-ic" aria-hidden="true">' + o.icon + '</span>'
      + '<span class="sl-way-head"><span class="sl-way-kick">' + esc(o.kick) + '</span><span class="sl-way-t">' + esc(o.title) + '</span></span></span>'
      + '<span class="sl-way-d">' + esc(o.desc) + '</span>'
      + '<span class="sl-way-go">' + esc(o.go) + ' →</span>'
      + close;
  }
  function heroProg(contId, studied, total) {
    return '<button type="button" class="sl-hero-prog" data-open="' + U.attr(contId) + '">'
      + '<span class="sl-hp-g">' + studied + '<span class="sl-hp-tot">/' + total + '</span></span>'
      + '<span class="sl-hp-t">' + (studied ? 'Continue Where You Left Off' : 'Your Progress') + '</span>'
      + '<span class="sl-hp-d">' + (studied ? (studied + ' step' + (studied === 1 ? '' : 's') + ' studied · resume →') : 'Pick a lane and your progress tracks here.') + '</span></button>';
  }
  function slPortCard(e) {
    var fam = e.fam || 'recon', n = e.moves.length;
    return '<button type="button" class="sl-pcard sl-fam-' + esc(fam) + '" data-port-open="' + U.attr(e.key) + '">'
      + '<span class="sl-pcard-top"><span class="sl-pnum">' + esc(e.port) + '</span>'
      + '<span class="sl-psvc">' + esc(e.label) + '</span><span class="sl-pfam">' + esc(fam) + '</span></span>'
      + '<span class="sl-psig">' + esc(e.signal) + '</span>'
      + '<span class="sl-pmoves">' + n + ' move' + (n === 1 ? '' : 's') + ' →</span></button>';
  }
  function slAccessCard(e) {
    return '<button type="button" class="sl-acard" data-port-open="' + U.attr(e.key) + '">'
      + '<span class="sl-adot" aria-hidden="true"></span><span class="sl-at">' + esc(e.label) + '</span></button>';
  }

  var SL_CURATED_PORTS = ['p80', 'p135', 'p88', 'p389', 'p22', 'p21', 'p3306', 'p1433', 'p53', 'p161', 'p3389', 'p5985'];

  function mapView() {
    var ls = study().lanes();
    var totalSteps = ls.reduce(function (a, L) { return a + L.count; }, 0);
    var studiedTotal = 0, contId = (ls[0] || {}).firstId || '', best = 0;
    ls.forEach(function (L) { var pr = study().laneProgress(L.key); studiedTotal += pr.studied; if (pr.studied > best) { best = pr.studied; contId = L.firstId; } });
    var ev = study().evidence(), byKey = {};
    ev.forEach(function (e) { byKey[e.key] = e; });
    var ports = SL_CURATED_PORTS.map(function (k) { return byKey[k]; }).filter(Boolean);
    var access = ev.filter(function (e) { return e.tier === 'access'; });

    var h = '<section class="study-route study-map">';
    h += '<div class="study-hero sl-hero">'
      + '<div class="sl-hero-main"><span class="sl-tag">Learn at your own pace, your own way</span>'
      + '<h1 class="study-hero-h">Learn the methodology</h1>'
      + '<p class="study-hero-p">OBOL teaches offensive security as a decision graph: <b>know what to do, and why, from what you\'ve found.</b> '
      + 'Start from a structured path, from a port you just scanned, or drop into a live box. Brand new or setting up a lab? Visit <a href="#/start">Start Here</a>.</p></div>'
      + heroProg(contId, studiedTotal, totalSteps)
      + '</div>';
    h += '<div class="sl-bar">'
      + barCard({ trig: 'data-sim', mod: 'sl-way-cold', icon: OBOL.ic('play'), kick: 'Guided Simulation', title: 'Run a Cold Box', desc: 'Start from an IP and nothing else. Read each result, choose the next move, and watch the box fall one step at a time.', go: 'Start a Run' })
      + barCard({ trig: 'data-graph', mod: 'sl-way-atlas', icon: OBOL.ic('graph'), kick: 'The Whole Map', title: 'Walk the Attack Graph', desc: 'Every move in one graph, wired by what unlocks what. Pan, zoom, and trace end-to-end paths, or light up a ready-made scenario.', go: 'Open the Atlas' })
      + barCard({ trig: 'data-decision', mod: 'sl-way-decision', icon: OBOL.ic('branch'), kick: 'Why Each Move', title: 'Walk the Decision Tree', desc: 'Every move as a decision: what unlocks it, what it proves, what it rules out. Follow the branches from an open port to the whole path.', go: 'Open the Map' })
      + barCard({ trig: 'data-ports', mod: 'sl-way-port', icon: OBOL.ic('ports'), kick: 'Start from a Scan', title: 'Browse by Open Port', desc: 'You scanned; these ports are open. Pick the one in front of you and get the exact, ordered moves it unlocks.', go: 'Full By-Port View' })
      + '</div>';
    h += '<div class="sl-dash">';
    function laneCard(L) {
      var pr = study().laneProgress(L.key), pct = pr.total ? Math.round(pr.studied / pr.total * 100) : 0;
      return '<button type="button" class="study-lane-card active lane-' + L.key + '" data-open="' + U.attr(L.firstId) + '">'
        + '<div class="study-lane-name"><span class="sln-t">' + esc(L.name) + '</span><span class="study-lane-badge">' + L.count + ' steps</span></div>'
        + '<div class="study-lane-desc">' + esc(L.desc) + '</div>'
        + '<div class="study-lane-foot"><div class="study-lane-bar"><span style="width:' + pct + '%"></span></div>'
        + '<span class="study-lane-go">' + (pr.studied ? pr.studied + ' / ' + pr.total + ' studied · continue →' : 'Start the path →') + '</span></div></button>';
    }
    function simLaneCard() {
      var scs = study().scenarios() || [];
      return '<button type="button" class="study-lane-card lane-sim" data-sim-card>'
        + '<div class="study-lane-name"><span class="sln-t">Cold-Box Exam Scenarios</span><span class="study-lane-badge">' + scs.length + ' chains</span></div>'
        + '<div class="study-lane-desc">Step through end-to-end multi-stage attack chains from a bare IP to root/SYSTEM under realistic exam conditions.</div>'
        + '<div class="study-lane-foot"><div class="study-lane-bar"><span style="width:100%"></span></div>'
        + '<span class="study-lane-go">Run a Cold-Box Scenario →</span></div></button>';
    }
    var GROUP = { ad: 1, database: 1 };
    var methodLanes = ls.filter(function (L) { return !GROUP[L.key]; }).concat(ls.filter(function (L) { return GROUP[L.key]; }));
    h += '<section class="sl-col sl-col-method" aria-label="Learn by methodology">'
      + '<div class="sl-col-h"><h2 class="sl-col-t">By Methodology</h2><span class="sl-col-count">' + ls.length + ' Lanes · ' + totalSteps + ' Steps</span></div>'
      + '<div class="study-lanes">' + methodLanes.map(laneCard).join('') + simLaneCard() + '</div></section>';
    h += '<section class="sl-col sl-col-port" aria-label="Learn by open port">'
      + '<div class="sl-col-h"><h2 class="sl-col-t">By Open Port</h2><span class="sl-col-count">What You Scanned</span></div>'
      + '<div class="sl-ports">' + ports.map(slPortCard).join('') + '</div>';
    if (access.length) {
      h += '<div class="sl-access-h">Once You\'re In, What You\'re Holding</div>'
        + '<div class="sl-access">' + access.map(slAccessCard).join('') + '</div>';
    }
    h += '</section></div>';
    return h + '</section>';
  }

  // ---- the BY-EVIDENCE view -------------------------------------------------------------------
  var FAM_LABEL = { recon: 'recon', web: 'web', db: 'database', ad: 'AD / Windows', remote: 'remote access', file: 'file share', mail: 'mail', access: 'post-foothold' };
  function evMovePill(m, i, mk) {
    var studied = (mk[m.id] || {}).studied ? ' done' : '';
    return '<li class="port-move-li"><button type="button" class="port-move lane-' + m.laneKey + studied + '" data-open="' + U.attr(m.id) + '">'
      + '<span class="pm-n" aria-hidden="true">' + i + '</span><span class="pm-t">' + esc(m.title) + '</span></button></li>';
  }
  function evMovesBlock(e, mk) {
    var moves = e.moves;
    if (moves.length <= 8) {
      return '<ol class="port-moves">' + moves.map(function (m, i) { return evMovePill(m, i + 1, mk); }).join('') + '</ol>';
    }
    var groups = [], gi = {};
    moves.forEach(function (m) { var c = m.cat || 'More'; if (gi[c] === undefined) { gi[c] = groups.length; groups.push({ cat: c, items: [] }); } groups[gi[c]].items.push(m); });
    var n = 0;
    return groups.map(function (g) {
      return '<div class="port-group"><h4 class="port-group-h">' + esc(g.cat) + '</h4><ol class="port-moves">'
        + g.items.map(function (m) { n += 1; return evMovePill(m, n, mk); }).join('') + '</ol></div>';
    }).join('');
  }
  function evidenceCard(e, mk, open) {
    var isPort = e.tier === 'ports';
    var n = e.moves.length;
    var fam = e.fam ? '<span class="evfam evfam-' + esc(e.fam) + '">' + esc(FAM_LABEL[e.fam] || e.fam) + '</span>' : '';
    var portBadge = (isPort && e.port) ? '<span class="port-num">' + esc(e.port) + (e.proto ? '<span class="port-proto">/' + esc(e.proto) + '</span>' : '') + '</span>' : '';
    var head = '<button type="button" class="port-head" data-ev-toggle="' + U.attr(e.key) + '" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<span class="port-lead">' + portBadge + '<span class="port-svc">' + esc(e.label) + '</span>' + fam + '</span>'
      + '<span class="port-meta"><span class="port-count">' + n + ' move' + (n === 1 ? '' : 's') + '</span>'
      + '<span class="port-chev" aria-hidden="true"></span></span>'
      + '</button>';
    var body = open
      ? '<div class="port-body"><p class="port-sig">' + esc(e.signal) + '</p>' + evMovesBlock(e, mk) + '</div>'
      : '<p class="port-sig port-sig-collapsed">' + esc(e.signal) + '</p>';
    return '<div class="port-card' + (e.key === 'scan' ? ' port-scan' : '') + (isPort ? '' : ' ev-access') + (e.fam ? ' port-fam-' + esc(e.fam) : '') + (open ? ' open' : '') + '">'
      + head + body + '</div>';
  }
  function portsView() {
    var ev = study().evidence(), mk = study().mastery(), op = evOpen();
    var portsT = ev.filter(function (e) { return e.tier === 'ports'; });
    var accessT = ev.filter(function (e) { return e.tier === 'access'; });
    var allOpen = ev.every(function (e) { return op[e.key]; });
    var isMap = _evMode === 'map';
    var h = '<section class="study-route study-ports">';
    h += '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Study</b> · By what you have found</div>'
      + '<div class="ev-mode-seg" role="group" aria-label="By-port view mode">'
      + '<button type="button" class="ev-mode' + (isMap ? '' : ' on') + '" data-ev-mode="cards" aria-pressed="' + (isMap ? 'false' : 'true') + '">Cards</button>'
      + '<button type="button" class="ev-mode' + (isMap ? ' on' : '') + '" data-ev-mode="map" aria-pressed="' + (isMap ? 'true' : 'false') + '">Decision map</button></div>'
      + (isMap ? '' : '<button type="button" class="ev-allbtn" data-ev-all="' + (allOpen ? 'close' : 'open') + '">' + (allOpen ? 'Collapse all' : 'Expand all') + '</button>')
      + '</div>';
    h += '<div class="study-hero"><h1 class="study-hero-h">What do I do with <i>this</i>?</h1>'
      + '<p class="study-hero-p">This is how you actually operate. You scan, and a list of open ports comes back. Each one is a signal: it tells you what the box runs and which moves it opens. '
      + 'Pick the port in front of you, read what it means, and open it for the ordered moves it unlocks. Once you are in, the signal changes to what you are holding, a shell, a hash, a credential.</p></div>';
    if (isMap) {
      h += '<p class="ev-map-lede">The whole decision forest, derived from the same move graph and ranker that drive the Cockpit, so it can never contradict the Cockpit. '
        + 'Use the port &amp; service chips below to isolate any service tree, scroll or use the controls to zoom, drag to pan, click + / - on a node to expand or fold its branches, and click any move to open its interactive workbench.</p>';
      h += '<div id="port-decision-map" class="dt-mount" role="region" aria-label="By-port decision map"></div>';
      return h + '</section>';
    }
    h += '<h2 class="ev-tier-h">Open ports, what you see first</h2>';
    h += '<div class="port-grid">' + portsT.map(function (e) { return evidenceCard(e, mk, !!op[e.key]); }).join('') + '</div>';
    h += '<h2 class="ev-tier-h">Once you are in, what you are holding</h2>';
    h += '<div class="port-grid ev-access-grid">' + accessT.map(function (e) { return evidenceCard(e, mk, !!op[e.key]); }).join('') + '</div>';
    return h + '</section>';
  }

  // ---- the full methodology graph (Atlas) -----------------------------------------------------
  var MAXC = 8, NW = 172, NH = 46, CGAP = 18, RGAP = 20, LEFT = 118, TOP = 10, BANDHEAD = 28, BANDGAP = 16;
  function atlasLayout() {
    var A = study().atlas();
    var colW = NW + CGAP, rowH = NH + RGAP, pos = {}, bands = [], y = TOP, maxRight = LEFT + MAXC * colW;
    A.lanes.forEach(function (L) {
      var collapsed = !!_collapsed[L.key];
      var laneNodes = A.nodes.filter(function (n) { return n.lane === L.key; });
      var rows = collapsed ? 0 : Math.ceil(laneNodes.length / MAXC) || 1;
      var top = y, h = BANDHEAD + (collapsed ? 6 : rows * rowH);
      if (!collapsed) laneNodes.forEach(function (n, idx) {
        var col = idx % MAXC, lr = Math.floor(idx / MAXC);
        var x = LEFT + col * colW, ny = top + BANDHEAD + lr * rowH;
        pos[n.id] = { x: x, y: ny, cx: x + NW / 2, cy: ny + NH / 2, lr: lr };
        if (x + NW > maxRight) maxRight = x + NW;
      });
      bands.push({ key: L.key, name: L.name, short: L.short, count: laneNodes.length, top: top, h: h, collapsed: collapsed, rows: rows, nodes: laneNodes });
      y += h + BANDGAP;
    });
    return { A: A, pos: pos, bands: bands, colW: colW, rowH: rowH, W: maxRight + 24, H: y + 6 };
  }

  function edgePath(pos, a, b, cross) {
    var p1 = pos[a], p2 = pos[b]; if (!p1 || !p2) return '';
    if (cross) { var sx = p1.cx, sy = (p2.cy > p1.cy ? p1.y + NH : p1.y), ex = p2.cx, ey = (p2.cy > p1.cy ? p2.y : p2.y + NH); return 'M' + sx + ',' + sy + ' C' + sx + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ((sy + ey) / 2) + ' ' + ex + ',' + ey; }
    if (p1.lr === p2.lr && p2.x > p1.x) { var x1 = p1.x + NW, y1 = p1.cy, x2 = p2.x, y2 = p2.cy, mx = (x1 + x2) / 2; return 'M' + x1 + ',' + y1 + ' C' + mx + ',' + y1 + ' ' + mx + ',' + y2 + ' ' + x2 + ',' + y2; }
    var bx = p1.cx, by = p1.y + NH, tx = p2.cx, ty = p2.y, my = (by + ty) / 2;
    return 'M' + bx + ',' + by + ' C' + bx + ',' + my + ' ' + tx + ',' + my + ' ' + tx + ',' + ty;
  }

  var SCEN_SLUG = { 'Recon': 'recon', 'Web to Shell': 'web', 'Cloud': 'cloud', 'Privilege Escalation': 'privesc', 'Active Directory': 'ad', 'Databases': 'database', 'Lateral & Pivot': 'pivot' };
  function catSlug(c) { return SCEN_SLUG[c] || 'recon'; }
  function scenariosBar() {
    var all = study().scenarios(), cats = study().scenarioCats(), byCat = {};
    all.forEach(function (s) { (byCat[s.cat] = byCat[s.cat] || []).push(s); });
    var groups = cats.filter(function (c) { return byCat[c]; }).map(function (c) {
      var slug = catSlug(c);
      return '<div class="scen-group scen-' + slug + '"><span class="scen-cat">' + esc(c) + '</span><div class="scen-chips">'
        + byCat[c].map(function (s) {
          return '<button type="button" class="atlas-scen scen-chip' + (s.key === _scenario ? ' on' : '') + '" data-scen="' + U.attr(s.key) + '" title="' + U.attr(s.desc) + '">'
            + esc(s.name) + ' <span class="scen-n">' + s.count + '</span></button>';
        }).join('') + '</div></div>';
    }).join('');
    return '<div class="atlas-scenarios"><div class="atlas-scen-head"><span class="atlas-scen-l">Common scenarios</span>'
      + '<span class="atlas-scen-or">pick one to light its path, then <b>Study this path</b> to walk it, or click steps to draw your own</span></div>'
      + '<div class="scen-groups">' + groups + '</div></div>';
  }
  function atlasView() {
    var LY = atlasLayout(), A = LY.A, pos = LY.pos, M = study().mastery();
    var laneEdgeSvg = A.laneEdges.map(function (e) { var d = edgePath(pos, e.from, e.to, false); return d ? '<path class="atlas-edge atlas-edge-lane lane-' + study().laneEntry(e.from).laneKey + '" d="' + d + '"/>' : ''; }).join('');
    var crossEdgeSvg = A.crossEdges.map(function (e) { var d = edgePath(pos, e.from, e.to, true); return d ? '<path class="atlas-edge atlas-edge-cross" d="' + d + '"><title>' + esc(e.note || '') + '</title></path>' : ''; }).join('');
    var nodeSvg = A.nodes.map(function (n) {
      var p = pos[n.id]; if (!p) return '';
      var proof = (n.proves && n.proves[0]) ? human(n.proves[0]) : '', mk = M[n.id] || {};
      var glyph = mk.correct ? '✓' : (mk.studied ? '◐' : '');
      return '<g class="atlas-node lane-' + n.lane + (mk.correct ? ' done' : (mk.studied ? ' seen' : '')) + '" data-anode="' + U.attr(n.id) + '" data-cx="' + p.cx + '" data-cy="' + p.cy + '" transform="translate(' + p.x + ',' + p.y + ')">'
        + '<rect class="an-box" width="' + NW + '" height="' + NH + '" rx="9"/>'
        + '<text class="an-badge" x="9" y="-7"></text>'
        + '<text class="an-mastery" x="' + (NW - 11) + '" y="17">' + glyph + '</text>'
        + '<text class="an-ph" x="11" y="16">' + esc(n.phase.toUpperCase()) + '</text>'
        + '<text class="an-t" x="11" y="31">' + esc(n.title.length > 24 ? n.title.slice(0, 23) + '…' : n.title) + '</text>'
        + '<text class="an-sub" x="11" y="43">' + esc(proof ? ('→ ' + (proof.length > 26 ? proof.slice(0, 25) + '…' : proof)) : '') + '</text>'
        + '</g>';
    }).join('');
    var bandSvg = LY.bands.map(function (b) {
      var prog = study().laneProgress(b.key);
      var label = '<g class="atlas-band lane-' + b.key + (b.collapsed ? ' collapsed' : '') + '" data-band="' + U.attr(b.key) + '">'
        + '<rect class="ab-bg" x="4" y="' + b.top + '" width="' + (LY.W - 8) + '" height="' + b.h + '" rx="10"/>'
        + '<text class="ab-chev" x="14" y="' + (b.top + 19) + '">' + (b.collapsed ? '▸' : '▾') + '</text>'
        + '<text class="atlas-lanelabel lane-' + b.key + '" x="30" y="' + (b.top + 19) + '">' + esc(b.short) + '</text>'
        + '<text class="ab-count" x="' + (LY.W - 20) + '" y="' + (b.top + 19) + '">' + prog.studied + '/' + b.count + '</text>';
      if (b.collapsed) {
        var dots = b.nodes.map(function (n, i) { var mk = (study().mastery()[n.id] || {}); var cls = mk.correct ? ' done' : (mk.studied ? ' seen' : ''); return '<circle class="ab-dot' + cls + '" cx="' + (118 + i * 11) + '" cy="' + (b.top + 15) + '" r="3.2"/>'; }).join('');
        label += dots;
      }
      return label + '</g>';
    }).join('');

    return '<section class="study-route study-atlas-route">'
      + '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Study</b> · Atlas <span class="study-map-path-note">drag to pan · scroll to zoom · click a step to add it to a path · click a lane title to fold it</span></div>'
      + '<div class="atlas-ctrl">'
      + '<input type="search" class="atlas-search" id="atlas-search" placeholder="Search steps…" value="' + U.attr(_atlasQuery) + '" autocomplete="off" spellcheck="false">'
      + '<button type="button" class="study-rp-btn" data-az="out">-</button>'
      + '<button type="button" class="study-rp-btn" data-az="reset">fit</button>'
      + '<button type="button" class="study-rp-btn" data-az="in">+</button></div></div>'
      + scenariosBar()
      + '<div class="atlas-stage" id="atlas-stage">'
      + '<svg class="atlas-svg" id="atlas-svg"><g class="atlas-view" id="atlas-view" data-w="' + LY.W + '" data-h="' + LY.H + '">'
      + '<g class="atlas-bands">' + bandSvg + '</g>'
      + '<g class="atlas-edges">' + laneEdgeSvg + crossEdgeSvg + '</g>'
      + '<path class="atlas-pathline" id="atlas-pathline" d=""/>'
      + '<g class="atlas-nodes">' + nodeSvg + '</g></g></svg>'
      + '<div class="atlas-minimap" id="atlas-minimap"><svg id="atlas-mini-svg" class="atlas-mini-svg"></svg><div class="atlas-mini-vp" id="atlas-mini-vp"></div></div>'
      + '<div class="atlas-empty" id="atlas-empty" hidden>No step matches "<span id="atlas-empty-q"></span>".</div>'
      + '<div class="atlas-hovercard" id="atlas-hovercard" hidden></div>'
      + '</div>'
      + '<div class="atlas-tray" id="atlas-tray"></div>'
      + '</section>';
  }

  function coachControl() {
    var p = study().coachPref();
    var lab = p === 'always' ? 'Why: always on' : (p === 'off' ? 'Why: off' : 'Why: auto');
    return '<button type="button" class="study-coach-ctl" data-coach-cycle title="How much reasoning to show. Auto fades it once you have the move down.">' + lab + '</button>';
  }
  function nodeView() {
    var right = _gear === 'practice' ? practicePanel() : cellPanel();
    var bench = (_gear !== 'practice' && hasFieldGuide(_sel)) ? howColumn() : '';
    var colsCls = 'study-cols' + (bench ? ' has-bench' : '');
    return '<section class="study-route' + (bench ? ' has-bench' : '') + '">'
      + '<div class="study-top">'
      + '<button type="button" class="study-back" data-back>← ' + (_pathMode ? 'Your path' : (_from === 'atlas' ? 'The Atlas' : (_from === 'ports' ? 'Open ports' : 'All paths'))) + '</button>'
      + '<div class="study-crumb"><b>Study</b> · ' + esc(laneMeta(laneKeyOf(_sel)).name) + ' · <span class="study-here">' + esc((study().cellFor(_sel) || {}).title || _sel) + '</span></div>'
      + '<div class="study-gears">'
      + coachControl()
      + '<button type="button" class="study-gear' + (_gear === 'watch' ? ' on' : '') + '" data-gear="watch">▶ Watch</button>'
      + '<button type="button" class="study-gear' + (_gear === 'practice' ? ' on' : '') + '" data-gear="practice">✎ Your turn</button>'
      + '</div></div>'
      + '<div class="' + colsCls + '">' + graphPanel() + right + bench + '</div>'
      + '<div class="study-factpop" id="study-factpop" hidden></div>'
      + '</section>';
  }

  // ---- COLD BOX: a guided, scaffolded playthrough of a scenario -------------------------------
  function simTerm(rp) {
    if (!rp || !rp.steps || !rp.steps.length) return '<div class="study-term sim-term"><span class="study-ln">No captured output for this step yet.</span></div>';
    var sig = rp.signal || '';
    var body = rp.steps.map(function (s) {
      var prompt = s.prompt || detectPromptFor(s.command, '', s.where);
      var cmd = '<span class="study-ln sim-cmd">' + esc(prompt + ' ' + (s.command || '')) + '</span>';
      var out = (s.outputLines || []).map(function (ln) {
        var hot = sig && ln.indexOf(sig) >= 0;
        return '<span class="study-ln' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</span>';
      }).join('');
      return cmd + out;
    }).join('');
    return '<div class="study-term sim-term">' + body + '</div>';
  }
  function simPicker() {
    var scs = study().scenarios(), mk = study().mastery();
    var h = '<section class="study-route study-sim">';
    h += '<div class="study-top"><button type="button" class="study-back" data-back-map>← Paths</button>'
      + '<div class="study-crumb"><b>Cold box</b> · pick a scenario</div></div>';
    h += '<div class="study-hero"><h1 class="study-hero-h">Run a cold box</h1>'
      + '<p class="study-hero-p">Start from an IP and nothing else. Read each result, decide the next move, and watch the box fall one step at a time. This is the exam, rehearsed.</p></div>';
    h += '<div class="sim-cards">' + scs.map(function (s) {
      var done = s.steps.filter(function (id) { return (mk[id] || {}).correct; }).length;
      return '<button type="button" class="sim-card" data-sim-start="' + U.attr(s.key) + '">'
        + '<div class="sim-card-n">' + esc(s.name) + '</div>'
        + '<div class="sim-card-d">' + esc(s.desc) + '</div>'
        + '<div class="sim-card-f"><span class="sim-card-steps">' + s.count + ' steps</span>'
        + '<span class="sim-card-go">' + (done ? done + ' / ' + s.count + ' mastered · run again →' : 'Start cold →') + '</span></div></button>';
    }).join('') + '</div>';
    return h + '</section>';
  }
  function simView() {
    if (!_simKey) return simPicker();
    var sim = study().simFor(_simKey);
    if (!sim || !sim.steps.length) { _simKey = null; return simPicker(); }
    var i = Math.max(0, Math.min(_simStep, sim.steps.length - 1));
    var step = sim.steps[i], st = _simState[i] || null, rp = step.replay;
    var h = '<section class="study-route study-sim">';
    h += '<div class="study-top"><button type="button" class="study-back" data-sim-exit>← Scenarios</button>'
      + '<div class="study-crumb"><b>Cold box</b> · ' + esc(sim.name) + '</div>'
      + '<div class="sim-prog">' + sim.steps.map(function (s, k) {
        return '<span class="sim-dot' + (k < i ? ' done' : (k === i ? ' here' : '')) + '"></span>';
      }).join('') + '<span class="sim-prog-l">Step ' + (i + 1) + ' of ' + sim.count + '</span></div></div>';
    h += '<div class="sim-stage">';
    h += '<div class="sim-intro">' + esc(step.intro) + '</div>';
    h += '<div class="sim-run"><span class="sim-run-l">You run</span> '
      + '<button type="button" class="sim-movelink" data-goto="' + U.attr(step.id) + '">' + esc(step.title) + '</button>'
      + '<span class="sim-run-hint">study this move in depth →</span></div>';
    h += simTerm(rp);
    var showTell = study().showWhy(step.id) || (st && !st.correct);
    if (showTell && rp && (rp.teach || rp.signal)) {
      h += '<div class="sim-tell"><span class="sim-tell-l">The tell</span><div>' + esc(rp.teach || rp.signal) + '</div></div>';
    }
    if (step.last) {
      h += '<div class="sim-done"><div class="sim-done-h">✓ You reached the end of this path.</div>'
        + '<p>From a cold box to ' + esc((step.title || '').toLowerCase()) + '. Run it again to lock it in, or open any move to study it in depth.</p>'
        + '<div class="sim-done-ctl"><button type="button" class="study-rp-btn primary" data-sim-restart>↺ Run it again</button>'
        + '<button type="button" class="study-rp-btn" data-sim-exit>Pick another scenario</button></div></div>';
    } else if (step.choices) {
      h += '<div class="sim-q">' + esc(step.prompt) + '</div><div class="study-choices sim-choices">';
      var letters = 'ABCDEFGH';
      step.choices.forEach(function (c, k) {
        var picked = st && st.pickedId === c.id, cls = '';
        if (picked) cls = c.correct ? ' ok' : ' bad';
        else if (st && st.correct) cls = ' dimmed';
        h += '<button type="button" class="study-choice sim-choice' + cls + '" data-sim-pick="' + U.attr(c.id) + '" data-correct="' + (c.correct ? '1' : '0') + '">'
          + '<span class="study-tag">' + letters[k] + '</span><span class="study-ct">' + esc(c.title) + '</span></button>';
      });
      h += '</div>';
      if (st && st.correct) {
        h += '<div class="study-verdict show ok"><div class="study-vh">✓ That is the move.</div><div>Good read. On to the next step.</div></div>';
        h += '<div class="sim-adv"><button type="button" class="study-rp-btn primary" data-sim-next>Next step →</button></div>';
      } else if (st) {
        var pc = null; step.choices.forEach(function (c) { if (c.id === st.pickedId) pc = c; });
        h += '<div class="study-verdict show bad"><div class="study-vh">✗ Not here.</div><div>' + esc(pc ? pc.why : '') + ' Read the output again and pick what it sets up.</div></div>';
      }
    }
    h += '</div><div class="study-factpop" id="study-factpop" hidden></div></section>';
    return h;
  }

  var TOPIC_TO_LANE = {
    'recon': 'recon',
    'web': 'web', 'web-exploitation': 'web',
    'checks': 'checks',
    'ad': 'ad', 'active-directory': 'ad',
    'creds': 'creds', 'cracking': 'creds', 'password-cracking': 'creds',
    'linux': 'linux', 'linux-privesc': 'linux',
    'windows': 'windows', 'windows-privesc': 'windows',
    'database': 'database', 'db': 'database',
    'shells': 'shells',
    'pivot': 'pivot', 'pivoting': 'pivot',
    'proof': 'proof'
  };
  var _lastAppliedArg = '';
  var _leftStudy = false;
  function render(ctx) {
    var arg0 = (ctx && ctx.args && ctx.args[0]) || '';
    var arg1 = (ctx && ctx.args && ctx.args[1]) || '';
    var fullArg = arg1 ? (arg0 + '/' + arg1) : arg0;
    // _leftStudy: re-entering the route (even with the SAME #/study/<id> hash as last time) must re-apply the
    // deep link, otherwise an in-app drill (e.g. a Dedicated Goal Module link) leaves a stale node showing.
    var reEntered = _leftStudy; _leftStudy = false;
    var topicSlug = (arg0 === 'topic' && arg1) ? arg1 : (TOPIC_TO_LANE[arg0] && !study().cellFor(arg0) ? arg0 : '');
    if (topicSlug && TOPIC_TO_LANE[topicSlug] && (fullArg !== _lastAppliedArg || reEntered)) {
      var targetLane = TOPIC_TO_LANE[topicSlug];
      var ls = study().lanes();
      for (var i = 0; i < ls.length; i++) {
        if (ls[i].key === targetLane && ls[i].firstId) {
          _lastAppliedArg = fullArg;
          _sel = ls[i].firstId;
          _view = 'node';
          _pathMode = false;
          _path = [];
          break;
        }
      }
    } else if (arg0 && (arg0 !== _lastAppliedArg || reEntered) && study().cellFor(arg0)) {
      _lastAppliedArg = arg0; _sel = arg0; _view = 'node'; _pathMode = false; _path = [];
    } else if (!arg0 && _lastAppliedArg) {
      _lastAppliedArg = ''; _view = 'map';
    }
    return _view === 'map' ? mapView() : (_view === 'atlas' ? atlasView() : (_view === 'ports' ? portsView() : (_view === 'sim' ? simView() : nodeView())));
  }

  // ---- replay controller ----------------------------------------------------------------------
  function cancelReplay() { if (_rpToken) { _rpToken.cancelled = true; _rpToken = null; } if (_rpIo) { _rpIo.disconnect(); _rpIo = null; } }
  if (typeof window !== 'undefined' && window.addEventListener) {
    window.addEventListener('hashchange', function () {
      if (OBOL.router && OBOL.router.current && OBOL.router.current().name !== 'study') {
        cancelReplay();
      }
    });
  }
  function reducedMotion() {
    try {
      var m = (typeof OBOL !== 'undefined' && OBOL.store) ? (OBOL.store.pref('motion') || localStorage.getItem('obol.motion')) : localStorage.getItem('obol.motion');
      if (m === 'reduced' || m === 'off') return true;
    } catch (e) {}
    try { return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch (e) { return false; }
  }
  function stepHeader(where, stepTitle, stepIdx, stepTotal) {
    var cleanTitle = String(stepTitle || '').replace(/^Step\s+\d+\s*(?:\([^)]+\))?\s*:\s*/i, '');
    var extra = cleanTitle ? (' · <span class="rp-step-title">Step ' + ((stepIdx || 0) + 1) + '/' + (stepTotal || 1) + ': ' + esc(cleanTitle) + '</span>') : '';
    return where === 'host'
      ? '<div class="rp-step-h rp-host"><span class="rp-where-glyph">' + OBOL.ic('host') + '</span> on the target, the compromised host' + extra + '</div>'
      : '<div class="rp-step-h rp-local"><span class="rp-where-glyph">' + OBOL.ic('box') + '</span> on your box (Kali)' + extra + '</div>';
  }
  function promptFor(where, cmdStr, toolName) {
    return detectPromptFor(cmdStr || '', toolName || '', where);
  }
  function currentReplayForPlayer(player) {
    var moveId = player.getAttribute('data-move') || _sel;
    var cmdIdxAttr = player.getAttribute('data-cmd-idx');
    var cmdIdx = (cmdIdxAttr != null && cmdIdxAttr !== '')
      ? (/^\d+$/.test(cmdIdxAttr) ? +cmdIdxAttr : cmdIdxAttr)
      : _wbCmdIdx[moveId];
    var cell = study().cellFor(moveId);
    var activeCmd = null;
    if (cell && cell.commands && cmdIdx != null) {
      for (var i = 0; i < cell.commands.length; i++) {
        if (String(cell.commands[i].cmdIdx) === String(cmdIdx) || i === cmdIdx) { activeCmd = cell.commands[i]; break; }
      }
    }
    return study().replayFor(moveId, cmdIdx, activeCmd ? activeCmd.rawRun : undefined);
  }
  function runReplay(mount, instant) {
    cancelReplay();
    var player = mount.querySelector('.study-replay'); if (!player) return;
    var rp = currentReplayForPlayer(player); if (!rp) return;
    _rpSeen[rp.id] = true;
    var term = mount.querySelector('#rp-term'), facts = mount.querySelector('#rp-facts'), prog = mount.querySelector('.study-rp-prog');
    if (!term) return;
    var token = { cancelled: false }; _rpToken = token;
    term.innerHTML = ''; if (facts) facts.innerHTML = '';
    var seq = (_pathMode && _path.length) ? _path.slice() : study().lane(laneKeyOf(rp.id)).map(function (x) { return x.id; });
    var idx = seq.indexOf(rp.id);
    if (prog) prog.textContent = 'move ' + (idx + 1) + ' / ' + seq.length + (rp.multi ? ' · ' + rp.steps.length + ' steps' : '');
    var steps = rp.steps && rp.steps.length ? rp.steps : [{ where: 'local', prompt: rp.prompt, command: rp.command, outputLines: rp.outputLines, sig: rp.signal, teach: rp.teach }];
    var multi = steps.length > 1;
    function popFacts(delay) {
      study().markStudied(rp.id, 'studied');
      if (facts && (rp.proves || []).length) setTimeout(function () {
        if (token.cancelled || !facts) return;
        if (OBOL.router && OBOL.router.current && OBOL.router.current().name !== 'study') { cancelReplay(); return; }
        var lab = document.createElement('span'); lab.className = 'rp-facts-l'; lab.textContent = 'New facts in hand'; facts.appendChild(lab);
      }, delay);
      (rp.proves || []).forEach(function (f, k) {
        setTimeout(function () {
          if (token.cancelled || !facts) return;
          if (OBOL.router && OBOL.router.current && OBOL.router.current().name !== 'study') { cancelReplay(); return; }
          var c = document.createElement('span'); c.className = 'study-chip proof rp-pop'; c.textContent = '+ ' + titleCase(human(f)); facts.appendChild(c);
        }, delay + 120 + k * 260);
      });
      var nextId = rp.next;
      if (_pathMode && _path.length) { var pi = _path.indexOf(rp.id); nextId = (pi >= 0 && pi < _path.length - 1) ? _path[pi + 1] : null; }
      if (_autolane && nextId) setTimeout(function () {
        if (token.cancelled) return;
        if (OBOL.router && OBOL.router.current && OBOL.router.current().name !== 'study') { cancelReplay(); return; }
        _sel = nextId; _autoplay = true; OBOL.router.render();
      }, delay + (rp.proves.length * 260) + 1400);
    }
    function stepLineHtml(ln, stepSig, stepTeach) {
      var sig = stepSig || rp.signal || '';
      var teach = stepTeach || rp.teach || '';
      var hot = (sig && ln.indexOf(sig) >= 0) || (rp.signal && ln.indexOf(rp.signal) >= 0);
      return '<div class="rp-line rp-out' + (hot ? ' hot' : '') + '">' + esc(ln || ' ') + '</div>'
        + (hot && teach ? '<div class="rp-cap">← ' + codeify(teach) + '</div>' : '');
    }
    if (instant) {
      var html = steps.map(function (s, sIdx) {
        var head = multi ? stepHeader(s.where, s.title, sIdx, steps.length) : '';
        var pr = s.prompt || promptFor(s.where, s.command, s.tool || rp.tool);
        var hostCls = isHostPrompt(pr, s.where) ? ' host' : '';
        var cmdLine = '<div class="rp-line rp-cmd"><span class="rp-prompt' + hostCls + '">' + esc(pr) + '</span> ' + esc(s.command) + '</div>';
        return head + cmdLine + (s.outputLines || []).map(function (ln) { return stepLineHtml(ln, s.sig, s.teach); }).join('');
      }).join('');
      term.innerHTML = html; term.scrollTop = 0; popFacts(200); return;
    }
    var si = 0;
    (function nextStep() {
      if (token.cancelled) return;
      if (si >= steps.length) { popFacts(300); return; }
      var s = steps[si];
      if (multi) { var h = document.createElement('div'); h.innerHTML = stepHeader(s.where, s.title, si, steps.length); term.appendChild(h.firstChild); term.scrollTop = term.scrollHeight; }
      var pr = s.prompt || promptFor(s.where, s.command, s.tool || rp.tool);
      var hostCls = isHostPrompt(pr, s.where) ? ' host' : '';
      var promptLine = document.createElement('div'); promptLine.className = 'rp-line rp-cmd';
      promptLine.innerHTML = '<span class="rp-prompt' + hostCls + '">' + esc(pr) + '</span> <span class="rp-typed"></span><span class="rp-cursor">▋</span>';
      term.appendChild(promptLine); term.scrollTop = term.scrollHeight;
      var typed = promptLine.querySelector('.rp-typed'), cmd = s.command || '', ci = 0;
      (function typeCmd() {
        if (token.cancelled) return;
        if (ci <= cmd.length) { typed.textContent = cmd.slice(0, ci); ci++; setTimeout(typeCmd, 14); return; }
        var cur = promptLine.querySelector('.rp-cursor'); if (cur) cur.remove();
        var lines = s.outputLines || [];
        if (!lines.length) {
          if (si === steps.length - 1 && !rp.hasOutput) { var ns = document.createElement('div'); ns.className = 'rp-line rp-nosample-line'; ns.textContent = '· sample output for this step is still being captured, but you can see the command above and what it proves below ·'; term.appendChild(ns); }
          si++; setTimeout(nextStep, 500); return;
        }
        var i = 0;
        var stepSig = s.sig || rp.signal || '';
        var stepTeach = s.teach || rp.teach || '';
        (function nextLine() {
          if (token.cancelled) return;
          if (i >= lines.length) { si++; setTimeout(nextStep, multi ? 650 : 300); return; }
          var ln = lines[i], el = document.createElement('div');
          var hot = (stepSig && ln.indexOf(stepSig) >= 0) || (rp.signal && ln.indexOf(rp.signal) >= 0);
          el.className = 'rp-line rp-out' + (hot ? ' hot' : ''); el.textContent = ln || ' ';
          term.appendChild(el); term.scrollTop = term.scrollHeight;
          if (hot && stepTeach) { var cap = document.createElement('div'); cap.className = 'rp-cap'; cap.innerHTML = '← ' + codeify(stepTeach); term.appendChild(cap); term.scrollTop = term.scrollHeight; }
          i++; setTimeout(nextLine, hot ? 1100 : 220);
        })();
      })();
    })();
  }

  // ---- Atlas interaction ----------------------------------------------------------------------
  function atlasApply(view) { view.setAttribute('transform', 'translate(' + _az.tx + ',' + _az.ty + ') scale(' + _az.k + ')'); }
  function atlasLOD(stage) { var k = _az.k; stage.setAttribute('data-lod', k < 0.62 ? 'far' : (k < 1.05 ? 'mid' : 'near')); }
  function atlasPathD(mount) {
    if (_atlasPath.length < 2) return '';
    var pts = _atlasPath.map(function (id) { var g = mount.querySelector('.atlas-node[data-anode="' + id + '"]'); return g ? (g.getAttribute('data-cx') + ',' + g.getAttribute('data-cy')) : null; }).filter(Boolean);
    return pts.length < 2 ? '' : 'M' + pts.join(' L');
  }
  function scenName(key) { var s = study().scenario(key); return s ? s.name : ''; }
  function pathWarnings() {
    if (_atlasPath.length < 2) return '';
    var v = study().validatePath(_atlasPath); if (v.ok) return '';
    var lines = v.issues.map(function (iss) {
      var c = study().cellFor(iss.id), title = c ? c.title : iss.id;
      if (iss.kind === 'unknown') return '<b>Step ' + (iss.idx + 1) + '</b> (' + esc(title) + ') isn\'t in this build.';
      var missing = (iss.missing || []).map(function (mk) { return /^one of:/.test(mk) ? ('one of: ' + mk.replace(/^one of:\s*/, '').split(' / ').map(human).join(' or ')) : human(mk); });
      return '<b>Step ' + (iss.idx + 1) + '</b> (' + esc(title) + ') needs ' + missing.map(function (x) { return '<i>' + esc(x) + '</i>'; }).join(', ') + '. Nothing earlier in this path gets you that.';
    });
    return '<div class="atlas-tray-warn"><span class="atw-i">' + OBOL.ic('lock') + '</span><div><b>Locked doors on this path:</b> '
      + lines.join(' ') + ' Add the step that opens each, or start where you already have the keys.</div></div>';
  }
  function atlasTray(mount) {
    var tray = mount.querySelector('#atlas-tray'); if (!tray) return;
    if (!_atlasPath.length) { tray.innerHTML = '<span class="atlas-tray-hint">Pick a <b>common scenario</b> above, or click steps in order to draw your own path, then study it as one guided run.</span>'; return; }
    var lead = _scenario ? ('<span class="atlas-tray-name">' + esc(scenName(_scenario)) + '</span>') : '<span class="atlas-tray-name custom">Custom path</span>';
    var chips = _atlasPath.map(function (id, i) { var c = study().cellFor(id); return '<span class="atlas-trchip lane-' + laneKeyOf(id) + '">' + (i + 1) + '. ' + esc(c ? c.title : id) + '</span>'; }).join('<span class="atlas-trarr">→</span>');
    tray.innerHTML = '<div class="atlas-tray-row">' + lead + '<div class="atlas-tray-path">' + chips + '</div>'
      + '<div class="atlas-tray-act"><button type="button" class="study-rp-btn" data-atlas="clear">clear</button>'
      + '<button type="button" class="study-rp-btn primary" data-atlas="study">▶ Study this path (' + _atlasPath.length + ') →</button></div></div>'
      + pathWarnings();
  }
  function syncScen(mount) { Array.prototype.forEach.call(mount.querySelectorAll('.atlas-scen'), function (c) { c.classList.toggle('on', c.getAttribute('data-scen') === _scenario); }); }
  function atlasSelection(mount) {
    Array.prototype.forEach.call(mount.querySelectorAll('.atlas-node'), function (g) {
      var i = _atlasPath.indexOf(g.getAttribute('data-anode'));
      g.classList.toggle('sel', i >= 0);
      var b = g.querySelector('.an-badge'); if (b) b.textContent = i >= 0 ? (i + 1) : '';
    });
    var pl = mount.querySelector('#atlas-pathline'); if (pl) pl.setAttribute('d', atlasPathD(mount));
    syncScen(mount);
    atlasTray(mount);
  }
  function applyQuery(mount) {
    var q = _atlasQuery.trim().toLowerCase(), first = null, nMatch = 0;
    Array.prototype.forEach.call(mount.querySelectorAll('.atlas-node'), function (g) {
      var id = g.getAttribute('data-anode'), c = study().cellFor(id);
      var hay = (id + ' ' + (c ? c.title : '') + ' ' + (c && c.proves ? c.proves.map(human).join(' ') : '')).toLowerCase();
      var hit = !q || hay.indexOf(q) >= 0;
      g.classList.toggle('dim', !!q && !hit);
      g.classList.toggle('qmatch', !!q && hit);
      if (q && hit) { nMatch++; if (!first) first = id; }
    });
    var empty = mount.querySelector('#atlas-empty'); if (empty) { empty.hidden = !(q && nMatch === 0); var eq = mount.querySelector('#atlas-empty-q'); if (eq) eq.textContent = _atlasQuery; }
    return q ? first : null;
  }
  function wireAtlas(mount) {
    var stage = mount.querySelector('#atlas-stage'), view = mount.querySelector('#atlas-view');
    if (!stage || !view) return;
    var W = +view.getAttribute('data-w'), H = +view.getAttribute('data-h');
    var mini = mount.querySelector('#atlas-minimap'), miniSvg = mount.querySelector('#atlas-mini-svg'), miniVp = mount.querySelector('#atlas-mini-vp');
    var MINIW = 164, miniK = Math.min(MINIW / W, 120 / H), miniH = Math.round(H * miniK);
    if (miniSvg) {
      miniSvg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); miniSvg.setAttribute('width', Math.round(W * miniK)); miniSvg.setAttribute('height', miniH);
      miniSvg.innerHTML = atlasLayout().bands.map(function (b) { return '<rect class="amm-band lane-' + b.key + '" x="4" y="' + b.top + '" width="' + (W - 8) + '" height="' + b.h + '" rx="8"/>'; }).join('');
      if (mini) mini.style.width = Math.round(W * miniK) + 'px';
    }
    function updateMini() {
      if (!miniVp) return; var r = stage.getBoundingClientRect();
      var vx = (-_az.tx / _az.k) * miniK, vy = (-_az.ty / _az.k) * miniK, vw = (r.width / _az.k) * miniK, vh = (r.height / _az.k) * miniK;
      miniVp.style.left = Math.max(0, vx) + 'px'; miniVp.style.top = Math.max(0, vy) + 'px';
      miniVp.style.width = Math.min(vw, Math.round(W * miniK)) + 'px'; miniVp.style.height = Math.min(vh, miniH) + 'px';
    }
    function apply() { atlasApply(view); atlasLOD(stage); updateMini(); }
    function fit() { var r = stage.getBoundingClientRect(); var k = Math.min((r.width - 24) / W, (r.height - 24) / H, 1.1); k = Math.max(k, 0.26); _az = { k: k, tx: (r.width - W * k) / 2, ty: 12 }; apply(); }
    function zoomAround(mx, my, f) { var nk = Math.max(0.26, Math.min(2.4, _az.k * f)), ratio = nk / _az.k; _az.tx = mx - (mx - _az.tx) * ratio; _az.ty = my - (my - _az.ty) * ratio; _az.k = nk; apply(); }
    function centerOn(id) { var g = mount.querySelector('.atlas-node[data-anode="' + id + '"]'); if (!g) return; var r = stage.getBoundingClientRect(); var cx = +g.getAttribute('data-cx'), cy = +g.getAttribute('data-cy'); _az.tx = r.width / 2 - cx * _az.k; _az.ty = r.height / 2 - cy * _az.k; apply(); }
    if (!_az) fit(); else apply();
    atlasSelection(mount);
    if (_atlasQuery) applyQuery(mount);
    var down = null, moved = false;
    stage.addEventListener('pointerdown', function (e) { if (e.target.closest && (e.target.closest('.atlas-band') || e.target.closest('.atlas-minimap'))) { down = null; return; } var g = e.target.closest && e.target.closest('.atlas-node'); down = { x: e.clientX, y: e.clientY, tx: _az.tx, ty: _az.ty, node: g }; moved = false; try { stage.setPointerCapture(e.pointerId); } catch (x) {} });
    stage.addEventListener('pointermove', function (e) { if (!down) return; var dx = e.clientX - down.x, dy = e.clientY - down.y; if (Math.abs(dx) + Math.abs(dy) > 4) moved = true; _az.tx = down.tx + dx; _az.ty = down.ty + dy; apply(); });
    stage.addEventListener('pointerup', function () { var wasMoved = moved, g = down && down.node; down = null; if (wasMoved || !g) return; var id = g.getAttribute('data-anode'), i = _atlasPath.indexOf(id); if (i >= 0) _atlasPath.splice(i, 1); else _atlasPath.push(id); _scenario = null; atlasSelection(mount); });
    stage.addEventListener('wheel', function (e) { e.preventDefault(); var r = stage.getBoundingClientRect(); zoomAround(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 0.89); }, { passive: false });
    var hover = mount.querySelector('#atlas-hovercard');
    function showHover(g, e) {
      if (!hover) return;
      var id = g.getAttribute('data-anode'), c = study().cellFor(id); if (!c) { hover.hidden = true; return; }
      var desc = c.whatItIs || '';
      hover.innerHTML = '<div class="ahc-ph lane-' + laneKeyOf(id) + '">' + esc((c.phase || '').toUpperCase()) + '</div>'
        + '<div class="ahc-t">' + esc(c.title) + '</div>'
        + (desc ? '<div class="ahc-d">' + esc(desc.length > 240 ? desc.slice(0, 237) + '…' : desc) + '</div>' : '')
        + (c.proves && c.proves.length ? '<div class="ahc-p"><span class="ahc-arr">→</span> ' + esc(c.proves.map(human).join(', ')) + '</div>' : '');
      hover.hidden = false;
      var r = stage.getBoundingClientRect(), cw = hover.offsetWidth || 300, ch = hover.offsetHeight || 120;
      var x = e.clientX - r.left + 16, y = e.clientY - r.top + 16;
      if (x + cw > r.width - 6) x = e.clientX - r.left - cw - 16;
      if (y + ch > r.height - 6) y = r.height - ch - 8;
      hover.style.left = Math.max(6, x) + 'px'; hover.style.top = Math.max(6, y) + 'px';
    }
    stage.addEventListener('pointermove', function (e) {
      if (down) { if (hover) hover.hidden = true; return; }
      var g = e.target.closest && e.target.closest('.atlas-node');
      if (g) showHover(g, e); else if (hover && !hover.hidden) hover.hidden = true;
    });
    stage.addEventListener('pointerleave', function () { if (hover) hover.hidden = true; });
    if (mini) mini.addEventListener('click', function (e) { var r = mini.getBoundingClientRect(), sr = stage.getBoundingClientRect(); var cx = (e.clientX - r.left) / miniK, cy = (e.clientY - r.top) / miniK; _az.tx = sr.width / 2 - cx * _az.k; _az.ty = sr.height / 2 - cy * _az.k; apply(); });
    U.on(mount, 'click', '[data-az]', function (e, t) { var a = t.getAttribute('data-az'); if (a === 'in' || a === 'out') { var r = stage.getBoundingClientRect(); zoomAround(r.width / 2, r.height / 2, a === 'in' ? 1.2 : 0.83); } else fit(); });
    U.on(mount, 'click', '[data-atlas="clear"]', function () { _atlasPath = []; _scenario = null; atlasSelection(mount); });
    U.on(mount, 'click', '[data-atlas="study"]', function () { if (!_atlasPath.length) return; _path = _atlasPath.slice(); _pathName = _scenario ? scenName(_scenario) : 'Your custom path'; _pathMode = true; _from = 'atlas'; _sel = _path[0]; _view = 'node'; OBOL.router.render(); });
    U.on(mount, 'click', '[data-band]', function (e, t) { var k = t.getAttribute('data-band'); _collapsed[k] = !_collapsed[k]; OBOL.router.render(); });
    U.on(mount, 'input', '#atlas-search', function (e, t) { _atlasQuery = t.value || ''; var first = applyQuery(mount); if (first) centerOn(first); });
    U.on(mount, 'click', '[data-scen]', function (e, t) {
      var key = t.getAttribute('data-scen');
      if (key === _scenario) { _scenario = null; _atlasPath = []; }
      else { var s = study().scenario(key); if (s) { _scenario = key; _atlasPath = s.steps.slice(); } }
      atlasSelection(mount);
    });
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    cancelReplay(); cancelBench();
    wireStudyClicks(mount);
    if (_view === 'node') {
      var railEl = mount.querySelector('.study-graph');
      if (railEl) {
        var wantTop = _railScroll; _railScroll = null;
        var sawNode = _railNodeSeen; _railNodeSeen = _sel;
        var applyRail = function () {
          if (!railEl.isConnected) return;
          if (wantTop != null) { railEl.scrollTop = wantTop; }
          else if (_sel !== sawNode) { var actEl = railEl.querySelector('.study-gnode.active'); if (actEl && actEl.scrollIntoView) { try { actEl.scrollIntoView({ block: 'nearest' }); } catch (e) { actEl.scrollIntoView(); } } }
        };
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(applyRail); else applyRail();
      }
    } else { _railNodeSeen = null; }
    if (_view === 'node' && _gear === 'watch' && _autoplay) { _autoplay = false; var rm0 = reducedMotion(); setTimeout(function () { runReplay(mount, rm0); }, rm0 ? 0 : 250); }
    else if (_view === 'node' && _gear === 'watch') {
      var rpEl = mount.querySelector('.study-replay');
      if (rpEl) {
        var selAt = _sel;
        if (_rpSeen[selAt]) { runReplay(mount, true); }
        else if (reducedMotion()) { _rpSeen[selAt] = true; runReplay(mount, true); }
        else if (typeof IntersectionObserver !== 'undefined') {
          var io = new IntersectionObserver(function (ents) {
            for (var i = 0; i < ents.length; i++) {
              if (!ents[i].isIntersecting) continue;
              io.disconnect();
              _rpIo = null;
              if (_sel !== selAt || _rpSeen[selAt]) return;
              _rpSeen[selAt] = true; runReplay(mount, false);
              return;
            }
          }, { threshold: 0.3 });
          _rpIo = io;
          io.observe(rpEl);
        } else { _rpSeen[selAt] = true; runReplay(mount, false); }
      }
    }
    if (_view === 'atlas') setTimeout(function () { wireAtlas(mount); }, 30);
    if (_view === 'ports' && _evMode === 'map') setTimeout(function () { wirePortMap(mount); }, 30);
  }

  function wirePortMap(mount) {
    var el = mount.querySelector('#port-decision-map'); if (!el) return;
    if (!(OBOL.decisionTreeView && OBOL.decisionMap && OBOL.PARSER_SIGNATURES)) {
      el.innerHTML = '<div class="dt-loading">Building the decision map…</div>';
      if (OBOL.lazy && OBOL.lazy.loadGroup) { OBOL.lazy.loadGroup('decisionmap').then(function () { if (el.isConnected && _view === 'ports' && _evMode === 'map') OBOL.router.render(); }); }
      return;
    }
    if (el.__dtMounted) return; el.__dtMounted = true;
    OBOL.decisionTreeView.mount(el, {
      onOpen: function (id) { _from = 'ports'; _sel = id; _view = 'node'; OBOL.router.render(); },
      onCards: function () { _evMode = 'cards'; try { localStorage.setItem('obol.evMode', 'cards'); } catch (e) {} OBOL.router.render(); },
    });
  }

  function wireStudyClicks(mount) {
    if (!mount || mount._studyWired || mount.__studyWired) return;
    mount._studyWired = true;
    mount.__studyWired = true;
    function onStudy(sel, fn) {
      U.on(mount, 'click', sel, function (e, t) {
        if (OBOL.router && OBOL.router.current && OBOL.router.current().name !== 'study') return;
        return fn.call(this, e, t);
      });
    }

    onStudy('[data-welcome-dismiss]', function () { try { localStorage.setItem('obol.welcomed', '1'); } catch (e) {} OBOL.router.render(); });
    onStudy('[data-welcome-go]', function () { try { localStorage.setItem('obol.welcomed', '1'); } catch (e) {} OBOL.router.go('home'); });
    onStudy('[data-recap-toggle]', function () { setRecapOpen(!recapOpen()); OBOL.router.render(); });
    onStudy('[data-recap-path]', function (e, t) { _recapPath[_sel] = t.getAttribute('data-recap-path'); OBOL.router.render(); });

    // Operator Field Guide tab switch ('playbook' | 'signal' | 'blockers')
    onStudy('[data-fg-tab]', function (e, t) {
      var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null;
      _fgTab[_sel] = t.getAttribute('data-fg-tab') || 'playbook';
      _rpSeen[_sel] = true;
      OBOL.router.render();
    });

    // Field-notes bench: pick a technique (plays its demo), or replay the current one
    onStudy('[data-bench]', function (e, t) {
      var i = +t.getAttribute('data-bench'), h = study().howTo(_sel); if (!h) return;
      _benchSel[_sel] = i;
      Array.prototype.forEach.call(mount.querySelectorAll('.bench-item'), function (b) { b.classList.toggle('on', +b.getAttribute('data-bench') === i); });
      var main = mount.querySelector('#bench-main'); if (main) { main.innerHTML = benchMain(h.items, i); playBenchTerm(mount, h.items[i].demo); }
    });
    onStudy('[data-bench-play], [data-bench-replay]', function () {
      var h = study().howTo(_sel); if (!h) return; var i = _benchSel[_sel] || 0;
      playBenchTerm(mount, (h.items[i] || {}).demo);
    });

    // Workbench stage filter (for Multi-Stage Tool Hubs & Scenario Umbrellas)
    onStudy('[data-wb-stage]', function (e, t) {
      var st = t.getAttribute('data-wb-stage') || 'all';
      var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null;
      _wbStage[_sel] = st;
      var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
      if (cell && cell.commands) {
        var stageCmds = st === 'all' ? cell.commands : cell.commands.filter(function (c) { return c.stage === st; });
        if (stageCmds.length && stageCmds[0].cmdIdx != null) {
          _wbCmdIdx[_sel] = stageCmds[0].cmdIdx;
        }
      }
      _rpSeen[_sel] = true;
      OBOL.router.render();
    });

    // Workbench multi-step pipeline flag inspector selection
    onStudy('[data-wb-step]', function (e, t) {
      if (e.target && e.target.closest && e.target.closest('[data-wb-copy]')) return;
      var stepIdx = +t.getAttribute('data-wb-step');
      if (isNaN(stepIdx) || stepIdx < 0) return;
      var key = t.getAttribute('data-wb-step-key') || (_sel + ':0');
      var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null;
      _wbStepIdx[key] = stepIdx;
      _rpSeen[_sel] = true;
      OBOL.router.render();
    });

    // Workbench command variant selection
    onStudy('[data-wb-idx]', function (e, t) {
      if (e.target && e.target.closest && e.target.closest('[data-wb-copy]')) return;
      var raw = t.getAttribute('data-wb-idx');
      if (raw == null || raw === '') return;
      var idx = /^\d+$/.test(raw) ? +raw : raw;
      var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null;
      _wbCmdIdx[_sel] = idx;
      _rpSeen[_sel] = true;
      OBOL.router.render();
    });

    // Copy command from workbench or blocker fix
    onStudy('[data-wb-copy]', function (e, t) {
      e.stopPropagation();
      var txt = t.getAttribute('data-wb-copy') || '';
      if (!txt) return;
      if (U && U.copy) U.copy(txt, t);
      else if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).catch(function () {});
        var orig = t.textContent; t.textContent = 'Copied!';
        setTimeout(function () { t.textContent = orig; }, 1200);
      }
    });

    // Send sample output to Coach sandbox
    onStudy('[data-wb-ingest]', function (e, t) {
      var player = mount.querySelector('.study-replay');
      var rp = player ? currentReplayForPlayer(player) : study().replayFor(_sel);
      if (!rp || !rp.outputLines || !rp.outputLines.length) return;
      var sampleOut = rp.outputLines.join('\n');
      var sampleCmd = rp.command || '';
      if (OBOL.ingest && OBOL.ingest.run) {
        Promise.resolve(OBOL.ingest.ensureParsers ? OBOL.ingest.ensureParsers() : true).then(function () {
          OBOL.ingest.run(sampleOut, { command: sampleCmd, actionId: _sel, source: 'study-sandbox' });
          t.textContent = '✓ Sent to Cockpit!';
          setTimeout(function () { OBOL.router.go('path'); }, 450);
        });
      } else if (OBOL.quickpaste && OBOL.quickpaste.open) {
        OBOL.quickpaste.open(sampleOut);
      }
    });

    // map/graph: open a lane/step -> node view
    onStudy('[data-open]', function (e, t) { _from = (_view === 'atlas' ? 'atlas' : (_view === 'ports' ? 'ports' : 'map')); _sel = t.getAttribute('data-open'); _view = 'node'; OBOL.router.render(); });
    onStudy('[data-back]', function () { _view = _from; OBOL.router.render(); });
    onStudy('[data-back-map]', function () { _view = 'map'; OBOL.router.render(); });
    onStudy('[data-graph]', function () { _view = 'atlas'; OBOL.router.render(); });
    onStudy('[data-ports]', function () { _view = 'ports'; OBOL.router.render(); });
    onStudy('[data-decision]', function () { _view = 'ports'; _evMode = 'map'; try { localStorage.setItem('obol.evMode', 'map'); } catch (e) {} OBOL.router.render(); });
    onStudy('[data-go-atlas]', function () { _view = 'atlas'; OBOL.router.render(); });
    onStudy('[data-go-ports]', function () { _view = 'ports'; OBOL.router.render(); });
    onStudy('[data-port-open]', function (e, t) {
      var k = t.getAttribute('data-port-open');
      _view = 'ports'; _evMode = 'cards';
      try { localStorage.setItem('obol.evMode', 'cards'); } catch (x) {}
      var o = evOpen(); o[k] = true; evSave();
      OBOL.router.render();
    });
    onStudy('[data-ev-toggle]', function (e, t) { var k = t.getAttribute('data-ev-toggle'); var o = evOpen(); o[k] = !o[k]; evSave(); OBOL.router.render(); });
    onStudy('[data-ev-all]', function (e, t) { var open = t.getAttribute('data-ev-all') === 'open'; var o = evOpen(); study().evidence().forEach(function (x) { o[x.key] = open; }); evSave(); OBOL.router.render(); });
    onStudy('[data-ev-mode]', function (e, t) { _evMode = t.getAttribute('data-ev-mode') === 'map' ? 'map' : 'cards'; try { localStorage.setItem('obol.evMode', _evMode); } catch (x) {} OBOL.router.render(); });
    onStudy('[data-sim], [data-sim-card]', function () { _view = 'sim'; _simKey = null; _simStep = 0; _simState = {}; OBOL.router.render(); });
    onStudy('[data-sim-start]', function (e, t) { _simKey = t.getAttribute('data-sim-start'); _simStep = 0; _simState = {}; _view = 'sim'; OBOL.router.render(); });
    onStudy('[data-sim-exit]', function () { _simKey = null; _simStep = 0; _simState = {}; _view = 'sim'; OBOL.router.render(); });
    onStudy('[data-sim-restart]', function () { _simStep = 0; _simState = {}; OBOL.router.render(); });
    onStudy('[data-sim-next]', function () { _simStep += 1; OBOL.router.render(); });
    onStudy('[data-sim-pick]', function (e, t) {
      var id = t.getAttribute('data-sim-pick'), correct = t.getAttribute('data-correct') === '1';
      _simState[_simStep] = { pickedId: id, correct: correct };
      if (correct) { var sim = study().simFor(_simKey); if (sim && sim.steps[_simStep]) study().markStudied(sim.steps[_simStep].id, 'correct'); }
      OBOL.router.render();
    });
    onStudy('[data-node]', function (e, t) { var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null; _sel = t.getAttribute('data-node'); OBOL.router.render(); });
    onStudy('[data-goto]', function (e, t) { var gid = t.getAttribute('data-goto'); if (!gid || !study().cellFor(gid)) return; if (_view === 'sim') _from = 'map'; _sel = gid; _view = 'node'; OBOL.router.render(); });
    onStudy('[data-gear]', function (e, t) { _gear = t.getAttribute('data-gear'); OBOL.router.render(); });

    // "Run it from" toggle: switches both the active command/terminal/switches AND reveals the matching pane
    onStudy('[data-runway]', function (e, t) {
      cancelReplay();
      var way = t.getAttribute('data-runway');
      Array.prototype.forEach.call(mount.querySelectorAll('.rw-tab'), function (b) { b.classList.toggle('on', b.getAttribute('data-runway') === way); });
      Array.prototype.forEach.call(mount.querySelectorAll('.rw-pane'), function (p) { p.hidden = p.getAttribute('data-pane') !== way; });
      var cell = study().cellFor(_sel, { profile: (OBOL.arsenal && OBOL.arsenal.profileGet && OBOL.arsenal.profileGet()) || null });
      if (cell && cell.commands) {
        var match = cell.commands.filter(function (c) { return way === 'onhost' ? c.rank === 2 : (c.rank === 0 || c.rank === 1); })[0];
        if (match && match.cmdIdx != null) {
          var g = mount.querySelector('.study-graph'); _railScroll = g ? g.scrollTop : null;
          _wbCmdIdx[_sel] = match.cmdIdx;
          if (_wbStage[_sel] && _wbStage[_sel] !== 'all' && match.stage && match.stage !== _wbStage[_sel]) {
            _wbStage[_sel] = 'all';
          }
          _rpSeen[_sel] = true;
          OBOL.router.render();
        }
      }
    });

    onStudy('[data-why-show]', function () { _whyOverride[_sel] = true; OBOL.router.render(); });
    onStudy('[data-coach-cycle]', function () { var p = study().coachPref(); study().setCoachPref(p === 'auto' ? 'always' : (p === 'always' ? 'off' : 'auto')); OBOL.router.render(); });
    onStudy('[data-fact]', function (e, t) { showFactPop(mount, t.getAttribute('data-fact')); });
    onStudy('[data-factpop-close]', function () { var p = mount.querySelector('#study-factpop'); if (p) p.hidden = true; });
    onStudy('[data-rp="play"]', function () { runReplay(mount, false); });
    onStudy('[data-rp="restart"]', function () { runReplay(mount, false); });
    onStudy('[data-rp="skip"]', function () { runReplay(mount, true); });
    onStudy('[data-rp="autolane"]', function () {
      _autolane = !_autolane;
      if (_autolane) { _autoplay = true; OBOL.router.render(); }
      else { cancelReplay(); OBOL.router.render(); }
    });
    onStudy('[data-pmode]', function (e, t) { _practiceMode = t.getAttribute('data-pmode'); OBOL.router.render(); });
    onStudy('.study-dx-choice', function (e, t) {
      var correct = t.getAttribute('data-correct') === '1';
      Array.prototype.forEach.call(mount.querySelectorAll('.study-dx-choice'), function (c) { c.classList.remove('ok', 'bad', 'dimmed'); if (c !== t) c.classList.add('dimmed'); });
      t.classList.add(correct ? 'ok' : 'bad');
      var vbox = mount.querySelector('#study-verdict'), why = mount.querySelector('#dx-why');
      if (correct) study().markStudied(_sel, 'correct');
      if (vbox) {
        vbox.className = 'study-verdict show ' + (correct ? 'ok' : 'bad');
        vbox.innerHTML = '<div class="study-vh">' + (correct ? '✓ That is the read.' : '✗ Not quite.') + '</div>'
          + '<div>' + (why ? codeify(why.getAttribute('data-why') || '') : '') + '</div>';
      }
    });
    onStudy('.study-choice', function (e, t) {
      if (t.classList.contains('study-dx-choice')) return;
      var verdict = t.getAttribute('data-verdict'), coach = t.getAttribute('data-coach') || '', missing = t.getAttribute('data-missing') || '';
      Array.prototype.forEach.call(mount.querySelectorAll('.study-choice'), function (c) { c.classList.remove('ok', 'alt', 'bad', 'dimmed'); if (c !== t) c.classList.add('dimmed'); });
      t.classList.add(verdict === 'correct' ? 'ok' : (verdict === 'alt' ? 'alt' : 'bad'));
      var vbox = mount.querySelector('#study-verdict'), slot = mount.querySelector('#study-reveal-slot');
      if (slot) slot.innerHTML = '';
      var head, body;
      if (verdict === 'correct') { head = '✓ Exactly.'; body = 'That\'s the move. Here\'s how it plays out →'; study().markStudied(_sel, 'correct'); }
      else if (verdict === 'alt') { head = '~ Also valid, but weigh it.'; body = coach ? codeify(coach) : 'A legal move here; consider the tradeoff against the cleaner path.'; }
      else { head = '✗ Not yet.'; body = (coach ? codeify(coach) : 'This needs something you don\'t have.') + (missing ? ' <span class="study-missing">Still need: ' + esc(missing) + '</span>' : ''); }
      if (vbox) {
        vbox.className = 'study-verdict show ' + (verdict === 'correct' ? 'ok' : (verdict === 'alt' ? 'alt' : 'bad'));
        vbox.innerHTML = '<div class="study-vh">' + head + '</div><div>' + body + '</div>'
          + (verdict === 'correct' ? '<button type="button" class="study-reveal-btn">See how it plays out ↓</button>' : '');
      }
    });
    onStudy('.study-reveal-btn', function (e, t) {
      var slot = mount.querySelector('#study-reveal-slot'); if (!slot) return;
      var save = _gear; _gear = 'watch'; var cellHtml = cellPanel(); _gear = save;
      slot.innerHTML = '<div class="study-reveal">' + cellHtml.replace(/^<div class="study-panel[^"]*">/, '').replace(/<\/div>$/, '') + '</div>';
      t.style.display = 'none';
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.study = { render: render, mounted: mounted, unmount: function () { cancelReplay(); cancelBench(); _leftStudy = true; } };
})(typeof globalThis !== 'undefined' ? globalThis : this);
