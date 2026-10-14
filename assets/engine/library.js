/*!
 * obol engine, library.js, the pure logic behind the Library tab.
 *
 * The Library is a READ-ONLY, deterministic catalogue of everything obol knows: every move, every
 * command, mapped onto MITRE ATT&CK. It is not the coach and it is not ranked: it is a reference you
 * explore by facet (lane, phase, port, service, tool) or by command (the hero lens) or by technique.
 *
 * Boundaries (identical to Stuck?): a function of the pack you hand it, writes nothing to OBOL.store,
 * never forks the ranker, never changes the move graph. The pack is the source of truth; this module
 * only projects it for browsing. Node-safe (no DOM), so the smoke test drives it headless.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var L = OBOL.library = OBOL.library || {};

  // ── lanes (methodology packs) ───────────────────────────────────────────────────────────────────
  // A move's lane is the ACTION_PACK it came from. packData keeps that grouping, so we derive it at
  // load (no build step, no per-action field) and label it for humans. Order is the pack load order.
  var LANE_LABEL = {
    recon_2026_09: 'Recon', ad_2026_09: 'Active Directory', web_2026_09: 'Web',
    web_exploit_checks_2026_09: 'Web Exploit Checks', database_2026_09: 'Database',
    linux_privesc_2026_09: 'Linux Privesc', windows_privesc_2026_09: 'Windows Privesc',
    credential_access_2026_09: 'Credential Access', cracking_2026_09: 'Cracking',
    shells_2026_09: 'Shells', pivoting_2026_09: 'Pivoting', obol_local_pivot_2026_09: 'Pivoting (On-Box)',
    findings_checks_2026_09: 'Findings Checks', obol_flag_hunt_2026_09: 'Flag Hunt',
  };
  // short hue key reused by the Learn/coach lane palette (lane-ad, lane-web, …); falls back to a neutral.
  var LANE_HUE = {
    recon_2026_09: 'recon', ad_2026_09: 'ad', web_2026_09: 'web', web_exploit_checks_2026_09: 'web',
    database_2026_09: 'database', linux_privesc_2026_09: 'linux', windows_privesc_2026_09: 'windows',
    credential_access_2026_09: 'creds', cracking_2026_09: 'creds', shells_2026_09: 'shells',
    pivoting_2026_09: 'pivot', obol_local_pivot_2026_09: 'pivot', findings_checks_2026_09: 'checks',
    obol_flag_hunt_2026_09: 'checks',
  };

  var _laneById = null;
  function laneMap() {
    if (_laneById) return _laneById;
    _laneById = {};
    var pd = OBOL.packData || {}, order = OBOL.ACTION_PACKS || [];
    order.forEach(function (pk) {
      var acts = (pd[pk] && pd[pk].actions) || [];
      acts.forEach(function (a) { if (a && a.id && !_laneById[a.id]) _laneById[a.id] = pk; });
    });
    return _laneById;
  }
  L.laneOf = function (id) { return laneMap()[id] || ''; };
  L.laneLabel = function (pk) { return LANE_LABEL[pk] || String(pk || '').replace(/_\d+.*$/, '').replace(/_/g, ' '); };
  L.laneHue = function (pk) { return LANE_HUE[pk] || 'checks'; };
  // Lanes in load order, only those that actually carry moves.
  L.lanes = function () {
    var pd = OBOL.packData || {}, order = OBOL.ACTION_PACKS || [];
    return order.filter(function (pk) { return pd[pk] && (pd[pk].actions || []).length; })
      .map(function (pk) { return { key: pk, label: L.laneLabel(pk), hue: L.laneHue(pk) }; });
  };

  function phaseOf(a) { return (OBOL.phases && OBOL.phases.phaseOfAction) ? OBOL.phases.phaseOfAction(a) : (a.phase || 'enum'); }
  L.phaseOf = phaseOf;

  // ── tokens a move keys on (its ports / services) ────────────────────────────────────────────────
  function gatesOf(a) { return (a.requires_all || []).concat(a.requires_any || []); }
  function portsOf(a) {
    var out = {}; gatesOf(a).forEach(function (k) { var m = /^port:(\d+)$/.exec(k); if (m) out[m[1]] = true; }); return Object.keys(out);
  }
  function servicesOf(a) {
    var out = {};
    gatesOf(a).forEach(function (k) {
      var m = /^service\.([a-z0-9-]+)$/.exec(k) || /^([a-z0-9]+)\.reachable$/.exec(k);
      if (m) out[m[1]] = true;
    });
    return Object.keys(out);
  }
  function toolsOf(a) {
    var out = {}; if (a.tool) out[String(a.tool).toLowerCase()] = true;
    (a.tools || []).forEach(function (t) { if (t) out[String(t).toLowerCase()] = true; });
    return Object.keys(out);
  }
  function needsCred(a) { return gatesOf(a).some(function (k) { return /^credential\./.test(k); }); }
  function isExploit(a) {
    var p = (a.produces || []).join(' ');
    return /foothold\.|access\.(shell|admin|system|root)|rce|exploit/i.test((a.id || '') + ' ' + p) || /exploit|cve-/i.test(a.id || '');
  }

  // ── facet index (every facet value -> its move ids, with counts) ────────────────────────────────
  var _index = null;
  function buildIndex(pack) {
    if (_index) return _index;
    var ix = { lane: {}, phase: {}, port: {}, service: {}, tool: {}, os: {}, locus: {}, tag: {} };
    function add(group, key, id) { if (!key && key !== 0) return; (ix[group][key] = ix[group][key] || {})[id] = true; }
    (pack || []).forEach(function (a) {
      add('lane', L.laneOf(a.id), a.id);
      add('phase', phaseOf(a), a.id);
      portsOf(a).forEach(function (p) { add('port', p, a.id); });
      servicesOf(a).forEach(function (s) { add('service', s, a.id); });
      toolsOf(a).forEach(function (t) { add('tool', t, a.id); });
      (a.os || []).forEach(function (o) { add('os', o, a.id); });
      if (a.locus) add('locus', a.locus, a.id);
      if (needsCred(a)) add('tag', 'needs-credential', a.id);
      add('tag', isExploit(a) ? 'exploit' : 'enumeration', a.id);
    });
    _index = ix;
    return ix;
  }
  // facet listing for the UI: [{group, values:[{key,label,count}]}], sorted sensibly.
  L.facets = function (pack) {
    var ix = buildIndex(pack);
    function vals(group, labeler, sorter) {
      var out = Object.keys(ix[group]).map(function (k) { return { key: k, label: labeler ? labeler(k) : k, count: Object.keys(ix[group][k]).length }; });
      out.sort(sorter || function (a, b) { return b.count - a.count || String(a.label).localeCompare(String(b.label)); });
      return out;
    }
    var PH = ['recon', 'enum', 'creds', 'access', 'escalate', 'loot'];
    return [
      { group: 'lane', label: 'Lane', values: L.lanes().map(function (ln) { return { key: ln.key, label: ln.label, count: Object.keys(ix.lane[ln.key] || {}).length, hue: ln.hue }; }).filter(function (v) { return v.count; }) },
      { group: 'phase', label: 'Phase', values: PH.filter(function (p) { return ix.phase[p]; }).map(function (p) { return { key: p, label: p.charAt(0).toUpperCase() + p.slice(1), count: Object.keys(ix.phase[p]).length }; }) },
      { group: 'service', label: 'Service', values: vals('service', function (s) { return s.toUpperCase(); }) },
      { group: 'port', label: 'Port', values: vals('port', function (p) { return p; }, function (a, b) { return (+a.key) - (+b.key); }) },
      { group: 'tool', label: 'Tool', values: vals('tool') },
      { group: 'os', label: 'OS', values: vals('os', function (o) { return o.charAt(0).toUpperCase() + o.slice(1); }) },
      { group: 'tag', label: 'Kind', values: vals('tag', function (t) { return t.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }); }) },
    ].filter(function (f) { return f.values.length; });
  };

  // filter moves: OR within a facet group, AND across groups. sel = { lane:[..], phase:[..], ... }.
  L.filter = function (pack, sel, q) {
    sel = sel || {};
    var ix = buildIndex(pack);
    var groups = Object.keys(sel).filter(function (g) { return (sel[g] || []).length && ix[g]; });
    var needle = (q || '').trim().toLowerCase();
    return (pack || []).filter(function (a) {
      for (var i = 0; i < groups.length; i++) {
        var g = groups[i], want = sel[g], ok = false;
        for (var j = 0; j < want.length; j++) { if (ix[g][want[j]] && ix[g][want[j]][a.id]) { ok = true; break; } }
        if (!ok) return false;
      }
      if (needle) {
        var hay = (a.id + ' ' + (a.title || '') + ' ' + (a.hypothesis || '') + ' ' + toolsOf(a).join(' ')
          + ' ' + (a.commands || []).map(function (c) { return c.run || ''; }).join(' ')).toLowerCase();
        if (hay.indexOf(needle) < 0) return false;
      }
      return true;
    });
  };

  // ── command catalogue (the hero lens): flatten, dedupe to template, group tool -> capability ────
  function stripCmd(run) {
    return String(run || '').replace(/^#.*$/m, '').replace(/^\s*(?:sudo\s+|proxychains4?\s+|[A-Z_][A-Z0-9_]*=\S+\s+)+/, '').trim();
  }
  // the tool a command invokes (normalised family) + a capability sub-label.
  L.toolOf = function (run) {
    var s = stripCmd(run); var first = (s.split(/\s+/)[0] || '').toLowerCase();
    if (first === 'netexec' || first === 'nxc') return 'nxc';
    if (/^impacket-/.test(first) || /^(secretsdump|getnpusers|getuserspns|gettgt|getst|psexec|wmiexec|smbexec|dcomexec|ntlmrelayx|getadusers|lookupsid|rbcd|dacledit|ticketer|raiseChild|goldenPac|mssqlclient|rpcdump|samrdump)\.py$/i.test(first)) return 'impacket';
    if (/\.py$/.test(first)) return first.replace(/\.py$/, '');
    return first || '(shell)';
  };
  L.capabilityOf = function (run, move) {
    var s = stripCmd(run), toks = s.split(/\s+/), tool = L.toolOf(run);
    if (tool === 'nxc') { var proto = (toks[1] || '').toLowerCase(); if (/^(smb|ldap|winrm|mssql|rdp|ssh|ftp|wmi|vnc|nfs)$/.test(proto)) return 'nxc ' + proto; return 'nxc'; }
    if (tool === 'impacket') { var b = (toks[0] || '').toLowerCase().replace(/^impacket-/, '').replace(/\.py$/, ''); return b || 'impacket'; }
    // everything else: group by the move's phase so nothing is uncategorised
    return move ? phaseOf(move) : 'other';
  };

  // One entry per DISTINCT command template, with back-links to every move that uses it. moves[] keeps
  // the per-move note so the UI can show context on click. Source of truth: the move's own commands.
  L.commandCatalog = function (pack) {
    var byTemplate = {};
    (pack || []).forEach(function (a) {
      var cmds = (a.commands && a.commands.length) ? a.commands : (a.command ? [{ run: a.command }] : []);
      cmds.forEach(function (c) {
        var run = String(c.run || '').trim(); if (!run || /^#/.test(run)) return;
        var key = run;
        var e = byTemplate[key];
        if (!e) {
          e = byTemplate[key] = { template: run, tool: L.toolOf(run), capability: L.capabilityOf(run, a), phase: phaseOf(a), lane: L.laneOf(a.id), moves: [] };
        }
        if (!e.moves.some(function (m) { return m.id === a.id; })) e.moves.push({ id: a.id, title: a.title || a.id, note: c.note || '' });
      });
    });
    return Object.keys(byTemplate).map(function (k) { return byTemplate[k]; });
  };

  // grouped tool -> capability -> [commands], for the default browse view.
  L.commandsGrouped = function (pack, q) {
    var list = L.commandCatalog(pack), needle = (q || '').trim().toLowerCase();
    if (needle) list = list.filter(function (e) {
      return (e.template + ' ' + e.tool + ' ' + e.capability + ' ' + e.moves.map(function (m) { return m.title; }).join(' ')).toLowerCase().indexOf(needle) >= 0;
    });
    var tools = {};
    list.forEach(function (e) {
      var t = tools[e.tool] = tools[e.tool] || { tool: e.tool, count: 0, caps: {} };
      (t.caps[e.capability] = t.caps[e.capability] || { capability: e.capability, cmds: [] }).cmds.push(e);
      t.count++;
    });
    return Object.keys(tools).map(function (tk) {
      var t = tools[tk];
      t.caps = Object.keys(t.caps).sort().map(function (ck) { var c = t.caps[ck]; c.cmds.sort(function (a, b) { return a.template.localeCompare(b.template); }); return c; });
      return t;
    }).sort(function (a, b) { return b.count - a.count || a.tool.localeCompare(b.tool); });
  };

  // fill a template from the active engagement's facts/params (the "relevant to my box" affordance),
  // or return it tokenised. Reuses the one filler, so a Library command matches what the coach would run.
  L.fill = function (template, facts, params) {
    try { return OBOL.command.fillCommand({ commands: [{ run: template }] }, facts, { params: params || {} }, 0).filled; }
    catch (e) { return template; }
  };

  // ── ATT&CK library view: every technique obol performs -> the moves + commands behind it ─────────
  L.techniqueLibrary = function (pack) {
    var AM = OBOL.ATTACK_MOVE, CAT = OBOL.ATTACK;
    if (!AM || !CAT) return [];
    var byMove = AM.byMove || {}, techs = {};
    (pack || []).forEach(function (a) {
      var codes = byMove[a.id]; if (!codes) return;
      (Array.isArray(codes) ? codes : [codes]).forEach(function (code) {
        var t = techs[code] = techs[code] || { id: code, moves: [] };
        t.moves.push({ id: a.id, title: a.title || a.id, lane: L.laneOf(a.id), phase: phaseOf(a) });
      });
    });
    // catalog technique entries are compact: .n = name, .ta = tactic ids, .p = parent, .url. A code obol
    // maps to may be a sub-technique whose name lives under its parent, so fall back to the parent entry.
    var meta = (CAT && CAT.techniques) || {};
    function parentOf(c) { var m = /^(T\d+)\.\d+$/.exec(c); return m ? m[1] : c; }
    return Object.keys(techs).map(function (code) {
      var t = techs[code], m = meta[code] || meta[parentOf(code)] || {};
      t.name = m.n || code; t.tactics = m.ta || []; t.url = m.url || '';
      return t;
    }).sort(function (a, b) {
      var ta = (a.tactics[0] || 'zzz'), tb = (b.tactics[0] || 'zzz');
      return ta.localeCompare(tb) || a.id.localeCompare(b.id);
    });
  };

  // tactic id -> label, in ATT&CK matrix order, for the library-scoped matrix colouring.
  L.tactics = function () {
    var CAT = OBOL.ATTACK; return ((CAT && CAT.tactics) || []).map(function (ta) { return { id: ta.id, name: ta.name }; });
  };

  // reset caches (the engagement changing does not change the catalogue, but tests may reload packs).
  L.reset = function () { _laneById = null; _index = null; };

  OBOL.library = L;
})(typeof globalThis !== 'undefined' ? globalThis : this);
