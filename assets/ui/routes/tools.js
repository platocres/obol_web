/*!
 * obol ui — routes/tools.js — THE TOOLS SURFACE (fact-aware tactical launchpad).
 *
 * A funnel, not a wall of flags: the shared Engagement Binding bar (OBOL.bind) autofills the target,
 * identity, ports, and wordlist; STATIONS group substitute tools by the job they do (Web Content
 * Discovery, Crack Hashes, Port Scan) with a visible engine selector; each tool opens to RECIPE tiles
 * (named presets, one tap to a filled command), an always-editable command preview, a flag-by-flag
 * teaching gloss, and a collapsible complete form (every documented switch). Compiled by
 * OBOL.toolbuilder.compile; nothing executes. Field values persist under engagement.ui.tools[toolId].
 * Presentation only: pack commands stay the source of truth. House style: no em or en dashes.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  var TB = OBOL.toolbuilder;
  var TK = OBOL.toolkit;
  function esc(s) { return U.esc(s); }
  function attr(s) { return U.attr ? U.attr(s) : esc(s); }
  function truthy(v) { return TB.truthy(v); }

  // hashcat -m <-> john --format for the common OSCP hash types, so swapping the Crack Hashes engine
  // keeps the hash type you already picked. Values match the two builders' own option lists exactly.
  var HASH_XWALK = [
    ['1000', 'NT'], ['3000', 'lm'], ['5500', 'netntlm'], ['5600', 'netntlmv2'],
    ['1100', 'mscash'], ['2100', 'mscash2'], ['13100', 'krb5tgs'], ['18200', 'krb5asrep'],
    ['19600', 'krb5tgs'], ['19700', 'krb5tgs'], ['19800', 'krb5asrep'], ['19900', 'krb5asrep'],
    ['1800', 'sha512crypt'], ['7400', 'sha256crypt'], ['500', 'md5crypt'], ['3200', 'bcrypt'], ['1500', 'descrypt'],
    ['0', 'raw-md5'], ['900', 'raw-md4'], ['100', 'raw-sha1'], ['1400', 'raw-sha256'], ['1700', 'raw-sha512'],
    ['400', 'phpass'], ['300', 'mysql-sha1'], ['200', 'mysql'], ['131', 'mssql'], ['132', 'mssql05'], ['1731', 'mssql12'],
    ['13400', 'keepass'], ['11600', '7z'], ['13000', 'rar5'], ['12500', 'rar'],
  ];
  function hcModeToJohn(mode) { for (var i = 0; i < HASH_XWALK.length; i++) if (HASH_XWALK[i][0] === String(mode)) return HASH_XWALK[i][1]; return null; }
  function johnFormatToHc(fmt) { for (var i = 0; i < HASH_XWALK.length; i++) if (HASH_XWALK[i][1] === String(fmt)) return HASH_XWALK[i][0]; return null; }
  // identifyHash returns lowercase john hints ('nt'); the john builder's NT option value is uppercase.
  function normJohn(j) { return j === 'nt' ? 'NT' : j; }

  var CATS = [
    { id: 'web', label: 'Web', hint: 'Content discovery, fingerprinting, request testing.' },
    { id: 'credentials', label: 'Credentials', hint: 'Validation, spraying, roasting, cracking, capture.' },
    { id: 'ad', label: 'Active Directory', hint: 'LDAP, Kerberos, AD CS, graph collection.' },
    { id: 'remote-exec', label: 'Remote Exec', hint: 'Authenticated shells and command execution.' },
    { id: 'database', label: 'Database', hint: 'SQL shells: read data, pivot to code execution.' },
    { id: 'pivot', label: 'Pivot', hint: 'Tunnels, SOCKS, port forwarding.' },
    { id: 'enum', label: 'Enumeration', hint: 'Scanning, SMB/RPC/SNMP surface mapping.' },
    { id: 'privesc', label: 'Privilege Escalation', hint: 'Local enumeration helpers.' },
    { id: 'shells', label: 'Shells & Transfer', hint: 'Payloads, listeners, file transfer.' },
  ];
  // Phase hue per recipe tag (reuses the --ph-* tokens).
  var PHASE_HUE = { recon: 'recon', enum: 'enum', cracking: 'creds', creds: 'creds', access: 'access', escalate: 'escalate', loot: 'loot' };
  // Each tool category gets a distinct LANE hue, so the page reads as colour-coded zones (the hue
  // encodes the category). Maps to the established .lane-* classes (which set --lane).
  var CATHUE = { web: 'lane-web', credentials: 'lane-creds', ad: 'lane-ad', 'remote-exec': 'lane-windows', database: 'lane-database', pivot: 'lane-pivot', enum: 'lane-recon', privesc: 'lane-linux', shells: 'lane-shells' };
  function catLane(id) { return CATHUE[id] || ''; }

  // ---- equipped scoping ----
  function equippedSet() { var set = {}; try { OBOL.packs.equippedTools().forEach(function (t) { set[t] = true; }); } catch (e) {} return set; }
  function toolset() { return (OBOL.TOOLSET || []).slice(); }
  function isEquipped(b, eq) { return (b.equips || []).some(function (t) { return eq[t]; }); }
  function equippedBuilders() { var eq = equippedSet(); return toolset().filter(function (b) { return isEquipped(b, eq); }); }
  function builderById(id) { return toolset().filter(function (b) { return b.id === id; })[0] || null; }

  // Builders that live inside a station are not also shown as standalone category cards.
  function stationBuilderIds() {
    var ids = {};
    (TK && TK.stations ? TK.stations() : []).forEach(function (s) { (s.engines || []).forEach(function (e) { ids[e.builderId] = true; }); });
    return ids;
  }

  // ---- autofill context (from the binding bar, with a safe fallback) ----
  function toolContext() {
    if (OBOL.bind && OBOL.bind.context) { try { return OBOL.bind.context(); } catch (e) {} }
    var eng = OBOL.store.active(), params = (eng && eng.params) || {}, facts;
    try { facts = OBOL.store.factSet(); } catch (e) { facts = new OBOL.facts.FactSet([]); }
    var c = {}; try { c = OBOL.command.buildContext(facts, { params: params }); } catch (e) { c = {}; }
    var target = (c.target && c.target !== '<target>') ? c.target : (params.target || params.rhost || '');
    var host = params.hostname || c.dc || target;
    var scheme = 'http://';
    var url = host ? (scheme + host) : '';
    return {
      target: { value: target, ip: params.rhost || params.ip || target, hostname: params.hostname || c.dc || '', url: url, fuzzurl: url ? (url + '/FUZZ') : '' },
      context: { domain: c.domain || params.domain || '', username: c.user || params.username || '', port: params.port || '', lhost: params.lhost || '', lport: params.lport || '' },
      workspace: { wordlist: params.wordlist || '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt', outputDir: params.outputDir || 'loot', hashfile: params.hashfile || 'hashes.txt' },
    };
  }

  // ---- layout lens (Grid | Focus), persisted per engagement; default Focus ----
  function layout() { try { return (OBOL.store.active().ui || {}).toolsLayout || 'focus'; } catch (e) { return 'focus'; } }
  function setLayout(v) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsLayout = v; }, 'tools-layout'); }
  // focus selection (station or tool id)
  function focusSel() { try { return (OBOL.store.active().ui || {}).toolsFocus || ''; } catch (e) { return ''; } }
  function setFocusSel(id) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsFocus = id; }, 'tools-focus'); }

  // ---- per-tool value persistence ----
  function savedValues(toolId) { var eng = OBOL.store.active(); var tools = (eng && eng.ui && eng.ui.tools) || {}; return Object.assign({}, tools[toolId] || {}); }
  function persistValues(toolId, values) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.tools = eng.ui.tools || {}; eng.ui.tools[toolId] = values; }, 'tool-values'); }
  // station engine choice
  function stationEngine(stationId, def) { try { var s = (OBOL.store.active().ui || {}).toolsStation || {}; return s[stationId] || def; } catch (e) { return def; } }
  function setStationEngine(stationId, builderId) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsStation = eng.ui.toolsStation || {}; eng.ui.toolsStation[stationId] = builderId; }, 'tool-station'); }

  // ================================ form rendering (shared) ================================
  function fieldControl(builder, field, value) {
    var id = 'tb-' + builder.id + '-' + field.id;
    var common = ' id="' + esc(id) + '" name="' + esc(field.id) + '" data-tb-field="' + esc(field.id) + '"' + (field.required ? ' required' : '');
    var help = field.help ? '<small class="tb-hint">' + esc(field.help) + '</small>' : '';
    if (field.type === 'checkbox') return '<label class="tb-check"><input type="checkbox"' + common + (truthy(value) ? ' checked' : '') + '> <span>' + esc(field.label) + '</span></label>' + help;
    if (field.type === 'select') {
      var anyDesc = false;
      var opts = (field.options || []).map(function (o) { if (o.description) anyDesc = true; return '<option value="' + esc(o.value) + '"' + (String(o.value) === String(value) ? ' selected' : '') + (o.description ? ' data-desc="' + esc(o.description) + '" title="' + esc(o.description) + '"' : '') + '>' + esc(o.label) + '</option>'; }).join('');
      var optDesc = anyDesc ? '<small class="tb-hint tb-optdesc" data-optdesc-for="' + esc(field.id) + '"></small>' : '';
      return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><select' + common + '>' + opts + '</select>' + optDesc + help;
    }
    if (field.type === 'textarea') return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><textarea' + common + (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '') + ' rows="3">' + esc(value == null ? '' : value) + '</textarea>' + help;
    var inputType = field.type === 'secret' ? 'password' : (field.type === 'number' ? 'number' : 'text');
    return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><input type="' + inputType + '"' + common + ' value="' + esc(value == null ? '' : value) + '"' + (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '') + ' autocomplete="' + (field.type === 'secret' ? 'off' : 'on') + '">' + help;
  }
  function presetsHtml(field) {
    var presets = Array.isArray(field.presets) ? field.presets : []; if (!presets.length) return '';
    return '<div class="tb-chips">' + presets.map(function (p) { var spd = p.speed ? '<span class="tb-spd ' + esc(p.speed) + '">' + esc(p.speed) + '</span>' : ''; return '<button type="button" class="tb-chip" data-preset-field="' + esc(field.id) + '" data-preset-value="' + esc(p.value) + '">' + spd + esc(p.label) + '</button>'; }).join('') + '</div>';
  }
  function snippetsHtml(field) {
    var snippets = Array.isArray(field.snippets) ? field.snippets : []; if (!snippets.length) return '';
    return '<div class="tb-chips">' + snippets.map(function (s) { return '<button type="button" class="tb-chip" data-snippet-field="' + esc(field.id) + '" data-snippet-value="' + esc(s.value) + '">' + esc(s.label) + '</button>'; }).join('') + '</div>';
  }
  function fieldRow(builder, field, values) {
    var hidden = field.visibleWhen && !TB.conditionMatches(field.visibleWhen, values);
    var wide = field.type === 'textarea' ? ' tb-wide' : '';
    return '<div class="tb-field' + wide + '" data-field-id="' + esc(field.id) + '"' + (hidden ? ' hidden' : '') + '>' + fieldControl(builder, field, values[field.id]) + snippetsHtml(field) + presetsHtml(field) + '</div>';
  }
  function groupsFor(builder) {
    var fields = (builder.fields || []); var byId = {}; fields.forEach(function (f) { byId[f.id] = f; });
    if (Array.isArray(builder.fieldGroups) && builder.fieldGroups.length) {
      var claimed = {};
      var groups = builder.fieldGroups.map(function (g) { return { title: g.title, description: g.description, fields: (g.fields || []).map(function (id) { claimed[id] = true; return byId[id]; }).filter(Boolean) }; }).filter(function (g) { return g.fields.length; });
      var leftovers = fields.filter(function (f) { return !claimed[f.id]; });
      if (leftovers.length) groups.push({ title: 'More Options', description: 'Additional flags and output controls.', fields: leftovers });
      return groups;
    }
    return [{ title: '', description: '', fields: fields }];
  }
  function formHtml(builder, values) {
    var groups = groupsFor(builder).map(function (group) {
      var rows = group.fields.map(function (f) { return fieldRow(builder, f, values); }).join('');
      if (!group.title) return '<div class="tb-group-body">' + rows + '</div>';
      return '<section class="tb-group"><div class="tb-group-head"><h4>' + esc(group.title) + '</h4><p>' + esc(group.description) + '</p></div><div class="tb-group-body">' + rows + '</div></section>';
    }).join('');
    return '<form class="tb-form" novalidate>' + groups + '</form>';
  }
  // The real executable of a compiled command, for the live cmd-tag label (skip env/sudo wrappers and
  // VAR=value prefixes so a field-choice tool like file-transfer-helper shows impacket-smbserver, not wget).
  function execOf(cmd) {
    var toks = (TK && TK.tokenize) ? TK.tokenize(cmd) : String(cmd).split(' ');
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t === 'env' || t === 'sudo' || t === 'nohup' || t === 'exec' || /^[A-Z_][A-Z0-9_]*=/.test(t)) continue;
      return t.split('/').pop();
    }
    return toks[0] || '';
  }
  function highlight(cmd) {
    // Tokenize honoring quotes (TK.tokenize) so a quoted argument like "whoami /all" stays ONE token and
    // its inner space is not mistaken for a flag boundary. Colour executables, flags, IPs, numbers, and
    // quoted strings distinctly so the command reads semantically, not as a grey slab.
    var toks = (TK && TK.tokenize) ? TK.tokenize(cmd) : String(cmd).split(' ');
    return toks.map(function (tok, i) {
      if (tok === '') return '';
      if (/FUZZ/.test(tok)) return tok.split(/(FUZZ)/).map(function (part) { return part === 'FUZZ' ? '<span class="tb-fuzz">FUZZ</span>' : (part ? '<span class="tb-arg">' + esc(part) + '</span>' : ''); }).join('');
      var cls;
      if (i === 0) cls = 'tb-exe';
      else if (/^-/.test(tok)) cls = 'tb-flag';
      else if (/^["']/.test(tok)) cls = 'tb-str';                          // a quoted argument, kept whole
      else if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(tok)) cls = 'tb-ip';   // an IPv4 (optional :port)
      else if (/^\d+$/.test(tok)) cls = 'tb-num';                          // a bare number (port, hashcat mode)
      else cls = 'tb-arg';
      return '<span class="' + cls + '">' + esc(tok) + '</span>';
    }).join(' ');
  }

  // ================================ funnel panel ================================
  function recipeTiles(builder, activeId) {
    var recipes = TK ? TK.recipesFor(builder.id) : [];
    if (!recipes.length) return '';
    // With many presets (the hash modes), switch to compact chips: name + phase only, the hint on hover,
    // so more fit on screen at once ("smaller neon chunks").
    var compact = recipes.length > 6;
    var tiles = recipes.map(function (r) {
      var hue = PHASE_HUE[r.phase] || 'enum';
      return '<button type="button" class="tb-recipe ns-card ns-ph-' + hue + (r.id === activeId ? ' selected is-glow' : '') + '" data-recipe="' + esc(r.id) + '" title="' + attr(r.hint) + '" aria-pressed="' + (r.id === activeId ? 'true' : 'false') + '">'
        + '<span class="tb-recipe-name">' + esc(r.label) + '</span>'
        + (compact ? '' : '<span class="tb-recipe-hint">' + esc(r.hint) + '</span>')
        + '<span class="ph-chip ph-' + hue + '">' + esc(r.phase) + '</span></button>';
    }).join('');
    return '<div class="tb-recipes' + (compact ? ' compact' : '') + '"><div class="tb-recipes-lab">Recipes <span class="tb-recipes-sub">one tap to a filled command, then tune it</span></div>'
      + '<div class="ns-grid tb-recipe-grid">' + tiles + '</div></div>';
  }
  function glossHtml(cmd, builder) {
    var rows = TK ? TK.glossCommand(cmd, builder) : [];
    if (!rows.length) return '<div class="tb-gloss"><div class="tb-gloss-lab">What Each Part Does</div><p class="tb-hint">Flag notes appear here once the command has recognized switches.</p></div>';
    return '<div class="tb-gloss"><div class="tb-gloss-lab">What Each Part Does</div><dl class="tb-gloss-list">'
      + rows.map(function (g) { return '<div class="tb-gloss-row"><dt><code>' + esc(g.flag) + '</code></dt><dd>' + esc(g.gloss) + '</dd></div>'; }).join('')
      + '</dl></div>';
  }
  function proofHtml(builder) {
    var e = builder.evidence || {}, m = builder.manualOutcome || {};
    return '<details class="tb-proof"><summary>Evidence &amp; Report Boundary</summary>'
      + '<p class="tb-hint"><b>Expected Evidence:</b> ' + esc(e.expectation) + '</p>'
      + '<p class="tb-hint"><b>Proof Boundary:</b> ' + esc(e.proofBoundary) + '</p>'
      + '<p class="tb-hint"><b>Manual Outcome:</b> ' + esc(m.boundary) + '</p></details>';
  }
  // the panel body: recipe tiles, editable preview + copy/reset, flag gloss, collapsible full form, evidence.
  // The primary "mode" field a tool switches on (protocol / method / role / ...). Surfaced as prominent
  // clickable chips at the top of the panel so the main choice is never buried in All Options.
  var PRIMARY_IDS = ['mode', 'method', 'protocol', 'role', 'source', 'inputMode'];
  function primaryField(builder) {
    var fields = builder.fields || [];
    for (var i = 0; i < PRIMARY_IDS.length; i++) {
      // 2 to 8 options: enough to be a real switch, few enough to chip. A big list (hashcat's 55 modes)
      // stays a select in All Options and is driven by recipes / auto-detect instead.
      var f = fields.filter(function (x) { var n = (x.options || []).length; return x.id === PRIMARY_IDS[i] && x.type === 'select' && n >= 2 && n <= 8; })[0];
      if (f) return f;
    }
    return null;
  }
  function modeChipsHtml(builder, values) {
    var f = primaryField(builder); if (!f) return '';
    var cur = values[f.id];
    var chips = (f.options || []).map(function (o) {
      var on = String(o.value) === String(cur);
      return '<button type="button" class="tb-mode-chip' + (on ? ' on' : '') + '" data-mode-field="' + esc(f.id) + '" data-mode-value="' + esc(o.value) + '" aria-pressed="' + (on ? 'true' : 'false') + '"'
        + (o.description ? ' title="' + esc(o.description) + '"' : '') + '>' + esc(o.label) + '</button>';
    }).join('');
    return '<div class="tb-modes"><span class="tb-modes-lab">' + esc(f.label) + '</span><div class="tb-modes-row">' + chips + '</div></div>';
  }

  // The required fields that are not yet filled (respecting requiredWhen + visibility), as field objects.
  function missingRequiredFields(builder, values) {
    return (builder.fields || []).filter(function (f) {
      var required = f.required === true || (f.requiredWhen ? TB.conditionMatches(f.requiredWhen, values) : false);
      if (!required) return false;
      if (f.visibleWhen && !TB.conditionMatches(f.visibleWhen, values)) return false;
      var v = values[f.id];
      return v === undefined || v === null || v === '' || (f.type === 'checkbox' && f.mustBeChecked === true && !truthy(v));
    });
  }
  // A labelled input for one missing field, proxied to the real form field (distinct id to avoid clashes).
  function needsInputHtml(field, value) {
    var fid = 'need-' + field.id, lab = '<label for="' + esc(fid) + '">' + esc(field.label) + '</label>';
    var ph = field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '';
    if (field.type === 'select') {
      var opts = (field.options || []).map(function (o) { return '<option value="' + esc(o.value) + '"' + (String(o.value) === String(value) ? ' selected' : '') + '>' + esc(o.label) + '</option>'; }).join('');
      return lab + '<select id="' + esc(fid) + '" data-needs-field="' + esc(field.id) + '">' + opts + '</select>';
    }
    if (field.type === 'textarea') return lab + '<textarea id="' + esc(fid) + '" data-needs-field="' + esc(field.id) + '" rows="2"' + ph + '>' + esc(value == null ? '' : value) + '</textarea>';
    var t = field.type === 'secret' ? 'password' : (field.type === 'number' ? 'number' : 'text');
    return lab + '<input type="' + t + '" id="' + esc(fid) + '" data-needs-field="' + esc(field.id) + '" value="' + esc(value == null ? '' : value) + '"' + ph + ' autocomplete="off" spellcheck="false">';
  }

  function panelBody(builder, values, activeRecipe) {
    return '<div class="tb-panel">'
      + recipeTiles(builder, activeRecipe)
      + modeChipsHtml(builder, values)
      + '<div class="tb-preview cmd"><div class="cmd-head"><span class="cmd-tag">' + esc((builder.equips && builder.equips[0]) || builder.tool) + '</span>'
        + '<span class="cmd-variant tb-recipe-name-live"></span>'
        + '<span class="cmd-spacer"></span>'
        + '<button type="button" class="btn-copy tb-editbtn" title="Edit the command by hand">edit</button>'
        + '<button type="button" class="btn-copy tb-reset" title="Restore the generated command">reset</button>'
        + '<button type="button" class="btn-copy tb-copy" title="Copy command">copy</button></div>'
        + '<pre class="cmd-run tb-render" title="Click to edit"><code class="tb-code"></code></pre>'
        + '<textarea class="tb-edit" spellcheck="false" aria-label="Editable command" rows="2"></textarea></div>'
      + '<div class="tb-needs" hidden></div>'
      + glossHtml('', builder)
      + '<details class="tb-allopts"><summary>All Options <span class="tb-hint">every documented switch, grouped</span></summary>' + formHtml(builder, values) + '</details>'
      + '<p class="tb-foot">Obol builds the command from the controls you set and never runs it. The box above is editable: tune it, copy it, and run it yourself in an authorized lab, then paste the output into Evidence.</p>'
      + '</div>';
  }

  // ================================ cards ================================
  function toolCardHead(builder) {
    return '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="false">'
      + '<div class="tool-card-title"><span class="tool-card-name">' + esc(builder.title) + '</span>'
      + '<span class="tool-card-exec">' + esc(builder.executionContext || 'any') + '</span>'
      + '<span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">' + esc(builder.summary) + '</p></div>';
  }
  function toolCard(builder, openId, laneCls) {
    var open = builder.id === openId || builder.tool === openId || (builder.equips || []).indexOf(openId) !== -1;
    // These are DESCRIPTIVE metadata (what binaries the tool uses, which auth it takes), not selectors.
    // Label them "uses" / "auth" and style them flat so they do not read as clickable mode toggles.
    var equips = (builder.equips || []).slice(0, 4);
    var equipsChips = equips.length ? '<span class="tags-lab">uses</span>' + equips.map(function (t) { return '<span class="pill tag-static">' + esc(t) + '</span>'; }).join('') : '';
    var cred = (builder.credentialModes && builder.credentialModes.length) ? '<span class="tags-lab">auth</span><span class="pill tb-cred tag-static">' + esc(builder.credentialModes.join(' / ')) + '</span>' : '';
    return '<article class="tool-card' + (laneCls ? ' ' + laneCls : '') + (open ? ' open' : '') + '" data-tool-id="' + esc(builder.id) + '">'
      + toolCardHead(builder)
      + '<div class="tool-card-tags">' + equipsChips + cred + '</div>'
      + '<div class="tool-body"></div></article>';
  }
  function stationCard(station, openStationId, factKinds) {
    var built = TK.stationBuilders(station);
    if (!built.length) return '';
    var active = stationEngine(station.id, TK.defaultEngine(station, factKinds));
    if (!built.some(function (b) { return b.builder.id === active; })) active = built[0].builder.id;
    var open = station.id === openStationId;
    var engineChips = built.map(function (b) {
      return '<button type="button" class="tb-engine' + (b.builder.id === active ? ' on' : '') + '" data-engine="' + esc(b.builder.id) + '" title="' + attr(b.engine.teach) + '">' + esc(b.engine.label) + '</button>';
    }).join('');
    var teach = (built.filter(function (b) { return b.builder.id === active; })[0] || built[0]).engine.teach;
    return '<article class="tool-card station-card lane-' + esc(station.hue) + (open ? ' open' : '') + '" data-station-id="' + esc(station.id) + '" data-active-engine="' + esc(active) + '">'
      + '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<div class="tool-card-title"><span class="station-badge">Station</span><span class="tool-card-name">' + esc(station.title) + '</span><span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">' + esc(station.job) + '</p></div>'
      + '<div class="station-engines"><span class="tb-engines-lab">Engine</span>' + engineChips + '<span class="tb-engine-teach">' + esc(teach) + '</span></div>'
      + '<div class="tool-body"></div></article>';
  }

  // ================================ Shell Station ================================
  function downloadText(filename, text) {
    try {
      var blob = new Blob([text], { type: 'text/x-shellscript' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      return true;
    } catch (e) { return false; }
  }
  function shellParams() {
    var p = (OBOL.store.active() || {}).params || {};
    return { lhost: p.lhost || '', lport: p.lport || '4444' };
  }
  function shellStationCard(open) {
    return '<article class="tool-card station-card shell-station lane-shells' + (open ? ' open' : '') + '" data-station-id="shell">'
      + '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<div class="tool-card-title"><span class="station-badge">Kit</span><span class="tool-card-name">Get A Shell</span><span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">Download a listener kit: one .sh that prints every payload filled with your LHOST and LPORT, the PowerShell -EncodedCommand, and the TTY upgrade, then listens.</p></div>'
      + '<div class="tool-body"></div></article>';
  }
  function mountShellStation(body) {
    if (!OBOL.shellkit) { body.innerHTML = '<p class="tb-hint">Shell kit engine still loading, try again in a moment.</p>'; return; }
    var SK = OBOL.shellkit;
    function draw() {
      var sp = shellParams();
      var catchers = SK.catchers();
      var cur = ((OBOL.store.active() || {}).ui || {}).shellCatcher || 'nc';
      if (!catchers.some(function (c) { return c.id === cur; })) cur = 'nc';
      var catEl = catchers.map(function (c) { return '<button type="button" class="tb-engine' + (c.id === cur ? ' on' : '') + '" data-catcher="' + esc(c.id) + '" title="' + attr(c.teach) + '">' + esc(c.label) + '</button>'; }).join('');
      var teach = (catchers.filter(function (c) { return c.id === cur; })[0] || catchers[0]).teach;
      var pays = SK.payloads(sp.lhost || 'LHOST', sp.lport || '4444');
      var payRows = pays.map(function (p) {
        return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-name">' + esc(p.name) + '</span><span class="shk-pay-os ' + esc(p.os) + '">' + esc(p.os) + '</span>'
          + '<button type="button" class="bind-chip shk-copy" data-copy="' + attr(p.cmd) + '">copy</button></div>'
          + '<code class="shk-pay-cmd">' + esc(p.cmd) + '</code></div>';
      }).join('');
      var enc = SK.psEncodedCommand(sp.lhost || 'LHOST', sp.lport || '4444');
      var tty = SK.ttyUpgrade().map(function (l) { return esc(l); }).join('\n');
      body.innerHTML = '<div class="shk">'
        + '<div class="shk-lh"><label>LHOST <input class="shk-lhost" value="' + attr(sp.lhost) + '" placeholder="10.10.14.5" spellcheck="false"></label>'
        + '<label>LPORT <input class="shk-lport" value="' + attr(sp.lport) + '" placeholder="4444" spellcheck="false"></label></div>'
        + '<div class="station-engines"><span class="tb-engines-lab">Catcher</span>' + catEl + '<span class="tb-engine-teach">' + esc(teach) + '</span></div>'
        + '<div class="shk-actions"><button type="button" class="shk-dl">Download Kit (.sh)</button>'
        + '<button type="button" class="bind-chip shk-copyenc" data-copy="' + attr(enc) + '">Copy PowerShell -EncodedCommand</button>'
        + '<span class="tb-hint">obol writes it; you run it on your own box. Nothing executes here.</span></div>'
        + '<div class="shk-pays">' + payRows + '</div>'
        + '<div class="tb-gloss"><div class="tb-gloss-lab">After You Catch It: Upgrade The TTY</div><pre class="shk-tty">' + tty + '</pre></div>'
        + '</div>';
    }
    draw();
    U.on(body, 'input', '.shk-lhost', function (e, t) { OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.lhost = t.value.trim(); }, 'params'); });
    U.on(body, 'input', '.shk-lport', function (e, t) { OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.lport = t.value.trim(); }, 'params'); });
    U.on(body, 'change', '.shk-lhost', function () { draw(); });
    U.on(body, 'change', '.shk-lport', function () { draw(); });
    U.on(body, 'click', '.tb-engine', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.shellCatcher = t.getAttribute('data-catcher'); }, 'shell-catcher'); draw(); });
    U.on(body, 'click', '.shk-copy, .shk-copyenc', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });
    U.on(body, 'click', '.shk-dl', function () {
      var sp = shellParams();
      var cur = ((OBOL.store.active() || {}).ui || {}).shellCatcher || 'nc';
      var kit = SK.listenerKit({ lhost: sp.lhost || 'LHOST', lport: sp.lport || '4444', catcher: cur });
      var okd = downloadText('obol-listener-' + (sp.lport || '4444') + '.sh', kit);
      U.toast(okd ? 'Listener kit downloaded' : 'Download blocked by the browser', okd ? '' : 'err');
    });
  }

  // ================================ render ================================
  function render(ctx) {
    var builders = equippedBuilders();
    var openId = (ctx.args && ctx.args[0]) ? decodeURIComponent(ctx.args[0]).toLowerCase() : '';
    if (!builders.length) {
      return '<section class="tools-route"><h1 class="route-h1">Tools</h1><p class="route-sub">No equipped tools resolved yet. Load a methodology pack and the matching builders appear here.</p></section>';
    }
    var lay = layout();
    var factKinds = []; try { factKinds = OBOL.store.factSet().kinds(); } catch (e) {}

    var html = '<section class="tools-route" data-layout="' + esc(lay) + '">';
    html += '<div class="tools-top"><h1 class="route-h1">Tools</h1>'
      + '<div class="tools-lens" role="group" aria-label="Layout"><button type="button" class="tools-lens-btn' + (lay === 'focus' ? ' on' : '') + '" data-lay="focus">Focus</button>'
      + '<button type="button" class="tools-lens-btn' + (lay === 'grid' ? ' on' : '') + '" data-lay="grid">Grid</button></div></div>';
    html += '<p class="route-sub">Point and click: the binding bar fills the target, identity, ports, and wordlist; pick a recipe for a ready command, tune it, copy it. Nothing runs here.</p>';
    html += '<div id="bind-bar"></div>';

    // stations (hero)
    var stations = (TK && TK.stations ? TK.stations() : []).filter(function (s) { return TK.stationBuilders(s).length; });
    if (stations.length) {
      html += '<section class="tools-stations"><div class="tools-cat-head"><h2 class="tools-cat-h">Stations</h2><span class="tools-cat-hint">One job, your choice of engine.</span></div>'
        + '<div class="tools-grid">' + stations.map(function (s) { return stationCard(s, openId, factKinds); }).join('') + '</div></section>';
    }

    // access kits (downloadable, fact-filled bundles)
    html += '<section class="tools-stations"><div class="tools-cat-head"><h2 class="tools-cat-h">Access Kits</h2><span class="tools-cat-hint">Downloadable, filled from your engagement. obol writes them; you run them.</span></div>'
      + '<div class="tools-grid">' + shellStationCard(openId === 'shell') + (OBOL.pivotStationUI ? OBOL.pivotStationUI.card(openId === 'pivot') : '') + '</div></section>';

    // categories (standalone tools not covered by a station)
    var inStation = stationBuilderIds();
    var byCat = {};
    builders.forEach(function (b) { if (inStation[b.id]) return; (byCat[b.category] = byCat[b.category] || []).push(b); });
    Object.keys(byCat).forEach(function (c) { byCat[c].sort(function (a, b) { return a.title.localeCompare(b.title); }); });
    var present = CATS.filter(function (c) { return byCat[c.id] && byCat[c.id].length; });

    html += '<nav class="tools-nav" aria-label="Jump to a tool category">'
      + '<button type="button" class="pill tools-jump tools-jump-top" data-cat="__top__" title="Back to Stations">↑ Top</button>'
      + present.map(function (c) { return '<button type="button" class="pill tools-jump ' + esc(catLane(c.id)) + '" data-cat="tb-cat-' + esc(c.id) + '">' + esc(c.label) + ' <b>' + byCat[c.id].length + '</b></button>'; }).join('') + '</nav>';
    present.forEach(function (c) {
      var lc = catLane(c.id);
      html += '<section class="tools-cat ' + esc(lc) + '" id="tb-cat-' + esc(c.id) + '"><div class="tools-cat-head"><h2 class="tools-cat-h">' + esc(c.label) + '</h2><span class="tools-cat-hint">' + esc(c.hint) + '</span></div>'
        + '<div class="tools-grid">' + byCat[c.id].map(function (b) { return toolCard(b, openId, lc); }).join('') + '</div></section>';
    });
    html += '</section>';
    return html;
  }

  // ================================ panel mounting ================================
  function collect(form, builder) {
    var out = {};
    (builder.fields || []).forEach(function (f) { var el = form.elements ? form.elements.namedItem(f.id) : null; if (!el) return; out[f.id] = f.type === 'checkbox' ? !!el.checked : el.value; });
    return out;
  }
  function applyVisibility(form, builder, values) {
    (builder.fields || []).forEach(function (f) { var row = form.querySelector('[data-field-id="' + f.id + '"]'); if (!row) return; row.hidden = !!(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, values)); });
  }
  function setFormValue(form, builder, fid, val) {
    var f = (builder.fields || []).filter(function (x) { return x.id === fid; })[0]; if (!f) return;
    var el = form.elements && form.elements.namedItem(fid); if (!el) return;
    if (f.type === 'checkbox') el.checked = truthy(val); else el.value = (val == null ? '' : val);
  }

  // Fill a builder's empty secret fields from the engagement's effective identity (the one the binding
  // bar points at). The secret is already stored in the credential ledger and shown masked in the bar,
  // so this places the same value into the tool's password/hash field (masked) rather than exposing
  // anything new. It never overwrites a value the operator typed.
  function fillSecrets(builder, values) {
    var id = (OBOL.bind && OBOL.bind.effectiveIdentity) ? OBOL.bind.effectiveIdentity() : null;
    if (!id) return;
    (builder.fields || []).forEach(function (f) {
      if (f.type !== 'secret' || (values[f.id] !== undefined && values[f.id] !== '')) return;
      if (f.credentialKind === 'password' && id.secret) values[f.id] = id.secret;
      else if ((f.credentialKind === 'ntlm' || f.credentialKind === 'netntlm') && id.nthash) values[f.id] = id.nthash;
    });
  }

  // Mount the funnel panel for one builder into panelEl (its .tool-body). persistId keys saved values.
  function mountPanel(panelEl, builder, context, persistId, startValues) {
    var start = startValues || Object.assign(TB.defaultsFor(builder, context), savedValues(persistId));
    fillSecrets(builder, start);
    var secretSet = {}; (builder.fields || []).forEach(function (f) { if (f.type === 'secret') secretSet[f.id] = 1; });
    var activeRecipe = TK ? TK.matchingRecipe(builder, start) : null;
    panelEl.innerHTML = panelBody(builder, start, activeRecipe);

    var form = panelEl.querySelector('.tb-form');
    var code = panelEl.querySelector('.tb-code');
    var edit = panelEl.querySelector('.tb-edit');
    var render = panelEl.querySelector('.tb-render');
    var copyBtn = panelEl.querySelector('.tb-copy');
    var resetBtn = panelEl.querySelector('.tb-reset');
    var editBtn = panelEl.querySelector('.tb-editbtn');
    var preview = panelEl.querySelector('.tb-preview');
    var glossEl = panelEl.querySelector('.tb-gloss');
    var cmdTag = panelEl.querySelector('.cmd-tag');
    var liveName = panelEl.querySelector('.tb-recipe-name-live');
    var needsEl = panelEl.querySelector('.tb-needs');
    var needsLastKey = '__init__';
    var edited = false; // operator hand-edited the command box

    // Surface the still-unfilled required fields as inline, labelled inputs right under the command, so
    // they are never a dead "Set required: ..." line and never hidden behind All Options. Re-render only
    // when the SET of missing fields changes, and never while the operator is typing inside the block.
    function renderNeeds(current) {
      if (!needsEl) return;
      var resolved = TB.normalizeValues(builder, current, context);
      var missing = missingRequiredFields(builder, resolved);
      var key = missing.map(function (f) { return f.id; }).join(',');
      // never yank the field being typed in; leave needsLastKey stale so it re-renders once focus leaves.
      if (needsEl.contains(document.activeElement)) return;
      if (key === needsLastKey) return;
      needsLastKey = key;
      if (!missing.length) { needsEl.innerHTML = ''; needsEl.setAttribute('hidden', ''); return; }
      needsEl.removeAttribute('hidden');
      needsEl.innerHTML = '<div class="tb-needs-lab"><span class="tb-needs-dot" aria-hidden="true"></span>Fill These To Build The Command'
        + '<span class="tb-needs-sub">' + missing.length + ' required</span></div>'
        + '<div class="tb-needs-grid">' + missing.map(function (f) { return '<div class="tb-need">' + needsInputHtml(f, current[f.id]) + '</div>'; }).join('') + '</div>';
    }
    function syncModeChips(current) {
      var chips = panelEl.querySelectorAll('.tb-mode-chip');
      for (var i = 0; i < chips.length; i++) {
        var fid = chips[i].getAttribute('data-mode-field');
        var on = String(current[fid]) === String(chips[i].getAttribute('data-mode-value'));
        chips[i].classList.toggle('on', on); chips[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      }
    }
    function setEditing(on) { if (!preview) return; preview.classList.toggle('editing', on); if (editBtn) editBtn.textContent = on ? 'done' : 'edit'; if (on && edit) { edit.focus(); } }

    function paintGloss(cmd) { if (glossEl) glossEl.outerHTML = glossHtml(cmd, builder); glossEl = panelEl.querySelector('.tb-gloss'); }
    function showCmd(cmd, valid) {
      if (cmdTag && valid) { var ex = execOf(cmd); if (ex) cmdTag.textContent = ex; } // reflect the ACTIVE executable
      code.innerHTML = valid ? highlight(cmd) : esc(cmd);
      code.setAttribute('data-valid', valid ? 'true' : 'false');
      if (valid) code.setAttribute('data-cmd', cmd); else code.removeAttribute('data-cmd');
      if (edit && document.activeElement !== edit) edit.value = cmd;
      paintGloss(valid ? cmd : '');
    }
    function recompile(save) {
      var current = collect(form, builder);
      applyVisibility(form, builder, TB.normalizeValues(builder, current, context));
      var activeId = TK ? TK.matchingRecipe(builder, TB.normalizeValues(builder, current, context)) : null;
      // reflect active recipe tile
      var tiles = panelEl.querySelectorAll('.tb-recipe');
      for (var ti = 0; ti < tiles.length; ti++) { var on = tiles[ti].getAttribute('data-recipe') === activeId; tiles[ti].classList.toggle('selected', on); tiles[ti].classList.toggle('is-glow', on); tiles[ti].setAttribute('aria-pressed', on ? 'true' : 'false'); }
      if (liveName) liveName.textContent = activeId ? (TK.recipeById(builder.id, activeId) || {}).label || '' : 'custom';
      edited = false;
      syncModeChips(current);
      renderNeeds(current);
      try { showCmd(TB.compile(builder, current, context), true); }
      catch (err) { var missing = TB.validateRequired(builder, TB.normalizeValues(builder, current, context)); showCmd(missing.length ? ('Fill the ' + missing.length + ' required field' + (missing.length > 1 ? 's' : '') + ' below to build this command.') : 'Complete the required fields to generate a command.', false); }
      // select option descriptions
      var sels = form.querySelectorAll('select');
      for (var si = 0; si < sels.length; si++) { var sel = sels[si], note = sel.parentNode && sel.parentNode.querySelector('.tb-optdesc'); if (!note) continue; var opt = sel.options[sel.selectedIndex]; note.textContent = (opt && opt.getAttribute('data-desc')) || ''; }
      if (save) { var pv = {}; Object.keys(current).forEach(function (k) { if (!secretSet[k]) pv[k] = current[k]; }); persistValues(persistId, pv); }
    }

    form.addEventListener('input', function () { recompile(true); });
    form.addEventListener('change', function () { recompile(true); });

    // Prominent mode chips at the top: set the primary field and rebuild (also mirrors into All Options).
    U.on(panelEl, 'click', '.tb-mode-chip', function (e, t) {
      setFormValue(form, builder, t.getAttribute('data-mode-field'), t.getAttribute('data-mode-value'));
      recompile(true);
    });
    // Inline "fill these" inputs proxy straight into the real form field, so required fields are fillable
    // without opening All Options. A select fires change; text fires input (and keeps focus, see renderNeeds).
    if (needsEl) {
      U.on(needsEl, 'input', '[data-needs-field]', function (e, t) { setFormValue(form, builder, t.getAttribute('data-needs-field'), t.value); recompile(true); });
      U.on(needsEl, 'change', '[data-needs-field]', function (e, t) { setFormValue(form, builder, t.getAttribute('data-needs-field'), t.value); recompile(true); });
      // when focus truly leaves the block, re-render so any now-filled fields drop out
      needsEl.addEventListener('focusout', function () { setTimeout(function () { if (!needsEl.contains(document.activeElement)) renderNeeds(collect(form, builder)); }, 0); });
    }

    // Hash auto-detect (Crack Hashes): paste a hash into the hash field and obol picks the matching -m
    // mode (hashcat) or --format (john) via OBOL.workbench.identifyHash, so you never hand-set the number.
    (function () {
      if (!OBOL.workbench || !OBOL.workbench.identifyHash) return;
      var isHc = builder.id === 'tb-hashcat', isJn = builder.id === 'tb-john';
      if (!isHc && !isJn) return;
      var hashEl = form.elements && form.elements.namedItem(isHc ? 'hashOrFile' : 'hashFile');
      var modeEl = form.elements && form.elements.namedItem(isHc ? 'mode' : 'format');
      if (!hashEl || !modeEl || modeEl.tagName !== 'SELECT') return;
      function hasOpt(v) { for (var i = 0; i < modeEl.options.length; i++) if (modeEl.options[i].value === String(v)) return true; return false; }
      function detect() {
        var v = String(hashEl.value || '').trim();
        if (!v || v.length < 8 || /[\s]/.test(v) || v.indexOf('/') >= 0 || v.indexOf('\\') >= 0) return; // a path or blank, not a hash
        var r = OBOL.workbench.identifyHash(v), cand = r && r.candidates && r.candidates[0];
        if (!cand) return;
        var want = isHc ? String(cand.mode) : normJohn(cand.john);
        if (want && hasOpt(want) && modeEl.value !== want) {
          modeEl.value = want;
          recompile(true);
          if (liveName) liveName.textContent = 'auto: ' + cand.name;
          if (U.toast) U.toast('Detected ' + cand.name, '');
        }
      }
      hashEl.addEventListener('change', detect);
      hashEl.addEventListener('input', function () { if (String(hashEl.value).trim().length >= 16) detect(); });
    })();

    // recipe tile: apply the preset to the form, then recompile
    U.on(panelEl, 'click', '.tb-recipe', function (e, t) {
      var rid = t.getAttribute('data-recipe');
      var recipe = TK.recipeById(builder.id, rid); if (!recipe) return;
      var vals = TK.applyRecipe(builder, recipe, context); // defaults + binding autofill + recipe values
      // Adopt the recipe WHOLESALE: set every non-secret field, clearing any a previous recipe pinned
      // (e.g. the rule file from "NTLM + Rules") that this recipe does not set. Without this, a stale
      // field keeps matchingRecipe locked on the broader recipe and the exact tile looks unselectable.
      (builder.fields || []).forEach(function (f) {
        if (f.type === 'secret') return; // never clobber a typed credential
        setFormValue(form, builder, f.id, Object.prototype.hasOwnProperty.call(vals, f.id) ? vals[f.id] : '');
      });
      recompile(true);
    });
    // presets / snippets inside the full form
    U.on(panelEl, 'click', '[data-preset-field]', function (e, t) { var el = form.elements && form.elements.namedItem(t.getAttribute('data-preset-field')); if (!el) return; el.value = t.getAttribute('data-preset-value'); try { el.dispatchEvent(new Event('change', { bubbles: true })); } catch (_e) {} recompile(true); });
    U.on(panelEl, 'click', '[data-snippet-field]', function (e, t) { var el = form.elements && form.elements.namedItem(t.getAttribute('data-snippet-field')); if (!el) return; var v = t.getAttribute('data-snippet-value'); el.value = (String(el.value).trim() ? String(el.value).replace(/\s+$/, '') + '\n' : '') + v; try { el.focus(); } catch (_e) {} recompile(true); });

    // editable command box: typing re-glosses live; it becomes the copy source
    if (edit) edit.addEventListener('input', function () { edited = true; code.setAttribute('data-cmd', edit.value); code.setAttribute('data-valid', 'true'); code.innerHTML = highlight(edit.value); paintGloss(edit.value); if (liveName) liveName.textContent = 'edited'; });
    if (editBtn) editBtn.addEventListener('click', function () { setEditing(!(preview && preview.classList.contains('editing'))); });
    // clicking the rendered command also opens the editor
    if (render) render.addEventListener('click', function () { setEditing(true); });
    if (resetBtn) resetBtn.addEventListener('click', function () { setEditing(false); recompile(false); });
    if (copyBtn) copyBtn.addEventListener('click', function () {
      var cmd = (edit && edited) ? edit.value : (code.getAttribute('data-cmd') || '');
      if (!cmd || code.getAttribute('data-valid') !== 'true') { U.toast('Command not ready', 'err'); return; }
      U.copy(cmd).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    recompile(false);
  }

  // ================================ mounted ================================
  function mounted(ctx) {
    var mount = ctx.mount;
    var context = toolContext();

    // binding bar: on change, recompute context and re-mount every open panel so previews re-fill.
    var bindEl = mount.querySelector('#bind-bar');
    if (bindEl && OBOL.bind) {
      bindEl.innerHTML = OBOL.bind.render({});
      OBOL.bind.mount(bindEl, { onChange: function () { context = toolContext(); remountOpen(); } });
    }

    function remountOpen() {
      var open = mount.querySelectorAll('.tool-card.open');
      for (var i = 0; i < open.length; i++) mountCardBody(open[i]);
    }
    function mountCardBody(card) {
      var body = card.querySelector('.tool-body'); if (!body) return;
      if (card.classList.contains('shell-station')) { mountShellStation(body); return; }
      if (card.classList.contains('pivot-station')) { if (OBOL.pivotStationUI) OBOL.pivotStationUI.mount(body); return; }
      if (card.classList.contains('station-card')) {
        var st = TK.stationById(card.getAttribute('data-station-id')); if (!st) return;
        var active = card.getAttribute('data-active-engine');
        var b = builderById(active); if (!b) return;
        mountPanel(body, b, context, 'station:' + st.id + ':' + b.id);
      } else {
        var builder = builderById(card.getAttribute('data-tool-id')); if (!builder) return;
        mountPanel(body, builder, context, builder.id);
      }
    }

    function toggle(card) {
      var head = card.querySelector('.tool-card-head');
      var open = card.classList.toggle('open');
      if (head) head.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) mountCardBody(card);
    }

    U.on(mount, 'click', '.tool-card-head', function (e, t) { toggle(t.closest('.tool-card')); });
    U.on(mount, 'keydown', '.tool-card-head', function (e, t) { if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); toggle(t.closest('.tool-card')); } });

    // station engine switch: carry shared params across, persist the choice, re-mount the panel
    U.on(mount, 'click', '.tb-engine', function (e, t) {
      if (e.stopPropagation) e.stopPropagation();
      var card = t.closest('.station-card'); if (!card) return;
      var st = TK.stationById(card.getAttribute('data-station-id')); if (!st) return;
      var fromId = card.getAttribute('data-active-engine'), toId = t.getAttribute('data-engine');
      if (fromId === toId) return;
      var fromEng = (st.engines || []).filter(function (en) { return en.builderId === fromId; })[0];
      var toEng = (st.engines || []).filter(function (en) { return en.builderId === toId; })[0];
      var fromVals = savedValues('station:' + st.id + ':' + fromId);
      var carried = TK.carryShared(st, fromEng, toEng, fromVals);
      // Carry the hash TYPE across the engine swap too (hashcat -m <-> john --format), so switching
      // engines on a kerberoast hash does not silently reset to NTLM.
      if (fromId === 'tb-hashcat' && toId === 'tb-john') { var jf = hcModeToJohn(fromVals.mode); if (jf) carried.format = jf; }
      else if (fromId === 'tb-john' && toId === 'tb-hashcat') { var hm = johnFormatToHc(fromVals.format); if (hm) carried.mode = hm; }
      setStationEngine(st.id, toId);
      card.setAttribute('data-active-engine', toId);
      // update engine chip states + teach line
      var chips = card.querySelectorAll('.tb-engine');
      for (var i = 0; i < chips.length; i++) chips[i].classList.toggle('on', chips[i].getAttribute('data-engine') === toId);
      var teachEl = card.querySelector('.tb-engine-teach'); if (teachEl && toEng) teachEl.textContent = toEng.teach;
      var toBuilder = builderById(toId); if (!toBuilder) return;
      var start = Object.assign(TB.defaultsFor(toBuilder, context), savedValues('station:' + st.id + ':' + toId), carried);
      mountPanel(card.querySelector('.tool-body'), toBuilder, context, 'station:' + st.id + ':' + toId, start);
    });

    // layout lens
    U.on(mount, 'click', '.tools-lens-btn', function (e, t) { setLayout(t.getAttribute('data-lay')); OBOL.router.render(); });
    // category jump
    U.on(mount, 'click', '.tools-jump', function (e, t) {
      var cat = t.getAttribute('data-cat');
      if (cat === '__top__') { var v = document.getElementById('view') || mount; try { v.scrollTo({ top: 0, behavior: 'smooth' }); } catch (_e) { v.scrollTop = 0; } return; }
      var el = document.getElementById(cat); if (el) { try { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_e) { el.scrollIntoView(); } }
    });

    // any card pre-opened (deep link) mounts now
    var opened = mount.querySelectorAll('.tool-card.open');
    for (var k = 0; k < opened.length; k++) { var c = opened[k]; var h = c.querySelector('.tool-card-head'); if (h) h.setAttribute('aria-expanded', 'true'); mountCardBody(c); if (k === 0) { try { c.scrollIntoView({ block: 'start' }); } catch (e) {} } }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.tools = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
