/*!
 * obol ui - routes/tools.js - THE TOOLS SURFACE (fact-aware tactical launchpad).
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
    ['19600', 'krb5tgs'], ['19700', 'krb5tgs'], ['19800', 'krb5pa-sha1'], ['19900', 'krb5pa-sha1'],
    ['1800', 'sha512crypt'], ['7400', 'sha256crypt'], ['500', 'md5crypt'], ['3200', 'bcrypt'], ['1500', 'descrypt'],
    ['0', 'raw-md5'], ['900', 'raw-md4'], ['100', 'raw-sha1'], ['1400', 'raw-sha256'], ['1700', 'raw-sha512'],
    ['400', 'phpass'], ['300', 'mysql-sha1'], ['200', 'mysql'], ['131', 'mssql'], ['132', 'mssql05'], ['1731', 'mssql12'],
    ['13400', 'keepass'], ['11600', '7z'], ['13000', 'rar5'], ['12500', 'rar'],
    ['5400', 'ike'], ['101', 'nsldap'], ['111', 'ssha'], ['112', 'oracle11'],
    ['10500', 'pdf'], ['13600', 'zip'], ['17200', 'pkzip'], ['22911', 'ssh'],
  ];
  // Captured hash facts -> the hashcat -m mode to pre-pick, so the Crack Hashes tool opens already set to
  // the hash you actually hold (an AS-REP roast, a Kerberoast ticket, a dumped NT hash). Roast hashes that
  // beg to be cracked rank first. Respects any mode the operator set by hand.
  var HASH_FACT_MODE = [
    ['hash.asrep', '18200'], ['hash.tgs', '13100'], ['hash.netntlmv2', '5600'], ['hash.netntlm', '5500'],
    ['hash.ntlm', '1000'], ['hash.krbtgt', '1000'], ['hash.mscache', '2100'], ['hash.ike_psk', '5400'],
  ];
  function hcModeToJohn(mode) { for (var i = 0; i < HASH_XWALK.length; i++) if (HASH_XWALK[i][0] === String(mode)) return HASH_XWALK[i][1]; return null; }
  function johnFormatToHc(fmt) { for (var i = 0; i < HASH_XWALK.length; i++) if (HASH_XWALK[i][1] === String(fmt)) return HASH_XWALK[i][0]; return null; }
  // identifyHash returns lowercase john hints ('nt'); the john builder's NT option value is uppercase.
  function normJohn(j) {
    var map = { nt: 'NT', rar3: 'rar', zip2: 'zip', sshng: 'ssh', oracle11g: 'oracle11', 'krb5pa-md5': 'krb5pa-sha1' };
    return map[j] || j;
  }

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
      context: (function () { var dom = c.domain || params.domain || ''; return { domain: dom, baseDn: dom ? ('DC=' + dom.split('.').join(',DC=')) : '', username: c.user || params.username || '', port: params.port || '', lhost: params.lhost || '', lport: params.lport || '' }; })(),
      workspace: { wordlist: params.wordlist || '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt', outputDir: params.outputDir || 'loot', hashfile: params.hashfile || 'hashes.txt' },
    };
  }

  // ---- layout lens (Grid | Focus), persisted per engagement; default Focus ----
  function layout() { try { return (OBOL.store.active().ui || {}).toolsLayout || 'grid'; } catch (e) { return 'grid'; } }
  function setLayout(v) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsLayout = v; }, 'tools-layout'); }
  // focus selection (a focus-item key: "station:<id>" | "kit:shell" | "kit:pivot" | "tool:<id>")
  function focusSel() { try { return (OBOL.store.active().ui || {}).toolsFocus || ''; } catch (e) { return ''; } }
  function setFocusSel(id) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsFocus = id; }, 'tools-focus'); }

  // ---- Focus Lens: one flat, grouped index of every selectable surface (stations, access kits, and
  // standalone tools), so the master-detail layout has a single source for the left list and the
  // detail dispatch. Each item carries a stable key, its display group, label, summary, and the kind
  // the detail pane mounts. Order: Stations, Access Kits, then the category order in CATS.
  function focusItems() {
    var items = [];
    var inStation = stationBuilderIds();
    (TK && TK.stations ? TK.stations() : []).forEach(function (s) {
      if (!TK.stationBuilders(s).length) return;
      items.push({ key: 'station:' + s.id, group: 'Stations', label: s.title, sum: s.job, kind: 'station', id: s.id, hue: 'lane-' + s.hue });
    });
    items.push({ key: 'kit:shell', group: 'Access Kits', label: 'Get A Shell', sum: 'Download a listener kit filled with your LHOST and LPORT.', kind: 'shell', hue: 'lane-shells' });
    if (OBOL.pivotStationUI) items.push({ key: 'kit:pivot', group: 'Access Kits', label: 'Pivot And Tunnel', sum: 'Download both halves of a tunnel, filled from your engagement.', kind: 'pivot', hue: 'lane-pivot' });
    var byCat = {};
    equippedBuilders().forEach(function (b) { if (inStation[b.id]) return; (byCat[b.category] = byCat[b.category] || []).push(b); });
    Object.keys(byCat).forEach(function (c) { byCat[c].sort(function (a, b) { return a.title.localeCompare(b.title); }); });
    CATS.forEach(function (c) {
      if (!byCat[c.id] || !byCat[c.id].length) return;
      byCat[c.id].forEach(function (b) { items.push({ key: 'tool:' + b.id, group: c.label, label: b.title, sum: b.summary, kind: 'tool', id: b.id, hue: catLane(c.id), exec: b.executionContext || 'any', uses: (b.equips || []).join(' ') }); });
    });
    return items;
  }
  // The card markup for a focus item, rendered open, so the existing mountCardBody dispatch can mount it.
  function focusCardHtml(item, factKinds, openId) {
    if (!item) return '';
    if (item.kind === 'shell') return shellStationCard(true);
    if (item.kind === 'pivot') return OBOL.pivotStationUI ? OBOL.pivotStationUI.card(true) : '';
    if (item.kind === 'station') { var s = TK.stationById(item.id); return s ? stationCard(s, openId || item.id, factKinds) : ''; }
    var b = builderById(item.id); return b ? toolCard(b, item.id, item.hue) : '';
  }
  // The station whose engine list includes this builder id (so a deep link to a station-only tool like
  // hashcat/ffuf resolves to its station), or null.
  function stationOf(builderId) {
    var sts = (TK && TK.stations) ? TK.stations() : [];
    for (var i = 0; i < sts.length; i++) {
      if ((sts[i].engines || []).some(function (e) {
        if (e.builderId === builderId) return true;
        var b = builderById(e.builderId);
        return b && (b.tool === builderId || (b.equips || []).indexOf(builderId) !== -1);
      })) return sts[i];
    }
    return null;
  }
  // Resolve a deep-link arg (a builder id, a tool NAME, or a station id) OR a saved key to a focus item.
  function resolveFocusKey(items, openId, saved) {
    function present(k) { return items.some(function (it) { return it.key === k; }); }
    if (openId) {
      var hit = items.filter(function (it) {
        return it.id === openId || it.key === 'tool:' + openId || it.key === 'station:' + openId
          || (openId === 'shell' && it.kind === 'shell') || (openId === 'pivot' && it.kind === 'pivot');
      })[0];
      // also resolve a tool NAME (e.g. "nxc") to the builder whose tool/equips match it
      if (!hit) {
        hit = items.filter(function (it) {
          if (it.kind !== 'tool') return false;
          var b = builderById(it.id); if (!b) return false;
          return String(b.tool || '').toLowerCase() === openId || (b.equips || []).some(function (t) { return String(t).toLowerCase() === openId; });
        })[0];
      }
      // a builder that only exists inside a station (hashcat, ffuf, ...) -> that station's item
      if (!hit) { var st = stationOf(openId); if (st) hit = items.filter(function (it) { return it.key === 'station:' + st.id; })[0]; }
      if (hit) return hit.key;
    }
    if (saved && present(saved)) return saved;
    return items.length ? items[0].key : '';
  }

  // ---- per-tool value persistence ----
  function savedValues(toolId) { var eng = OBOL.store.active(); var tools = (eng && eng.ui && eng.ui.tools) || {}; return Object.assign({}, tools[toolId] || {}); }
  function persistValues(toolId, values) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.tools = eng.ui.tools || {}; eng.ui.tools[toolId] = values; }, 'tool-values'); }
  // station engine choice
  function stationEngine(stationId, def) { try { var s = (OBOL.store.active().ui || {}).toolsStation || {}; return s[stationId] || def; } catch (e) { return def; } }
  function setStationEngine(stationId, builderId) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.toolsStation = eng.ui.toolsStation || {}; eng.ui.toolsStation[stationId] = builderId; }, 'tool-station'); }

  // ================================ form rendering (shared) ================================
  // A field's `suggest` list makes its text/path/number input a COMBOBOX (native <datalist>): a dropdown
  // of common values that the operator can pick in one tap OR type over freely. This is the "do not make
  // me go look it up on Kali" control: canonical masks, rule files, wordlists, modes, SIDs, ports, and so
  // on live in the dropdown; typing still works for anything bespoke. Each entry is {value, label?} or a
  // bare string. Returns the `list=` attribute for the input plus the <datalist> element to emit after it.
  function suggestList(field, idBase) {
    var s = Array.isArray(field.suggest) ? field.suggest : [];
    if (!s.length) return { attr: '', html: '' };
    var dlId = idBase + '-dl';
    var opts = s.map(function (o) {
      var v = (o && typeof o === 'object') ? o.value : o;
      var lab = (o && typeof o === 'object' && o.label) ? o.label : '';
      return '<option value="' + attr(v == null ? '' : v) + '"' + (lab ? ' label="' + attr(lab) + '"' : '') + '></option>';
    }).join('');
    return { attr: ' list="' + esc(dlId) + '" data-combobox="1"', html: '<datalist id="' + esc(dlId) + '">' + opts + '</datalist>' };
  }
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
    var sl = suggestList(field, id);
    var ac = (field.type === 'secret' || sl.attr) ? 'off' : 'on'; // a combobox turns autocomplete off so the datalist, not form history, drives the dropdown
    return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><input type="' + inputType + '"' + common + sl.attr + ' value="' + esc(value == null ? '' : value) + '"' + (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '') + ' autocomplete="' + ac + '">' + sl.html + help;
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
    // haystack for the "Find A Switch" palette: label, help, id, and every option/suggestion label.
    var hay = [field.label, field.help, field.placeholder, field.id]
      .concat((field.options || []).map(function (o) { return o.label + ' ' + o.value; }))
      .concat((field.suggest || []).map(function (s) { return (s && typeof s === 'object') ? (s.label || s.value) : s; }))
      .join(' ').toLowerCase();
    return '<div class="tb-field' + wide + '" data-field-id="' + esc(field.id) + '" data-filter="' + attr(hay) + '"' + (hidden ? ' hidden' : '') + '>' + fieldControl(builder, field, values[field.id]) + snippetsHtml(field) + presetsHtml(field) + '</div>';
  }
  function groupsFor(builder) {
    var fields = (builder.fields || []);
    var byId = {}; fields.forEach(function (f) { byId[f.id] = f; });
    if (Array.isArray(builder.fieldGroups) && builder.fieldGroups.length) {
      var claimed = {};
      var groups = builder.fieldGroups.map(function (g) {
        return {
          title: g.title,
          description: g.description,
          fields: (g.fields || []).map(function (id) {
            claimed[id] = true;
            return byId[id];
          }).filter(Boolean)
        };
      }).filter(function (g) { return g.fields.length; });
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
      var unq = t.replace(/^['"]|['"]$/g, '');
      if (t === 'env' || t === 'sudo' || t === 'nohup' || t === 'exec' || /^[A-Z_][A-Z0-9_]*=/.test(unq)) continue;
      return unq.split('/').pop();
    }
    return toks[0] || '';
  }
  function highlight(cmd) {
    // Tokenize honoring quotes (TK.tokenize) so a quoted argument like "whoami /all" stays ONE token and
    // its inner space is not mistaken for a flag boundary. Colour executables, flags, IPs, numbers, and
    // quoted strings distinctly so the command reads semantically, not as a grey slab.
    var toks = (TK && TK.tokenize) ? TK.tokenize(cmd) : String(cmd).split(' ');
    // Find the real executable (gold), skipping env/sudo/nohup/exec wrappers and VAR= prefixes, and the
    // one subcommand/protocol word right after it (violet): nxc SMB, gobuster DIR, certipy FIND, git CLONE.
    var execIdx = -1;
    for (var k = 0; k < toks.length; k++) {
      var t0 = toks[k];
      if (t0 === '') continue;
      var unq0 = t0.replace(/^['"]|['"]$/g, '');
      if (t0 === 'env' || t0 === 'sudo' || t0 === 'nohup' || t0 === 'exec' || /^[A-Z_][A-Z0-9_]*=/.test(unq0)) continue;
      execIdx = k;
      break;
    }
    var subIdx = -1;
    if (execIdx >= 0) { for (var j = execIdx + 1; j < toks.length; j++) { if (toks[j] === '') continue; if (/^[a-z][a-z0-9_-]*$/.test(toks[j])) subIdx = j; break; } }
    return toks.map(function (tok, i) {
      if (tok === '') return '';
      if (/FUZZ/.test(tok)) return tok.split(/(FUZZ)/).map(function (part) { return part === 'FUZZ' ? '<span class="tb-fuzz">FUZZ</span>' : (part ? '<span class="tb-arg">' + esc(part) + '</span>' : ''); }).join('');
      var cls;
      if (/^<[a-z0-9_-]+>$/i.test(tok)) cls = 'tb-ph';                     // a <placeholder> for an unfilled field
      else if (i === execIdx) cls = 'tb-exe';                              // the executable, gold
      else if (i === subIdx) cls = 'tb-sub';                               // the subcommand / protocol, violet
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
    // The primary field (protocol / method / ...) the tool switches on. A recipe that pins a value for
    // it is tagged with data-rmode, so the panel can show only the recipes relevant to the chosen mode
    // (Protocol -> relevant Recipes -> Fill These -> All Options). Recipes that set no primary value are
    // mode-agnostic and always show.
    var pf = primaryField(builder), pfid = pf ? pf.id : null;
    var tiles = recipes.map(function (r) {
      var hue = PHASE_HUE[r.phase] || 'enum';
      var rmode = (pfid && r.values && Object.prototype.hasOwnProperty.call(r.values, pfid)) ? String(r.values[pfid]) : '';
      return '<button type="button" class="tb-recipe ns-card ns-ph-' + hue + (r.id === activeId ? ' selected is-glow' : '') + '" data-recipe="' + esc(r.id) + '" data-rmode="' + esc(rmode) + '" title="' + attr(r.hint) + '" aria-pressed="' + (r.id === activeId ? 'true' : 'false') + '">'
        + '<span class="tb-recipe-name">' + esc(r.label) + '</span>'
        + (compact ? '' : '<span class="tb-recipe-hint">' + esc(r.hint) + '</span>')
        + '<span class="ph-chip ph-' + hue + '">' + esc(r.phase) + '</span></button>';
    }).join('');
    return '<div class="tb-recipes' + (compact ? ' compact' : '') + '"><div class="tb-recipes-lab">Options <span class="tb-recipes-sub">one tap to a filled command, then tune it</span></div>'
      + '<div class="ns-grid tb-recipe-grid">' + tiles + '</div>'
      + '<p class="tb-recipes-empty tb-hint" hidden>No preset for this selection yet. Open All Switches below, or pick another above.</p></div>';
  }
  // Stackable Option toggles: a builder's headlineToggles (independent checkbox switches) surfaced as
  // multi-select chips so the operator composes several in one command (nxc --users --groups --asreproast).
  // Only the toggles whose visibleWhen matches the current state show (so SMB-only modules hide under LDAP);
  // any shown subset is a valid stack by construction. Distinct from the single-select mode chips above.
  function toggleChipsHtml(builder, values) {
    var ids = builder.headlineToggles || []; if (!ids.length) return '';
    var byId = {}; (builder.fields || []).forEach(function (f) { byId[f.id] = f; });
    var chips = ids.map(function (fid) {
      var f = byId[fid]; if (!f) return '';
      var vis = !(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, values));
      var on = truthy(values[fid]);
      return '<button type="button" class="tb-tog-chip' + (on ? ' on' : '') + '" data-toggle-field="' + esc(fid) + '"' + (vis ? '' : ' hidden')
        + ' aria-pressed="' + (on ? 'true' : 'false') + '"' + (f.help ? ' title="' + attr(f.help) + '"' : '') + '>' + esc(f.label) + '</button>';
    }).join('');
    var lab = builder.switchesLabel || 'Switches';
    return '<div class="tb-toggles"><span class="tb-modes-lab">' + esc(lab) + ' <span class="tb-recipes-sub">stack any that apply</span></span><div class="tb-toggles-row">' + chips + '</div></div>';
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
  // protocol wins over authMode (so nxc leads with its protocol), but authMode is the primary branch for the
  // credentialed tools that have no protocol/mode (Evil-WinRM, secretsdump, bloodhound-python): password vs
  // Pass-The-Hash vs Kerberos is their main choice, so it gets the lead chips.
  var PRIMARY_IDS = ['mode', 'action', 'gobusterMode', 'source', 'protocol', 'method', 'authMode', 'role', 'inputMode'];
  function primaryField(builder) {
    var fields = builder.fields || [];
    for (var i = 0; i < PRIMARY_IDS.length; i++) {
      // 2 to 8 options: enough to be a real switch, few enough to chip. A big list (hashcat's 55 modes)
      // stays a select in All Options and is driven by recipes / auto-detect instead.
      var f = fields.filter(function (x) {
        if (x.visibleWhen) return false;
        var n = (x.options || []).length;
        return x.id === PRIMARY_IDS[i] && x.type === 'select' && n >= 2 && n <= 8;
      })[0];
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
    var sl = suggestList(field, fid); // the same combobox dropdown in the Fill These block
    return lab + '<input type="' + t + '" id="' + esc(fid) + '" data-needs-field="' + esc(field.id) + '"' + sl.attr + ' value="' + esc(value == null ? '' : value) + '"' + ph + ' autocomplete="off" spellcheck="false">' + sl.html;
  }

  function panelBody(builder, values, activeRecipe) {
    // Protocol / mode chips LEAD, then the recipes relevant to that choice, then Fill These, then All
    // Options: pick the protocol first and only its recipes and fields follow (the funnel the owner wants).
    return '<div class="tb-panel">'
      + modeChipsHtml(builder, values)
      + toggleChipsHtml(builder, values)
      + recipeTiles(builder, activeRecipe)
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
      + '<details class="tb-allopts"><summary>All Switches <span class="tb-hint">every documented switch, grouped</span></summary>'
        + '<div class="tb-optfind"><input type="search" class="tb-optfilter" placeholder="Find A Switch (mask, rule, username, proxy, ...)" aria-label="Find a switch" autocomplete="off" spellcheck="false"><span class="tb-optfind-none tb-hint" hidden>No option matches that.</span></div>'
        + formHtml(builder, values) + '</details>'
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
    var engineMatch = null;
    (station.engines || []).forEach(function (e) {
      if (engineMatch) return;
      if (e.builderId === openStationId) { engineMatch = e.builderId; return; }
      var b = builderById(e.builderId);
      if (b && (b.tool === openStationId || (b.equips || []).indexOf(openStationId) !== -1)) {
        engineMatch = e.builderId;
      }
    });
    var active = engineMatch ? engineMatch : stationEngine(station.id, TK.defaultEngine(station, factKinds));
    if (!built.some(function (b) { return b.builder.id === active; })) active = built[0].builder.id;
    var open = station.id === openStationId || !!engineMatch;
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
  function shellParams(bodyEl) {
    var manual = OBOL.bind && OBOL.bind.isManual && OBOL.bind.isManual();
    var p = manual ? {} : ((OBOL.store.active() || {}).params || {});
    var lhEl = bodyEl && bodyEl.querySelector ? bodyEl.querySelector('.shk-lhost') : null;
    var lpEl = bodyEl && bodyEl.querySelector ? bodyEl.querySelector('.shk-lport') : null;
    var lh = lhEl ? lhEl.value.trim() : (p.lhost || '');
    var lp = lpEl ? lpEl.value.trim() : (p.lport || '4444');
    return { lhost: lh, lport: lp || '4444' };
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
    if (body.parentNode && body._obolMounted) {
      var fresh = body.cloneNode(false);
      body.parentNode.replaceChild(fresh, body);
      body = fresh;
    }
    body._obolMounted = true;
    var SK = OBOL.shellkit;
    // Encoding for the Linux one-liners: Raw, Base64 runner (quoting-proof delivery), or URL-encoded
    // (to inject through a parameter). Windows payloads keep the dedicated -EncodedCommand button.
    var ENC_MODES = [{ id: 'raw', label: 'Raw' }, { id: 'b64', label: 'Base64' }, { id: 'url', label: 'URL' }];
    function encMode() { var m = ((OBOL.store.active() || {}).ui || {}).shellEnc || 'raw'; return ENC_MODES.some(function (e) { return e.id === m; }) ? m : 'raw'; }
    function draw() {
      var sp = shellParams(body);
      var catchers = SK.catchers();
      var cur = ((OBOL.store.active() || {}).ui || {}).shellCatcher || 'nc';
      if (!catchers.some(function (c) { return c.id === cur; })) cur = 'nc';
      var catEl = catchers.map(function (c) { return '<button type="button" class="tb-engine' + (c.id === cur ? ' on' : '') + '" data-catcher="' + esc(c.id) + '" title="' + attr(c.teach) + '">' + esc(c.label) + '</button>'; }).join('');
      var teach = (catchers.filter(function (c) { return c.id === cur; })[0] || catchers[0]).teach;
      var em = encMode();
      var pays = SK.payloads(sp.lhost || 'LHOST', sp.lport || '4444');
      var payRows = pays.map(function (p) {
        // Only the Linux shells are safe to base64/url wrap; leave Windows PowerShell as-is.
        var shown = (p.os === 'linux' && em !== 'raw' && SK.encodePayload) ? SK.encodePayload(p.cmd, em) : p.cmd;
        var encBadge = (p.os === 'linux' && em !== 'raw') ? '<span class="shk-enc-badge">' + esc(em) + '</span>' : '';
        return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-name">' + esc(p.name) + '</span><span class="shk-pay-os ' + esc(p.os) + '">' + esc(p.os) + '</span>' + encBadge
          + '<button type="button" class="bind-chip shk-copy" data-copy="' + attr(shown) + '">copy</button></div>'
          + '<code class="shk-pay-cmd">' + esc(shown) + '</code></div>';
      }).join('');
      var encToggle = '<div class="shk-enc"><span class="tb-engines-lab">Encode Linux Payloads</span>'
        + ENC_MODES.map(function (e) { return '<button type="button" class="tb-engine shk-encbtn' + (e.id === em ? ' on' : '') + '" data-enc="' + esc(e.id) + '">' + esc(e.label) + '</button>'; }).join('')
        + '<span class="tb-engine-teach">' + (em === 'b64' ? 'Delivered as echo B64 | base64 -d | bash, so quoting cannot break it.' : em === 'url' ? 'Percent-encoded to inject through a URL or form parameter.' : 'The plain one-liner.') + '</span></div>';
      var enc = SK.psEncodedCommand(sp.lhost || 'LHOST', sp.lport || '4444');
      var mvRows = (SK.msfvenom ? SK.msfvenom(sp.lhost || 'LHOST', sp.lport || '4444') : []).map(function (m) {
        return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-name">' + esc(m.name) + '</span><span class="shk-pay-os ' + esc(m.os) + '">' + esc(m.os) + '</span>'
          + '<button type="button" class="bind-chip shk-copy" data-copy="' + attr(m.cmd) + '">copy</button></div>'
          + '<code class="shk-pay-cmd">' + esc(m.cmd) + '</code><span class="shk-pay-note">' + esc(m.note) + '</span></div>';
      }).join('');
      var wsRows = (SK.webshells ? SK.webshells() : []).map(function (w) {
        var cradle = SK.webshellCradle ? SK.webshellCradle(w.code, w.ext) : '';
        return '<div class="shk-pay"><div class="shk-pay-h"><span class="shk-pay-name">' + esc(w.name) + '</span><span class="shk-pay-os web">shell.' + esc(w.ext) + '</span>'
          + '<button type="button" class="bind-chip shk-ws-dl" data-fn="shell.' + attr(w.ext) + '" data-code="' + attr(w.code) + '">download</button>'
          + (cradle ? '<button type="button" class="bind-chip shk-copy" data-copy="' + attr(cradle) + '" title="One-line base64 delivery: decode straight to a file on the target, no pasting raw source">cradle</button>' : '')
          + '<button type="button" class="bind-chip shk-copy" data-copy="' + attr(w.code) + '">copy</button></div>'
          + '<code class="shk-pay-cmd">' + esc(w.code) + '</code><span class="shk-pay-note">' + esc(w.note) + '</span></div>';
      }).join('');
      var tty = SK.ttyUpgrade().map(function (l) { return esc(l); }).join('\n');
      body.innerHTML = '<div class="shk">'
        + '<div class="shk-lh"><label>LHOST <input class="shk-lhost" value="' + attr(sp.lhost) + '" placeholder="10.10.14.5" spellcheck="false"></label>'
        + '<label>LPORT <input class="shk-lport" value="' + attr(sp.lport) + '" placeholder="4444" spellcheck="false"></label></div>'
        + '<div class="station-engines"><span class="tb-engines-lab">Catcher</span>' + catEl + '<span class="tb-engine-teach">' + esc(teach) + '</span></div>'
        + '<div class="shk-actions"><button type="button" class="shk-dl">Download Kit (.sh)</button>'
        + '<button type="button" class="bind-chip shk-copyenc" data-copy="' + attr(enc) + '">Copy PowerShell -EncodedCommand</button>'
        + '<span class="tb-hint">OBOL writes it; you run it on your own box. Nothing executes here.</span></div>'
        + encToggle
        + '<div class="shk-sec-lab">Reverse Shells</div><div class="shk-pays">' + payRows + '</div>'
        + '<div class="shk-sec-lab">MSFVenom Payload Files</div><div class="shk-pays">' + mvRows + '</div>'
        + '<div class="shk-sec-lab">Web Shells (Drop And Browse)</div><div class="shk-pays">' + wsRows + '</div>'
        + '<div class="tb-gloss"><div class="tb-gloss-lab">After You Catch It: Upgrade The TTY</div><pre class="shk-tty">' + tty + '</pre></div>'
        + '</div>';
    }
    function updateCommands() {
      var sp = shellParams(body);
      var em = encMode();
      var pays = SK.payloads(sp.lhost || 'LHOST', sp.lport || '4444');
      var allPaySecs = body.querySelectorAll('.shk-pays');
      if (allPaySecs.length) {
        var pRows = allPaySecs[0].querySelectorAll('.shk-pay');
        pays.forEach(function (p, idx) {
          if (pRows[idx]) {
            var shown = (p.os === 'linux' && em !== 'raw' && SK.encodePayload) ? SK.encodePayload(p.cmd, em) : p.cmd;
            var cEl = pRows[idx].querySelector('.shk-pay-cmd');
            var bEl = pRows[idx].querySelector('.shk-copy');
            if (cEl) cEl.textContent = shown;
            if (bEl) bEl.setAttribute('data-copy', shown);
          }
        });
      }
      var encBtn = body.querySelector('.shk-copyenc');
      if (encBtn) {
        var enc = SK.psEncodedCommand(sp.lhost || 'LHOST', sp.lport || '4444');
        encBtn.setAttribute('data-copy', enc);
      }
      if (allPaySecs.length > 1 && SK.msfvenom) {
        var mvRows = allPaySecs[1].querySelectorAll('.shk-pay');
        var mvs = SK.msfvenom(sp.lhost || 'LHOST', sp.lport || '4444');
        mvs.forEach(function (m, idx) {
          if (mvRows[idx]) {
            var cEl = mvRows[idx].querySelector('.shk-pay-cmd');
            var bEl = mvRows[idx].querySelector('.shk-copy');
            if (cEl) cEl.textContent = m.cmd;
            if (bEl) bEl.setAttribute('data-copy', m.cmd);
          }
        });
      }
    }
    draw();
    U.on(body, 'input', '.shk-lhost', function (e, t) {
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.lhost = t.value.trim(); }, 'params');
      updateCommands();
    });
    U.on(body, 'input', '.shk-lport', function (e, t) {
      OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.lport = t.value.trim(); }, 'params');
      updateCommands();
    });
    U.on(body, 'click', '.shk-encbtn', function (e, t) { OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.shellEnc = t.getAttribute('data-enc'); }, 'shell-enc'); draw(); });
    U.on(body, 'click', '.tb-engine:not(.shk-encbtn)', function (e, t) { if (!t.getAttribute('data-catcher')) return; OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; eng.ui.shellCatcher = t.getAttribute('data-catcher'); }, 'shell-catcher'); draw(); });
    U.on(body, 'click', '.shk-copy, .shk-copyenc', function (e, t) { U.copy(t.getAttribute('data-copy')).then(function (ok) { U.toast(ok ? 'Copied' : 'Copy failed', ok ? '' : 'err'); }); });
    U.on(body, 'click', '.shk-ws-dl', function (e, t) {
      var okd = downloadText(t.getAttribute('data-fn') || 'shell.txt', t.getAttribute('data-code') || '');
      U.toast(okd ? 'Web shell downloaded' : 'Download blocked by the browser', okd ? '' : 'err');
    });
    U.on(body, 'click', '.shk-dl', function () {
      var sp = shellParams(body);
      var cur = ((OBOL.store.active() || {}).ui || {}).shellCatcher || 'nc';
      var kit = SK.listenerKit({ lhost: sp.lhost || 'LHOST', lport: sp.lport || '4444', catcher: cur });
      var okd = downloadText('obol-listener-' + (sp.lport || '4444') + '.sh', kit);
      U.toast(okd ? 'Listener kit downloaded' : 'Download blocked by the browser', okd ? '' : 'err');
    });
  }

  // ================================ render ================================
  // The Grid layout: every surface laid out as expandable cards (stations hero, access kits, then
  // category sections with a sticky jump nav). The scannable, see-everything view.
  function renderGrid(openId, factKinds) {
    var builders = equippedBuilders();
    var html = '';
    var stations = (TK && TK.stations ? TK.stations() : []).filter(function (s) { return TK.stationBuilders(s).length; });
    if (stations.length) {
      html += '<section class="tools-stations"><div class="tools-cat-head"><h2 class="tools-cat-h">Stations</h2><span class="tools-cat-hint">One job, your choice of engine.</span></div>'
        + '<div class="tools-grid">' + stations.map(function (s) { return stationCard(s, openId, factKinds); }).join('') + '</div></section>';
    }
    html += '<section class="tools-stations"><div class="tools-cat-head"><h2 class="tools-cat-h">Access Kits</h2><span class="tools-cat-hint">Downloadable, filled from your engagement. OBOL writes them; you run them.</span></div>'
      + '<div class="tools-grid">' + shellStationCard(openId === 'shell') + (OBOL.pivotStationUI ? OBOL.pivotStationUI.card(openId === 'pivot') : '') + '</div></section>';
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
    return html;
  }
  // The Focus layout: a master-detail workbench. A searchable, grouped tool list on the left; the
  // selected tool's full funnel panel on the right. One tool at a time, no scrolling past the rest.
  function renderFocus(openId, factKinds) {
    var items = focusItems();
    var sel = resolveFocusKey(items, openId, focusSel());
    var selItem = items.filter(function (it) { return it.key === sel; })[0] || items[0];
    // left list, grouped in item order
    var listHtml = '', lastGroup = '';
    items.forEach(function (it) {
      if (it.group !== lastGroup) {
        if (lastGroup) listHtml += '</div>';
        listHtml += '<div class="tfl-group" data-group="' + attr(it.group) + '"><div class="tfl-group-head">' + esc(it.group) + '</div>';
        lastGroup = it.group;
      }
      var on = it.key === sel;
      listHtml += '<button type="button" class="tfl-item ' + esc(it.hue || '') + (on ? ' on' : '') + '" data-focus="' + attr(it.key) + '"'
        + ' data-search="' + attr((it.label + ' ' + (it.sum || '') + ' ' + (it.uses || '')).toLowerCase()) + '" aria-pressed="' + (on ? 'true' : 'false') + '">'
        + '<span class="tfl-item-name">' + esc(it.label) + '</span>'
        + '<span class="tfl-item-sum">' + esc(it.sum || '') + '</span></button>';
    });
    if (lastGroup) listHtml += '</div>';
    var detailHtml = '<div class="tools-focus-detail" data-sel="' + attr(sel) + '">' + focusCardHtml(selItem, factKinds, openId) + '</div>';
    return '<div class="tools-focus-wrap">'
      + '<aside class="tools-focus-list" aria-label="Tool list">'
      + '<div class="tfl-search-wrap"><input type="search" class="tfl-search" placeholder="Search Tools" aria-label="Search tools" spellcheck="false" autocomplete="off">'
      + '<span class="tfl-search-none" hidden>No tool matches.</span></div>'
      + '<div class="tfl-groups">' + listHtml + '</div></aside>'
      + detailHtml + '</div>';
  }
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
      + '<div class="tools-lens" role="group" aria-label="Layout"><button type="button" class="tools-lens-btn' + (lay === 'grid' ? ' on' : '') + '" data-lay="grid" aria-pressed="' + (lay === 'grid' ? 'true' : 'false') + '">Grid</button>'
      + '<button type="button" class="tools-lens-btn' + (lay === 'focus' ? ' on' : '') + '" data-lay="focus" aria-pressed="' + (lay === 'focus' ? 'true' : 'false') + '">Focus</button></div></div>';
    html += '<p class="route-sub">Point and click: the binding bar fills the target, identity, and ports; pick a recipe for a ready command, tune it, copy it. Nothing runs here.</p>';
    html += '<div id="bind-bar"></div>';
    html += (lay === 'focus') ? renderFocus(openId, factKinds) : renderGrid(openId, factKinds);
    html += '</section>';
    return html;
  }

  // ================================ panel mounting ================================
  function collect(form, builder) {
    var out = Object.assign({}, (form && form._panelState) || {});
    (builder.fields || []).forEach(function (f) {
      var el = (form && form.elements) ? form.elements.namedItem(f.id) : null;
      if (!el) return;
      out[f.id] = f.type === 'checkbox' ? !!el.checked : el.value;
      if (form && form._panelState) form._panelState[f.id] = out[f.id];
    });
    return out;
  }
  function applyVisibility(form, builder, values) {
    (builder.fields || []).forEach(function (f) { var row = form.querySelector('[data-field-id="' + f.id + '"]'); if (!row) return; row.hidden = !!(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, values)); });
  }
  function setFormValue(form, builder, fid, val) {
    var f = (builder.fields || []).filter(function (x) { return x.id === fid; })[0]; if (!f) return;
    if (form) {
      form._panelState = form._panelState || {};
      form._panelState[fid] = f.type === 'checkbox' ? truthy(val) : (val == null ? '' : val);
    }
    var el = form && form.elements && form.elements.namedItem(fid); if (!el) return;
    if (f.type === 'checkbox') el.checked = truthy(val); else el.value = (val == null ? '' : val);
  }

  // Fill a builder's empty secret fields from the engagement's effective identity (the one the binding
  // bar points at). The secret is already stored in the credential ledger and shown masked in the bar,
  // so this places the same value into the tool's password/hash field (masked) rather than exposing
  // anything new. It never overwrites a value the operator typed.
  function fillSecrets(builder, values) {
    var id = (OBOL.bind && OBOL.bind.effectiveIdentity) ? OBOL.bind.effectiveIdentity() : null;
    if (!id) return;
    if (!id.secret && id.nthash) {
      var authField = (builder.fields || []).filter(function (f) { return f.id === 'authMode' && f.type === 'select'; })[0];
      if (authField && (authField.options || []).some(function (o) { return o.value === 'ntlm'; })) {
        if (!values.authMode || values.authMode === 'password') {
          values.authMode = 'ntlm';
        }
      }
    }
    (builder.fields || []).forEach(function (f) {
      if (f.type !== 'secret' || (values[f.id] !== undefined && values[f.id] !== '')) return;
      if (f.credentialKind === 'password' && id.secret) values[f.id] = id.secret;
      else if ((f.credentialKind === 'ntlm' || f.credentialKind === 'netntlm') && id.nthash) values[f.id] = id.nthash;
    });
  }

  // Mount the funnel panel for one builder into panelEl (its .tool-body). persistId keys saved values.
  // Pre-pick the hashcat -m / john --format from a captured hash fact, unless the operator already chose a
  // mode by hand (a saved value). Only on a fresh mount (not an engine swap, which carries the type across).
  function crackPrepick(builder, persistId, start) {
    var isHc = builder.id === 'tb-hashcat', isJn = builder.id === 'tb-john';
    if (!isHc && !isJn) return;
    var key = isHc ? 'mode' : 'format';
    var saved = savedValues(persistId);
    if (saved && saved[key] !== undefined && saved[key] !== '') return; // respect an explicit choice
    var kinds = {}; try { kinds = OBOL.store.factSet().kinds() || {}; } catch (e) { return; } // kinds() is an object keyed by fact kind
    for (var i = 0; i < HASH_FACT_MODE.length; i++) {
      if (!kinds[HASH_FACT_MODE[i][0]]) continue;
      var hc = HASH_FACT_MODE[i][1];
      if (isHc) start.mode = hc;
      else { var j = hcModeToJohn(hc); if (j) start.format = normJohn(j); else return; }
      return;
    }
  }

  // compilePreview(builder, values, context) -> a command string with <fieldid> placeholders standing in for
  // every VISIBLE required field the operator has not filled yet, so the command's SHAPE is ALWAYS on screen
  // (never a dead "fill these" line), whatever option they toggle. Thorough by construction: it fills every
  // blank that could block compilation, by kind, so a required credential (<password>), an unset executable
  // selector, or a must-check box can never swallow the preview. Returns null only if even a fully-placeholdered
  // command will not compile (not expected for a valid builder), in which case the caller shows a message.
  // The placeholders carry <>, which is shell-unsafe, so compile() quotes them; we strip that one layer of
  // quoting back off so they read as <user>, not '<user>'. Placeholder-free tokens keep their real quoting.
  function compilePreview(builder, values, context) {
    if (!TB) return null;
    var norm = TB.normalizeValues(builder, values || {}, context);
    var filled = {}; Object.keys(norm).forEach(function (k) { filled[k] = norm[k]; });
    // The executable itself must resolve to a real binary. If it is a selector whose field is blank (or holds a
    // value that is not one of its choices), adopt the first choice, so the shape leads with a real command name,
    // never a <placeholder> in the executable slot.
    var exSel = builder.command && builder.command.executable;
    if (exSel && typeof exSel === 'object' && exSel.field) {
      var ev = filled[exSel.field];
      var known = (exSel.choices || []).some(function (c) { return String(c.value) === String(ev); });
      if (!known && (exSel.choices || []).length) filled[exSel.field] = exSel.choices[0].value;
    }
    (builder.fields || []).forEach(function (f) {
      if (f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm)) return; // only fields actually on screen
      var required = f.required === true || (f.requiredWhen ? TB.conditionMatches(f.requiredWhen, norm) : false);
      if (!required) return;
      var v = filled[f.id];
      var present = !(v === undefined || v === null || v === '');
      if (f.type === 'checkbox') { if (!present && f.mustBeChecked) filled[f.id] = true; return; } // show the flag
      // every other kind (text, number, path, textarea, select, and a SECRET like a password or hash) gets a
      // readable <placeholder>; a secret placeholdered this way shows the operator a credential is needed.
      if (!present) filled[f.id] = '<' + f.id + '>';
    });
    var cmd;
    try { cmd = TB.compile(builder, filled, context); } catch (e) { return null; }
    // unwrap the one layer of shell/Windows quoting the compiler put around any token holding a placeholder:
    // '<user>' -> <user>, "--user=<user>" -> --user=<user>. Only placeholder-bearing tokens are touched.
    return cmd.replace(/(['"])([^'"]*<[a-z0-9_-]+>[^'"]*)\1/gi, '$2');
  }

  function cleanSaved(builder, saved) {
    if (!saved || !builder) return saved || {};
    var out = Object.assign({}, saved);
    (builder.fields || []).forEach(function (f) {
      if (!f || !f.autofill) return;
      var isCtx = false;
      if (typeof f.autofill === 'string') isCtx = /^(target|context)\./.test(f.autofill);
      else if (typeof f.autofill === 'object' && f.autofill) isCtx = f.autofill.from === 'target' || f.autofill.from === 'context';
      if (isCtx) delete out[f.id];
    });
    return out;
  }

  function mountPanel(panelEl, builder, context, persistId, startValues) {
    if (panelEl.parentNode && panelEl._obolMounted) {
      var fresh = panelEl.cloneNode(false);
      panelEl.parentNode.replaceChild(fresh, panelEl);
      panelEl = fresh;
    }
    panelEl._obolMounted = true;
    var saved = cleanSaved(builder, savedValues(persistId), context);
    var start = startValues || Object.assign(TB.defaultsFor(builder, context), saved);
    if (!startValues) crackPrepick(builder, persistId, start);
    fillSecrets(builder, start);
    var secretSet = {}; (builder.fields || []).forEach(function (f) { if (f.type === 'secret') secretSet[f.id] = 1; });
    // Fields that SOME recipe pins (the union of every recipe's value keys). These are "recipe-owned": swapping
    // recipes may legitimately clear one a previous recipe set (e.g. a rule file) so a stale value does not keep
    // matchingRecipe locked on the broader recipe. Every OTHER field (target, username, domain, ports: the
    // engagement identity no recipe touches) is the operator's, and is carried ACROSS a recipe swap untouched,
    // so they never re-type the same thing when hopping protocols and recipes.
    var recipeOwnedFields = {};
    (TK ? TK.recipesFor(builder.id) : []).forEach(function (r) { Object.keys(r.values || {}).forEach(function (k) { recipeOwnedFields[k] = 1; }); });
    var activeRecipe = TK ? TK.matchingRecipe(builder, start) : null;
    panelEl.innerHTML = panelBody(builder, start, activeRecipe);

    var form = panelEl.querySelector('.tb-form');
    if (form) form._panelState = Object.assign({}, start);
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
    // Reflect the stackable Option toggles: each chip's on/off from its checkbox value, and its visibility
    // from visibleWhen against the current state (so the SMB modules hide the moment the operator picks LDAP).
    var fieldsById = {}; (builder.fields || []).forEach(function (f) { fieldsById[f.id] = f; });
    function syncToggleChips(current) {
      var chips = panelEl.querySelectorAll('.tb-tog-chip'); if (!chips.length) return;
      var norm = TB.normalizeValues(builder, current, context);
      for (var i = 0; i < chips.length; i++) {
        var fid = chips[i].getAttribute('data-toggle-field'), f = fieldsById[fid];
        var vis = !(f && f.visibleWhen && !TB.conditionMatches(f.visibleWhen, norm));
        if (!vis && truthy(current[fid])) {
          setFormValue(form, builder, fid, false);
          current[fid] = false;
        }
        chips[i].hidden = !vis;
        var on = vis && truthy(current[fid]);
        chips[i].classList.toggle('on', on); chips[i].setAttribute('aria-pressed', on ? 'true' : 'false');
      }
    }
    function syncRecipeFilter(current) {
      var wrap = panelEl.querySelector('.tb-recipes');
      var tiles = panelEl.querySelectorAll('.tb-recipe');
      if (!wrap || !tiles.length) return;
      var anyVisible = false;
      for (var i = 0; i < tiles.length; i++) {
        var rid = tiles[i].getAttribute('data-recipe');
        var r = TK ? TK.recipeById(builder.id, rid) : null;
        var rvals = (r && r.values) || {};
        var show = true;
        if (rvals.engine && current.engine && rvals.engine !== current.engine) {
          show = false;
        }
        tiles[i].hidden = !show;
        if (show) anyVisible = true;
      }
      var grid = wrap.querySelector('.tb-recipe-grid'); if (grid) grid.hidden = !anyVisible;
      var empty = wrap.querySelector('.tb-recipes-empty'); if (empty) empty.hidden = anyVisible;
    }
    function setEditing(on) { if (!preview) return; preview.classList.toggle('editing', on); if (editBtn) editBtn.textContent = on ? 'done' : 'edit'; if (on && edit) { edit.focus(); } }

    function paintGloss(cmd) { if (glossEl) glossEl.outerHTML = glossHtml(cmd, builder); glossEl = panelEl.querySelector('.tb-gloss'); }
    // state: true = a real, copyable command; 'preview' = the command SHAPE with <placeholder> tokens (shown,
    // glossed, but not copyable); false = a plain message (cmd is the message text). A preview highlights and
    // glosses like a real command so the student sees the whole thing before filling a single field.
    function showCmd(cmd, state) {
      var valid = state === true, preview = state === 'preview', render = valid || preview;
      if (cmdTag && render) { var ex = execOf(cmd); if (ex) cmdTag.textContent = ex; } // reflect the ACTIVE executable
      code.innerHTML = render ? highlight(cmd) : esc(cmd);
      code.setAttribute('data-valid', valid ? 'true' : 'false');
      code.setAttribute('data-preview', preview ? 'true' : 'false');
      if (valid) code.setAttribute('data-cmd', cmd); else code.removeAttribute('data-cmd');
      if (edit && document.activeElement !== edit) edit.value = render ? cmd : '';
      paintGloss(render ? cmd : '');
    }
    function recompile(save) {
      var current = collect(form, builder);
      syncToggleChips(current);
      var norm = TB.normalizeValues(builder, current, context);
      applyVisibility(form, builder, norm);
      var activeId = TK ? TK.matchingRecipe(builder, norm) : null;
      // reflect active recipe tile
      var tiles = panelEl.querySelectorAll('.tb-recipe');
      for (var ti = 0; ti < tiles.length; ti++) { var on = tiles[ti].getAttribute('data-recipe') === activeId; tiles[ti].classList.toggle('selected', on); tiles[ti].classList.toggle('is-glow', on); tiles[ti].setAttribute('aria-pressed', on ? 'true' : 'false'); }
      if (liveName) liveName.textContent = activeId ? (TK.recipeById(builder.id, activeId) || {}).label || '' : 'custom';
      edited = false;
      syncModeChips(norm);
      syncRecipeFilter(norm);
      renderNeeds(current);
      try { showCmd(TB.compile(builder, current, context), true); }
      catch (err) {
        // Not yet runnable (a required field is blank). Show the command SHAPE with <placeholder> tokens so the
        // student sees what they are building before they fill anything; fall back to a message only if even the
        // placeholdered command cannot compile (e.g. no executable selected).
        var pv = compilePreview(builder, current, context);
        if (pv) showCmd(pv, 'preview');
        else { var missing = TB.validateRequired(builder, norm); showCmd(missing.length ? ('Fill the ' + missing.length + ' required field' + (missing.length > 1 ? 's' : '') + ' below to build this command.') : 'Complete the required fields to generate a command.', false); }
      }
      // select option descriptions
      var sels = form.querySelectorAll('select');
      for (var si = 0; si < sels.length; si++) { var sel = sels[si], note = sel.parentNode && sel.parentNode.querySelector('.tb-optdesc'); if (!note) continue; var opt = sel.options[sel.selectedIndex]; note.textContent = (opt && opt.getAttribute('data-desc')) || ''; }
      if (save) {
        var pv = {};
        (builder.fields || []).forEach(function (f) {
          if (secretSet[f.id]) return;
          var v = current[f.id];
          if (v === undefined) return;
          if (f.autofill) {
            var isCtx = false;
            if (typeof f.autofill === 'string') isCtx = /^(target|context)\./.test(f.autofill);
            else if (typeof f.autofill === 'object' && f.autofill) isCtx = f.autofill.from === 'target' || f.autofill.from === 'context';
            if (isCtx) return;
          }
          pv[f.id] = v;
        });
        persistValues(persistId, pv);
      }
    }

    form.addEventListener('input', function () { recompile(true); });
    form.addEventListener('change', function () { recompile(true); });

    // "Find A Switch" palette: type to filter All Options down to the matching switches, so a specific
    // flag is one search away instead of a scan. A group with no visible row collapses; empty shows a note.
    var optFilter = panelEl.querySelector('.tb-optfilter');
    if (optFilter) {
      optFilter.addEventListener('input', function () {
        var q = String(optFilter.value || '').trim().toLowerCase();
        var rows = form.querySelectorAll('.tb-field'), any = false;
        for (var i = 0; i < rows.length; i++) { var r = rows[i]; var hit = !q || (r.getAttribute('data-filter') || '').indexOf(q) >= 0; r.classList.toggle('tb-filter-hide', !hit); if (hit && !r.hidden) any = true; }
        var groups = form.querySelectorAll('.tb-group');
        for (var g = 0; g < groups.length; g++) { groups[g].classList.toggle('tb-filter-hide', !!q && !groups[g].querySelector('.tb-field:not(.tb-filter-hide)')); }
        var none = panelEl.querySelector('.tb-optfind-none'); if (none) none.hidden = any || !q;
      });
    }

    // Prominent mode chips at the top: set the primary field and rebuild (also mirrors into All Switches).
    U.on(panelEl, 'click', '.tb-mode-chip', function (e, t) {
      setFormValue(form, builder, t.getAttribute('data-mode-field'), t.getAttribute('data-mode-value'));
      recompile(true);
    });
    // Stackable Option toggles: flip the underlying checkbox on/off and rebuild. Independent of every other
    // toggle, so the operator composes as many as apply (the command stays valid by construction).
    U.on(panelEl, 'click', '.tb-tog-chip', function (e, t) {
      var fid = t.getAttribute('data-toggle-field');
      setFormValue(form, builder, fid, !truthy(collect(form, builder)[fid]));
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
        if (!v || v.length < 8 || /\s/.test(v)) return; // blank, too short, or whitespace: not a single hash
        // A slash/backslash usually means a filesystem path, NOT a hash, EXCEPT a structured hash that starts
        // with '$' (a Kerberoast $krb5tgs$ carries the SPN, e.g. MSSQLSvc/dc01:1433, with slashes).
        if (v.charAt(0) !== '$' && (v.indexOf('/') >= 0 || v.indexOf('\\') >= 0)) return;
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

    // Identify A Hash (Crack Hashes hero): paste ONE sample hash, obol cleans up the common lab formatting
    // pitfalls (wrapped Rubeus ticket, secretsdump line, quotes, log prefix), names it, and lets you set the
    // -m mode (john format) with one tap. Reuses the Workbench engine (identifyHash + normalizeHash), so the
    // two surfaces stay identical. The cleaned value can also be dropped straight into the hashes field.
    (function () {
      if (!OBOL.workbench || !OBOL.workbench.identifyHash || !OBOL.workbench.normalizeHash) return;
      var isHc = builder.id === 'tb-hashcat', isJn = builder.id === 'tb-john';
      if (!isHc && !isJn) return;
      var modeEl = form.elements && form.elements.namedItem(isHc ? 'mode' : 'format');
      var fileEl = form.elements && form.elements.namedItem(isHc ? 'hashOrFile' : 'hashFile');
      if (!modeEl || modeEl.tagName !== 'SELECT') return;
      function modeHasOpt(v) { for (var i = 0; i < modeEl.options.length; i++) if (modeEl.options[i].value === String(v)) return true; return false; }
      var panel = document.createElement('div');
      panel.className = 'tb-hashid';
      panel.innerHTML = '<div class="tb-hashid-h">Identify A Hash <span class="tb-recipes-sub">paste one sample; OBOL names it, cleans it, sets the mode</span></div>'
        + '<textarea class="tb-hashid-in" rows="2" placeholder="Paste one hash (a wrapped Rubeus ticket or a full secretsdump line is fine)" autocomplete="off" spellcheck="false"></textarea>'
        + '<div class="tb-hashid-out" aria-live="polite"></div>';
      var pv = panelEl.querySelector('.tb-preview');
      if (pv && pv.parentNode) pv.parentNode.insertBefore(panel, pv); else panelEl.querySelector('.tb-panel').appendChild(panel);
      var inEl = panel.querySelector('.tb-hashid-in'), outEl = panel.querySelector('.tb-hashid-out');
      function render() {
        var W = OBOL.workbench, v = String(inEl.value || '');
        if (!v.trim()) { outEl.innerHTML = ''; return; }
        var nz = W.normalizeHash(v);
        var banner = '';
        if (nz.changed && nz.cleaned && nz.cleaned !== v.trim()) {
          // hashcat takes a literal hash on the command line, so "use as hash" fills the hash field. john
          // reads hashes from a FILE only (a literal positional arg is treated as a path and fails), so for
          // john offer "copy" and a note to save it to a file rather than filling a path field with a literal.
          var cleanBtn = isHc
            ? '<button type="button" class="btn-copy tb-hashid-fill" data-clean="' + attr(nz.cleaned) + '">use as hash</button>'
            : '<button type="button" class="btn-copy tb-hashid-copy" data-clean="' + attr(nz.cleaned) + '">copy</button>';
          banner = '<div class="wb-clean"><div class="wb-clean-h">Cleaned For Cracking</div><ul class="wb-clean-list">'
            + nz.changes.map(function (c) { return '<li>' + esc(c) + '</li>'; }).join('') + '</ul>'
            + '<div class="wb-cmd"><code>' + esc(nz.cleaned) + '</code>' + cleanBtn + '</div>'
            + (isJn ? '<p class="tb-hint">john reads hashes from a file: save this into your hashes file, then point john at it.</p>' : '')
            + '</div>';
        }
        var r = W.identifyHash(nz.cleaned);
        if (!r.candidates.length) { outEl.innerHTML = banner + '<p class="tb-hint">' + esc(r.note || 'No confident match.') + '</p>'; return; }
        var cards = r.candidates.map(function (c, i) {
          var act;
          if (isHc) act = (c.mode != null && modeHasOpt(c.mode)) ? '<button type="button" class="tb-hashid-use" data-mode="' + esc(c.mode) + '">Use -m ' + esc(c.mode) + '</button>'
            : (c.mode != null ? '<span class="tb-hint">hashcat -m ' + esc(c.mode) + ' (not in this tool)</span>' : '<span class="tb-hint">no hashcat mode, use john</span>');
          else { var jf = normJohn(c.john); act = (jf && modeHasOpt(jf)) ? '<button type="button" class="tb-hashid-use" data-mode="' + esc(jf) + '">Use ' + esc(jf) + '</button>' : (c.john ? '<span class="tb-hint">john: ' + esc(c.john) + '</span>' : ''); }
          return '<div class="tb-hashid-cand' + (i === 0 ? ' top' : '') + '"><div class="tb-hashid-cn">'
            + (i === 0 ? '<span class="tb-hashid-top">Most Likely</span>' : '') + '<span class="tb-hashid-name">' + esc(c.name) + '</span></div>'
            + (c.note ? '<p class="tb-hint">' + esc(c.note) + '</p>' : '') + '<div class="tb-hashid-act">' + act + '</div></div>';
        }).join('');
        outEl.innerHTML = banner + cards;
      }
      inEl.addEventListener('input', render);
      U.on(panel, 'click', '.tb-hashid-use', function (e, t) {
        modeEl.value = t.getAttribute('data-mode'); recompile(true);
        if (liveName) liveName.textContent = 'identified';
        if (U.toast) U.toast('Mode set to ' + t.getAttribute('data-mode'), '');
      });
      U.on(panel, 'click', '.tb-hashid-fill', function (e, t) {
        if (fileEl) { fileEl.value = t.getAttribute('data-clean') || ''; recompile(true); if (U.toast) U.toast('Cleaned hash set', ''); }
      });
      U.on(panel, 'click', '.tb-hashid-copy', function (e, t) {
        U.copy(t.getAttribute('data-clean') || '').then(function (ok) { if (U.toast) U.toast(ok ? 'Cleaned hash copied' : 'Copy failed', ok ? '' : 'err'); });
      });
    })();

    // recipe tile: apply the preset to the form, then recompile
    U.on(panelEl, 'click', '.tb-recipe', function (e, t) {
      var rid = t.getAttribute('data-recipe');
      var recipe = TK.recipeById(builder.id, rid); if (!recipe) return;
      var rvals = (recipe.values) || {};
      // Apply the recipe WITHOUT wiping what the operator already typed. For each non-secret field:
      //   - the recipe pins it            -> set it to the recipe value;
      //   - a DIFFERENT recipe owns it     -> clear it, so a stale pin (e.g. a rule file from "NTLM + Rules")
      //                                       does not keep matchingRecipe locked on the broader recipe;
      //   - no recipe owns it (identity)   -> LEAVE IT, so target / username / domain / ports carry across
      //                                       the swap and are never re-typed.
      (builder.fields || []).forEach(function (f) {
        if (f.type === 'secret') return; // never clobber a typed credential
        if (Object.prototype.hasOwnProperty.call(rvals, f.id)) setFormValue(form, builder, f.id, rvals[f.id]);
        else if (recipeOwnedFields[f.id]) {
          var def = (builder.defaults && builder.defaults[f.id] !== undefined) ? builder.defaults[f.id] : (f.default !== undefined ? f.default : (f.type === 'checkbox' ? false : ''));
          setFormValue(form, builder, f.id, def);
        }
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
    var openId = (ctx.args && ctx.args[0]) ? decodeURIComponent(ctx.args[0]).toLowerCase() : '';
    // Deep-link selector (#/tools/<tool>/<sel>): a recipe id, a protocol/mode value, or a hashcat/john mode.
    var selArg = (ctx.args && ctx.args[1]) ? decodeURIComponent(ctx.args[1]) : '';
    // If the deep link named a station engine builder (hashcat/ffuf/...), switch the station to it before
    // the selector lands. Clicking the engine chip reuses the panel's own swap (which re-mounts the body).
    function applyStationEngine(card) {
      if (!card || !openId || !card.classList.contains('station-card')) return;
      var active = card.getAttribute('data-active-engine');
      var chips = card.querySelectorAll('.tb-engine');
      for (var i = 0; i < chips.length; i++) {
        var engId = chips[i].getAttribute('data-engine');
        var b = builderById(engId);
        var match = engId === openId || (b && (b.tool === openId || (b.equips || []).indexOf(openId) !== -1));
        if (match) {
          if (active !== engId) chips[i].click();
          return;
        }
      }
    }

    // Apply the deep-link selector to a freshly mounted tool card: pick the recipe tile (which also sets
    // its protocol), else the protocol/mode chip, else the mode/format select. Clicking reuses the panel's
    // own handlers, so the command rebuilds exactly as if the operator chose it.
    function applyToolSelector(card, sel) {
      if (!card || !sel) return;
      // Composition tools (nxc) map the old recipe-id selectors to a protocol + the module toggle(s) to turn
      // on, so "Build In Tools" lands on exactly that switch, now stackable with others.
      var b = builderById(card.getAttribute('data-tool-id')) || builderById(card.getAttribute('data-active-engine'));
      var alias = b && b.selectorAliases && b.selectorAliases[sel];
      if (alias) {
        if (alias.protocol) { var mc = card.querySelector('.tb-mode-chip[data-mode-value="' + alias.protocol + '"]'); if (mc) mc.click(); }
        (alias.on || []).forEach(function (fid) { var tc = card.querySelector('.tb-tog-chip[data-toggle-field="' + fid + '"]'); if (tc && tc.getAttribute('aria-pressed') !== 'true') tc.click(); });
        return;
      }
      var tiles = card.querySelectorAll('.tb-recipe');
      for (var i = 0; i < tiles.length; i++) { if (tiles[i].getAttribute('data-recipe') === sel) { tiles[i].click(); return; } }
      var chips = card.querySelectorAll('.tb-mode-chip');
      for (var j = 0; j < chips.length; j++) { if (chips[j].getAttribute('data-mode-value') === sel) { chips[j].click(); return; } }
      var selects = card.querySelectorAll('select[name="mode"], select[name="format"]');
      for (var k = 0; k < selects.length; k++) { var s = selects[k]; for (var o = 0; o < s.options.length; o++) { if (s.options[o].value === sel) { s.value = sel; try { s.dispatchEvent(new Event('change', { bubbles: true })); } catch (e) {} return; } } }
    }

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
      if (!card) return;
      // In the Focus detail pane the selected tool is always expanded (the left list is the selector),
      // so a head click there is a no-op rather than a collapse.
      if (card.closest('.tools-focus-detail')) return;
      var head = card.querySelector('.tool-card-head');
      var open = card.classList.toggle('open');
      if (head) head.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) mountCardBody(card);
    }

    // Focus Lens: swap the detail pane to the picked tool, mount it, mark the list row active.
    function selectFocus(key) {
      var detail = mount.querySelector('.tools-focus-detail'); if (!detail) return;
      setFocusSel(key);
      var rows = mount.querySelectorAll('.tfl-item');
      for (var i = 0; i < rows.length; i++) { var on = rows[i].getAttribute('data-focus') === key; rows[i].classList.toggle('on', on); rows[i].setAttribute('aria-pressed', on ? 'true' : 'false'); }
      var item = focusItems().filter(function (it) { return it.key === key; })[0]; if (!item) return;
      var fk = []; try { fk = OBOL.store.factSet().kinds(); } catch (e) {}
      detail.setAttribute('data-sel', key);
      detail.innerHTML = focusCardHtml(item, fk);
      var card = detail.querySelector('.tool-card'); if (card) { card.classList.add('open'); mountCardBody(card); }
    }
    function filterFocusList(q) {
      q = String(q || '').trim().toLowerCase();
      var rows = mount.querySelectorAll('.tfl-item'), anyAll = false;
      for (var i = 0; i < rows.length; i++) { var hit = !q || (rows[i].getAttribute('data-search') || '').indexOf(q) >= 0; rows[i].hidden = !hit; if (hit) anyAll = true; }
      var groups = mount.querySelectorAll('.tfl-group');
      for (var g = 0; g < groups.length; g++) { groups[g].hidden = !groups[g].querySelector('.tfl-item:not([hidden])'); }
      var none = mount.querySelector('.tfl-search-none'); if (none) none.hidden = anyAll;
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
      var fromBuilder = builderById(fromId), liveForm = card.querySelector('.tb-form');
      var fromVals = (liveForm && fromBuilder) ? collect(liveForm, fromBuilder) : savedValues('station:' + st.id + ':' + fromId);
      var carried = TK.carryShared(st, fromEng, toEng, fromVals);
      // Carry the hash TYPE across the engine swap too (hashcat -m <-> john --format), so switching
      // engines on a kerberoast hash does not silently reset to NTLM.
      if (fromId === 'tb-hashcat' && toId === 'tb-john') { var jf = hcModeToJohn(fromVals.mode); if (jf) carried.format = normJohn(jf); }
      else if (fromId === 'tb-john' && toId === 'tb-hashcat') { var hm = johnFormatToHc(fromVals.format); if (hm) carried.mode = hm; }
      setStationEngine(st.id, toId);
      card.setAttribute('data-active-engine', toId);
      // update engine chip states + teach line
      var chips = card.querySelectorAll('.tb-engine');
      for (var i = 0; i < chips.length; i++) chips[i].classList.toggle('on', chips[i].getAttribute('data-engine') === toId);
      var teachEl = card.querySelector('.tb-engine-teach'); if (teachEl && toEng) teachEl.textContent = toEng.teach;
      var toBuilder = builderById(toId); if (!toBuilder) return;
      var toPersist = 'station:' + st.id + ':' + toId;
      var saved = cleanSaved(toBuilder, savedValues(toPersist), context);
      var start = Object.assign(TB.defaultsFor(toBuilder, context), saved, carried);
      if (carried.mode === undefined && carried.format === undefined) crackPrepick(toBuilder, toPersist, start);
      mountPanel(card.querySelector('.tool-body'), toBuilder, context, toPersist, start);
    });

    // Focus Lens: list selection + search
    U.on(mount, 'click', '.tfl-item', function (e, t) { selectFocus(t.getAttribute('data-focus')); });
    U.on(mount, 'input', '.tfl-search', function (e, t) { filterFocusList(t.value); });

    // layout lens
    U.on(mount, 'click', '.tools-lens-btn', function (e, t) {
      setLayout(t.getAttribute('data-lay')); OBOL.router.render();
      // start the switched layout at the top, not wherever the previous layout was scrolled (the scroller is
      // #view on desktop, the window on mobile, so reset both).
      var v = document.getElementById('view'); if (v) { try { v.scrollTo({ top: 0 }); } catch (_e) { v.scrollTop = 0; } }
      try { window.scrollTo(0, 0); } catch (_e2) {}
    });
    // category jump
    U.on(mount, 'click', '.tools-jump', function (e, t) {
      var cat = t.getAttribute('data-cat');
      if (cat === '__top__') { var v = document.getElementById('view') || mount; try { v.scrollTo({ top: 0, behavior: 'smooth' }); } catch (_e) { v.scrollTop = 0; } return; }
      var el = document.getElementById(cat); if (el) { try { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_e) { el.scrollIntoView(); } }
    });

    // any card pre-opened (deep link) mounts now, then the deep-link selector is applied to the first one.
    // Only scroll to it for a GRID deep link (openId): in Focus the detail pane is already at the top, and
    // scrolling a short detail card into view would jump the page down (the whole header sits above it).
    var opened = mount.querySelectorAll('.tool-card.open');
    for (var k = 0; k < opened.length; k++) {
      var c = opened[k]; var h = c.querySelector('.tool-card-head'); if (h) h.setAttribute('aria-expanded', 'true'); mountCardBody(c);
      if (k === 0) {
        if (openId && !c.closest('.tools-focus-detail')) { try { c.scrollIntoView({ block: 'start' }); } catch (e) {} }
        applyStationEngine(c); applyToolSelector(c, selArg);
      }
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.tools = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
