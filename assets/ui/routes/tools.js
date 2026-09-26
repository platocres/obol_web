/*!
 * obol ui — routes/tools.js — THE TOOLS SURFACE.
 * Robust command BUILDERS for exactly the tools obol-local is prepared to equip. Every builder
 * in OBOL.TOOLSET whose equips[] intersects OBOL.packs.equippedTools() is shown, grouped by
 * category, as an expandable card. Expanding mounts a grouped form (presets, snippets, credential
 * modes) with a live command preview compiled by OBOL.toolbuilder.compile — autofilled from the
 * engagement params + proven facts (via OBOL.command.buildContext). Field values persist under
 * engagement.ui.tools[toolId]. Nothing executes: the surface only generates copy-ready text.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  var TB = OBOL.toolbuilder;
  function esc(s) { return U.esc(s); }
  function truthy(v) { return TB.truthy(v); }

  var CATS = [
    { id: 'web', label: 'Web', hint: 'Content discovery, fingerprinting, request testing.' },
    { id: 'credentials', label: 'Credentials', hint: 'Validation, spraying, roasting, cracking, capture.' },
    { id: 'ad', label: 'Active Directory', hint: 'LDAP, Kerberos, AD CS, graph collection.' },
    { id: 'remote-exec', label: 'Remote exec', hint: 'Authenticated shells and command execution.' },
    { id: 'pivot', label: 'Pivot', hint: 'Tunnels, SOCKS, port forwarding.' },
    { id: 'enum', label: 'Enumeration', hint: 'Scanning, SMB/RPC/SNMP surface mapping.' },
    { id: 'privesc', label: 'Privilege escalation', hint: 'Local enumeration helpers.' },
    { id: 'shells', label: 'Shells & transfer', hint: 'Payloads, listeners, file transfer.' },
  ];

  // ---- equipped scoping ----
  function equippedSet() {
    var set = {};
    try { OBOL.packs.equippedTools().forEach(function (t) { set[t] = true; }); } catch (e) {}
    return set;
  }
  function toolset() { return (OBOL.TOOLSET || []).slice(); }
  function isEquipped(builder, equipped) {
    return (builder.equips || []).some(function (t) { return equipped[t]; });
  }
  function equippedBuilders() {
    var equipped = equippedSet();
    return toolset().filter(function (b) { return isEquipped(b, equipped); });
  }

  // ---- autofill context (nested keys the builders' `autofill` reads) ----
  function toolContext() {
    var eng = OBOL.store.active();
    var params = (eng && eng.params) || {};
    var facts;
    try { facts = OBOL.store.factSet(); } catch (e) { facts = new OBOL.facts.FactSet([]); }
    var ctx = {};
    try { ctx = OBOL.command.buildContext(facts, { params: params }); } catch (e) { ctx = {}; }
    var target = (ctx.target && ctx.target !== '<target>') ? ctx.target : (params.target || params.rhost || '');
    return {
      target: { value: target, ip: params.rhost || params.ip || target, hostname: params.hostname || ctx.dc || '' },
      context: { domain: ctx.domain || params.domain || '', username: ctx.user || params.username || '', port: params.port || '' },
      workspace: {
        wordlist: params.wordlist || '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt',
        outputDir: params.outputDir || 'loot',
        hashfile: params.hashfile || 'hashes.txt',
      },
    };
  }

  // ---- per-tool value persistence ----
  function savedValues(toolId) {
    var eng = OBOL.store.active();
    var tools = (eng && eng.ui && eng.ui.tools) || {};
    return Object.assign({}, tools[toolId] || {});
  }
  function persistValues(toolId, values) {
    OBOL.store.update(function (eng) {
      eng.ui = eng.ui || {};
      eng.ui.tools = eng.ui.tools || {};
      eng.ui.tools[toolId] = values;
    }, 'tool-values');
  }

  // ================================ form rendering ================================
  function fieldControl(builder, field, value) {
    var id = 'tb-' + builder.id + '-' + field.id;
    var common = ' id="' + esc(id) + '" name="' + esc(field.id) + '" data-tb-field="' + esc(field.id) + '"' + (field.required ? ' required' : '');
    var help = field.help ? '<small class="tb-hint">' + esc(field.help) + '</small>' : '';
    if (field.type === 'checkbox') {
      return '<label class="tb-check"><input type="checkbox"' + common + (truthy(value) ? ' checked' : '') + '> <span>' + esc(field.label) + '</span></label>' + help;
    }
    if (field.type === 'select') {
      var anyDesc = false;
      var opts = (field.options || []).map(function (o) {
        if (o.description) anyDesc = true;
        return '<option value="' + esc(o.value) + '"' + (String(o.value) === String(value) ? ' selected' : '')
          + (o.description ? ' data-desc="' + esc(o.description) + '" title="' + esc(o.description) + '"' : '') + '>' + esc(o.label) + '</option>';
      }).join('');
      // A live description line under the select mirrors the hovered/selected option's `description`
      // (native <option> tooltips are unreliable) — updated in refresh().
      var optDesc = anyDesc ? '<small class="tb-hint tb-optdesc" data-optdesc-for="' + esc(field.id) + '"></small>' : '';
      return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><select' + common + '>' + opts + '</select>' + optDesc + help;
    }
    if (field.type === 'textarea') {
      return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><textarea' + common + (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '') + ' rows="3">' + esc(value == null ? '' : value) + '</textarea>' + help;
    }
    var inputType = field.type === 'secret' ? 'password' : (field.type === 'number' ? 'number' : 'text');
    return '<label for="' + esc(id) + '">' + esc(field.label) + '</label><input type="' + inputType + '"' + common + ' value="' + esc(value == null ? '' : value) + '"' + (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : '') + ' autocomplete="' + (field.type === 'secret' ? 'off' : 'on') + '">' + help;
  }
  function presetsHtml(field) {
    var presets = Array.isArray(field.presets) ? field.presets : [];
    if (!presets.length) return '';
    return '<div class="tb-chips">' + presets.map(function (p) {
      var spd = p.speed ? '<span class="tb-spd ' + esc(p.speed) + '">' + esc(p.speed) + '</span>' : '';
      return '<button type="button" class="tb-chip" data-preset-field="' + esc(field.id) + '" data-preset-value="' + esc(p.value) + '">' + spd + esc(p.label) + '</button>';
    }).join('') + '</div>';
  }
  function snippetsHtml(field) {
    var snippets = Array.isArray(field.snippets) ? field.snippets : [];
    if (!snippets.length) return '';
    return '<div class="tb-chips">' + snippets.map(function (s) {
      return '<button type="button" class="tb-chip" data-snippet-field="' + esc(field.id) + '" data-snippet-value="' + esc(s.value) + '">' + esc(s.label) + '</button>';
    }).join('') + '</div>';
  }
  function fieldRow(builder, field, values) {
    var hidden = field.visibleWhen && !TB.conditionMatches(field.visibleWhen, values);
    var wide = field.type === 'textarea' ? ' tb-wide' : '';
    return '<div class="tb-field' + wide + '" data-field-id="' + esc(field.id) + '"' + (hidden ? ' hidden' : '') + '>'
      + fieldControl(builder, field, values[field.id]) + snippetsHtml(field) + presetsHtml(field) + '</div>';
  }
  function groupsFor(builder) {
    var fields = (builder.fields || []);
    var byId = {}; fields.forEach(function (f) { byId[f.id] = f; });
    if (Array.isArray(builder.fieldGroups) && builder.fieldGroups.length) {
      var claimed = {};
      var groups = builder.fieldGroups.map(function (g) {
        return { title: g.title, description: g.description, fields: (g.fields || []).map(function (id) { claimed[id] = true; return byId[id]; }).filter(Boolean) };
      }).filter(function (g) { return g.fields.length; });
      var leftovers = fields.filter(function (f) { return !claimed[f.id]; });
      if (leftovers.length) groups.push({ title: 'More options', description: 'Additional flags and output controls.', fields: leftovers });
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
  function highlight(cmd) {
    return String(cmd).split(' ').map(function (tok, i) {
      if (tok === '') return '';
      var cls = i === 0 ? 'tb-exe' : (/^-/.test(tok) ? 'tb-flag' : 'tb-arg');
      if (/FUZZ/.test(tok)) return tok.split(/(FUZZ)/).map(function (part) { return part === 'FUZZ' ? '<span class="tb-fuzz">FUZZ</span>' : (part ? '<span class="' + cls + '">' + esc(part) + '</span>' : ''); }).join('');
      return '<span class="' + cls + '">' + esc(tok) + '</span>';
    }).join(' ');
  }
  function proofHtml(builder) {
    var e = builder.evidence || {}, m = builder.manualOutcome || {};
    return '<details class="tb-proof"><summary>Evidence &amp; report boundary</summary>'
      + '<p class="tb-hint"><b>Expected Evidence:</b> ' + esc(e.expectation) + '</p>'
      + '<p class="tb-hint"><b>Proof boundary:</b> ' + esc(e.proofBoundary) + '</p>'
      + '<p class="tb-hint"><b>Manual outcome:</b> ' + esc(m.boundary) + '</p></details>';
  }

  // full builder body (mounted lazily on first expand)
  function bodyHtml(builder, values) {
    return '<div class="tb-preview cmd"><div class="cmd-head"><span class="cmd-tag">' + esc((builder.equips && builder.equips[0]) || builder.tool) + '</span>'
      + '<span class="cmd-variant">generated command</span>'
      + '<button type="button" class="btn-copy tb-copy" title="Copy command">copy</button></div>'
      + '<pre class="cmd-run"><code class="tb-code"></code></pre></div>'
      + formHtml(builder, values)
      + proofHtml(builder)
      + '<p class="tb-foot">Obol builds the minimal valid command from the controls you set and never executes it. Review and run it yourself in an authorized environment, then paste the output into Evidence.</p>';
  }

  // ================================ render ================================
  function toolCard(builder, openId) {
    var open = builder.id === openId || builder.tool === openId || (builder.equips || []).indexOf(openId) !== -1;
    var equipsChips = (builder.equips || []).slice(0, 4).map(function (t) { return '<span class="pill">' + esc(t) + '</span>'; }).join('');
    var cred = (builder.credentialModes && builder.credentialModes.length) ? '<span class="pill tb-cred">' + esc(builder.credentialModes.join(' / ')) + '</span>' : '';
    // The head is a role=button div (not a real <button>) so it can validly contain the
    // title/summary blocks; the tag pills live OUTSIDE it, so clicking a tag never toggles the card.
    return '<article class="tool-card' + (open ? ' open' : '') + '" data-tool-id="' + esc(builder.id) + '">'
      + '<div class="tool-card-head" role="button" tabindex="0" aria-expanded="' + (open ? 'true' : 'false') + '">'
      + '<div class="tool-card-title"><span class="tool-card-name">' + esc(builder.title) + '</span>'
      + '<span class="tool-card-exec">' + esc(builder.executionContext || 'any') + '</span>'
      + '<span class="tool-card-chev" aria-hidden="true">▾</span></div>'
      + '<p class="tool-card-sum">' + esc(builder.summary) + '</p></div>'
      + '<div class="tool-card-tags">' + equipsChips + cred + '</div>'
      + '<div class="tool-body"></div></article>';
  }

  function render(ctx) {
    var builders = equippedBuilders();
    var openId = (ctx.args && ctx.args[0]) ? decodeURIComponent(ctx.args[0]).toLowerCase() : '';

    if (!builders.length) {
      return '<section class="tools-route"><h1 class="route-h1">Tools</h1>'
        + '<p class="route-sub">No equipped tools resolved yet. Load a methodology pack (the equipped-tool set is the union of every pack action\'s tools) and the matching builders appear here.</p></section>';
    }

    var byCat = {};
    builders.forEach(function (b) { (byCat[b.category] = byCat[b.category] || []).push(b); });
    Object.keys(byCat).forEach(function (c) { byCat[c].sort(function (a, b) { return a.title.localeCompare(b.title); }); });

    var html = '<section class="tools-route">';
    html += '<h1 class="route-h1">Tools</h1>';
    html += '<p class="route-sub">Command builders for the ' + builders.length + ' equipped tools obol-local carries. Pick a tool, tune the controls, and copy the generated command — it is never executed here. Fields autofill from your engagement params and proven facts.</p>';

    // category jump nav
    var present = CATS.filter(function (c) { return byCat[c.id] && byCat[c.id].length; });
    // Buttons, not <a href="#…"> — a bare hash is misread by the hash router as a route and
    // bounces the user to the default screen. These scroll to the category in mounted().
    html += '<nav class="tools-nav">' + present.map(function (c) {
      return '<button type="button" class="pill tools-jump" data-cat="tb-cat-' + esc(c.id) + '">' + esc(c.label) + ' <b>' + byCat[c.id].length + '</b></button>';
    }).join('') + '</nav>';

    present.forEach(function (c) {
      html += '<section class="tools-cat" id="tb-cat-' + esc(c.id) + '">'
        + '<div class="tools-cat-head"><h2 class="tools-cat-h">' + esc(c.label) + '</h2><span class="tools-cat-hint">' + esc(c.hint) + '</span></div>'
        + '<div class="tools-grid">' + byCat[c.id].map(function (b) { return toolCard(b, openId); }).join('') + '</div></section>';
    });

    html += '</section>';
    return html;
  }

  // ================================ mounted / interactivity ================================
  function builderById(id) { return equippedBuilders().filter(function (b) { return b.id === id; })[0] || null; }

  function collect(form, builder) {
    var out = {};
    (builder.fields || []).forEach(function (f) {
      var el = form.elements ? form.elements.namedItem(f.id) : null;
      if (!el) return;
      out[f.id] = f.type === 'checkbox' ? !!el.checked : el.value;
    });
    return out;
  }
  function applyVisibility(form, builder, values) {
    (builder.fields || []).forEach(function (f) {
      var row = form.querySelector('[data-field-id="' + f.id + '"]');
      if (!row) return;
      row.hidden = !!(f.visibleWhen && !TB.conditionMatches(f.visibleWhen, values));
    });
  }

  function mountBuilder(card, builder, context) {
    var bodyEl = card.querySelector('.tool-body');
    if (!bodyEl || bodyEl.getAttribute('data-mounted') === '1') return;
    var start = Object.assign(TB.defaultsFor(builder, context), savedValues(builder.id));
    bodyEl.innerHTML = bodyHtml(builder, start);
    bodyEl.setAttribute('data-mounted', '1');

    var form = bodyEl.querySelector('.tb-form');
    var code = bodyEl.querySelector('.tb-code');
    var copyBtn = bodyEl.querySelector('.tb-copy');

    function refresh(save) {
      var current = collect(form, builder);
      applyVisibility(form, builder, TB.normalizeValues(builder, current, context));
      try {
        var cmd = TB.compile(builder, current, context);
        code.setAttribute('data-valid', 'true');
        code.innerHTML = highlight(cmd);
        code.setAttribute('data-cmd', cmd);
      } catch (err) {
        code.setAttribute('data-valid', 'false');
        var missing = TB.validateRequired(builder, TB.normalizeValues(builder, current, context));
        code.textContent = missing.length ? ('Set required: ' + missing.join(', ')) : 'Complete the required fields to generate a command.';
        code.removeAttribute('data-cmd');
      }
      // Mirror each select's chosen option description into its live description line.
      var sels = form.querySelectorAll('select');
      for (var si = 0; si < sels.length; si++) {
        var sel = sels[si];
        var note = sel.parentNode && sel.parentNode.querySelector('.tb-optdesc');
        if (!note) continue;
        var opt = sel.options[sel.selectedIndex];
        note.textContent = (opt && opt.getAttribute('data-desc')) || '';
      }
      if (save) persistValues(builder.id, current);
    }

    form.addEventListener('input', function () { refresh(true); });
    form.addEventListener('change', function () { refresh(true); });

    // presets: set a field value
    U.on(bodyEl, 'click', '[data-preset-field]', function (e, t) {
      var el = form.elements && form.elements.namedItem(t.getAttribute('data-preset-field'));
      if (!el) return;
      el.value = t.getAttribute('data-preset-value');
      try { el.dispatchEvent(new Event('change', { bubbles: true })); } catch (_e) {}
      refresh(true);
    });
    // snippets: append a line to a textarea
    U.on(bodyEl, 'click', '[data-snippet-field]', function (e, t) {
      var el = form.elements && form.elements.namedItem(t.getAttribute('data-snippet-field'));
      if (!el) return;
      var val = t.getAttribute('data-snippet-value');
      el.value = (String(el.value).trim() ? String(el.value).replace(/\s+$/, '') + '\n' : '') + val;
      try { el.focus(); } catch (_e) {}
      refresh(true);
    });
    if (copyBtn) copyBtn.addEventListener('click', function () {
      if (code.getAttribute('data-valid') !== 'true') { U.toast('Command not ready', 'err'); return; }
      U.copy(code.getAttribute('data-cmd') || code.textContent).then(function (ok) { U.toast(ok ? 'Command copied' : 'Copy failed', ok ? '' : 'err'); });
    });

    refresh(false);
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    var context = toolContext();

    function toggle(card) {
      var head = card.querySelector('.tool-card-head');
      var open = card.classList.toggle('open');
      if (head) head.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) {
        var builder = builderById(card.getAttribute('data-tool-id'));
        if (builder) mountBuilder(card, builder, context);
      }
    }

    U.on(mount, 'click', '.tool-card-head', function (e, t) {
      toggle(t.closest('.tool-card'));
    });
    // keyboard access for the role=button head
    U.on(mount, 'keydown', '.tool-card-head', function (e, t) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); toggle(t.closest('.tool-card')); }
    });
    // category jump chips: scroll to the section (no hash navigation → no router hijack)
    U.on(mount, 'click', '.tools-jump', function (e, t) {
      var el = document.getElementById(t.getAttribute('data-cat'));
      if (el) { try { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_e) { el.scrollIntoView(); } }
    });

    // any card pre-marked open (deep link #/tools/<tool>) mounts now and scrolls into view
    var opened = mount.querySelectorAll('.tool-card.open');
    for (var i = 0; i < opened.length; i++) {
      var card = opened[i];
      var head = card.querySelector('.tool-card-head');
      if (head) head.setAttribute('aria-expanded', 'true');
      var b = builderById(card.getAttribute('data-tool-id'));
      if (b) mountBuilder(card, b, context);
      if (i === 0) { try { card.scrollIntoView({ block: 'start' }); } catch (e) {} }
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.tools = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
