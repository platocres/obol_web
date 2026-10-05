/*!
 * obol ui — ctxbar.js — the global engagement context strip.
 *
 * A slim bar under the header, present on EVERY route (Learn included), carrying the three pieces of
 * engagement context that any command-filling surface reads: the active engagement, the active
 * credential, and the active target. Promoting these out of the left sidebar (which is hidden on the
 * full-bleed Learn front door) means you can swap the credential or target and have every command,
 * anywhere, re-fill — exactly as on the working surfaces.
 *
 * All three are native <select>s on purpose: fully keyboard- and screen-reader-operable, no custom
 * popup to trap focus. The credential list is engagement-wide (OBOL.creds.gather spans every target),
 * and "active target" is the `target` parameter wearing a hat — one source of truth with the left bar.
 *
 * A second row is the contextual engagement sub-nav: the per-engagement surfaces, shown only on
 * engagement routes so the reduced five-item top nav never leaves anything unreachable.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(String(s == null ? '' : s)); }

  // routes that belong to "an engagement" (the sub-nav + the Engagements parent highlight cover these)
  var ENG_ROUTES = ['home', 'targets', 'target', 'evidence', 'path', 'map', 'domain', 'creds', 'checklist', 'findings', 'history', 'scoreboard', 'report', 'graph'];
  // the contextual sub-nav, grouped by how a box actually gets worked
  var SUBNAV = [
    { group: 'Work the box', items: [['home', 'Hub'], ['targets', 'Targets'], ['path', 'Next Steps'], ['evidence', 'Evidence']] },
    { group: 'Analyze', items: [['map', 'Map'], ['domain', 'Domain'], ['creds', 'Creds']] },
    { group: 'Track & report', items: [['checklist', 'Checklist'], ['findings', 'Findings'], ['history', 'Run Log'], ['scoreboard', 'Scoreboard'], ['report', 'Report']] },
  ];

  function ic(n) { return OBOL.ic ? OBOL.ic(n) : ''; }
  function focusOn() { try { return localStorage.getItem('obol.focus') === '1'; } catch (e) { return false; } }
  function applyFocus() { try { document.documentElement.setAttribute('data-focus', focusOn() ? '1' : '0'); } catch (e) {} }
  function routeName() { return (location.hash || '').replace(/^#\/?/, '').split('/')[0] || ''; }
  function isEngRoute(n) { return ENG_ROUTES.indexOf(n) >= 0; }

  function engOptions() {
    var list = (OBOL.store.listEngagements && OBOL.store.listEngagements()) || [];
    var activeId = OBOL.store.activeId && OBOL.store.activeId();
    return list.map(function (e) {
      return '<option value="' + U.attr(e.id) + '"' + (e.id === activeId ? ' selected' : '') + '>' + esc(e.name) + '</option>';
    }).join('');
  }

  function credOptions() {
    var creds = (OBOL.creds && OBOL.creds.gather()) || [];
    _creds = creds;
    if (!creds.length) return { disabled: true, html: '<option value="">no credentials yet</option>' };
    var active = (OBOL.creds && OBOL.creds.activeKey()) || '';
    var opts = '<option value="">no credential</option>' + creds.map(function (c, i) {
      var on = OBOL.creds.keyOf(c) === active;
      var label = (c.domain ? c.domain + '\\' : '') + c.user + (c.type === 'NT' ? ' (hash)' : (c.type === 'PW' ? '' : ' (' + c.type + ')'));
      return '<option value="' + i + '"' + (on ? ' selected' : '') + '>' + esc(label) + '</option>';
    }).join('');
    return { disabled: false, html: opts };
  }

  function targetOptions() {
    var eng = OBOL.store.active() || {};
    var cur = (eng.params || {}).target || '';
    var targets = (eng.targets || []).map(function (t) { return t.ip || t.target || ''; }).filter(Boolean);
    if (cur && targets.indexOf(cur) < 0) targets.unshift(cur);
    if (!targets.length) return { disabled: true, html: '<option value="">no targets yet</option>' };
    var opts = '<option value="">no target</option>' + targets.map(function (ip) {
      return '<option value="' + U.attr(ip) + '"' + (ip === cur ? ' selected' : '') + '>' + esc(ip) + '</option>';
    }).join('');
    return { disabled: false, html: opts };
  }

  var _creds = [];

  function subnavHtml(name) {
    return SUBNAV.map(function (g) {
      return '<span class="ctx-subgroup" role="group" aria-label="' + esc(g.group) + '">'
        + '<span class="ctx-subgroup-l" aria-hidden="true">' + esc(g.group) + '</span>'
        + g.items.map(function (it) {
          var on = it[0] === name;
          return '<a data-nav data-subnav href="#/' + it[0] + '"' + (on ? ' class="active" aria-current="page"' : '') + '>' + esc(it[1]) + '</a>';
        }).join('')
        + '</span>';
    }).join('');
  }

  function render() {
    var bar = document.getElementById('ctxbar');
    if (!bar) return;
    var name = routeName(), onEng = isEngRoute(name);
    var cred = credOptions(), tgt = targetOptions();
    var html = '<div class="ctx-context">'
      + '<label class="ctx-pill ctx-eng" title="Active engagement"><span class="ctx-ic" aria-hidden="true">◆</span>'
      + '<span class="ctx-k">Engagement</span>'
      + '<select id="ctx-eng" aria-label="Active engagement">' + engOptions() + '</select></label>'
      + '<label class="ctx-pill ctx-cred' + (cred.disabled ? ' is-empty' : '') + '" title="Active credential, fills commands everywhere, Learn included">'
      + '<span class="ctx-ic" aria-hidden="true">' + ic('lock') + '</span><span class="ctx-k">Credential</span>'
      + '<select id="ctx-cred" aria-label="Active credential"' + (cred.disabled ? ' disabled' : '') + '>' + cred.html + '</select></label>'
      + '<label class="ctx-pill ctx-target' + (tgt.disabled ? ' is-empty' : '') + '" title="Active target, fills {{target}} and routes anchorless pastes">'
      + '<span class="ctx-ic" aria-hidden="true">' + ic('crosshair') + '</span><span class="ctx-k">Target</span>'
      + '<select id="ctx-target" aria-label="Active target"' + (tgt.disabled ? ' disabled' : '') + '>' + tgt.html + '</select></label>'
      + '<button type="button" class="ctx-focus" data-ctx-focus aria-pressed="' + (focusOn() ? 'true' : 'false') + '" title="Focus mode: hide secondary panels for low-distraction work">' + ic('spark') + '<span>Focus</span></button>'
      + '</div>';
    html += '<nav class="ctx-subnav" aria-label="Engagement surfaces"' + (onEng ? '' : ' hidden') + '>' + (onEng ? subnavHtml(name) : '') + '</nav>';
    bar.innerHTML = html;
    bar.setAttribute('data-eng', onEng ? '1' : '0');
  }

  function wire() {
    var bar = document.getElementById('ctxbar');
    if (!bar || bar._wired) return;
    bar._wired = true;
    bar.addEventListener('click', function (e) {
      if (e.target.closest && e.target.closest('[data-ctx-focus]')) {
        try { localStorage.setItem('obol.focus', focusOn() ? '0' : '1'); } catch (x) {}
        applyFocus(); render();
      }
    });
    bar.addEventListener('change', function (e) {
      var t = e.target;
      if (t.id === 'ctx-eng') {
        OBOL.store.setActive(t.value).then(function () { if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar(); render(); OBOL.router.render(); });
      } else if (t.id === 'ctx-cred') {
        if (t.value === '') { OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.username = ''; eng.params.password = ''; eng.params.nthash = ''; }, 'params'); }
        else { OBOL.creds.activate(_creds[+t.value]); }
      } else if (t.id === 'ctx-target') {
        OBOL.store.update(function (eng) { eng.params = eng.params || {}; eng.params.target = t.value; }, 'params');
        if (OBOL.app && OBOL.app.renderSidebar) OBOL.app.renderSidebar();
        OBOL.router.render();
      }
    });
    // keep the strip in sync with state and navigation
    if (OBOL.store && OBOL.store.onChange) OBOL.store.onChange(function () { render(); });
    window.addEventListener('hashchange', render);
  }

  function init() { applyFocus(); render(); wire(); }

  OBOL.ctxbar = { init: init, render: render, ENG_ROUTES: ENG_ROUTES };
})(typeof globalThis !== 'undefined' ? globalThis : this);
