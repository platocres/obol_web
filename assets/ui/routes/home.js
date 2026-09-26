/*!
 * obol ui — routes/home.js — THE ENGAGEMENT SCREEN (the front door / launch surface).
 * Replaces the old dashboard: create an engagement with a platform profile (HTB, OffSec/OSCP,
 * PWK, TryHackMe, HTB CPTS, CTF, OSWP, custom) + machine-type + scope/targets, then launch a
 * run (seeds facts -> lands on the coach). Also the engagement library + active-engagement
 * status. Emulates obol-local's `engagement new` + profile + scope flow.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  // Extract IPs and CIDRs from arbitrary pasted text (obol-local `scope paste` filter).
  var IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g;
  function extractScope(text) {
    var out = [], m, seen = {};
    while ((m = IP_RE.exec(text || '')) !== null) {
      var v = m[0];
      // validate octets 0-255
      var ok = v.split('/')[0].split('.').every(function (o) { return +o >= 0 && +o <= 255; });
      if (ok && !seen[v]) { seen[v] = 1; out.push(v); }
    }
    return out;
  }
  function isCidr(s) { return s.indexOf('/') >= 0; }

  function platformCards(selected) {
    return OBOL.profile.listPresets().map(function (p) {
      return '<label class="pf-card' + (p.id === selected ? ' sel' : '') + '">'
        + '<input type="radio" name="pf-platform" value="' + esc(p.id) + '"' + (p.id === selected ? ' checked' : '') + '>'
        + '<span class="pf-name">' + esc(p.name) + '</span>'
        + (p.exam ? '<span class="pf-badge exam">exam</span>' : '<span class="pf-badge lab">lab</span>')
        + '<span class="pf-flags">' + esc(p.flag_names.join(', ')) + '</span>'
        + '</label>';
    }).join('');
  }

  function machineOptions(selected) {
    return '<option value="">— machine type (optional) —</option>' + OBOL.profile.listMachineTypes().map(function (m) {
      return '<option value="' + esc(m.id) + '"' + (m.id === selected ? ' selected' : '') + '>' + esc(m.name) + '</option>';
    }).join('');
  }

  function activePanel() {
    var eng = OBOL.store.active();
    if (!eng) return '';
    var prof = eng.profile || {};
    var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
    var exam = OBOL.profile.isExamPlatform(prof.platform);
    var facts = OBOL.store.factSet();
    var ranked = OBOL.pack.nextActions(facts, OBOL.packs.actions());
    var reached = OBOL.phases.phaseIndex(OBOL.phases.targetPhase(facts));
    var frontier = OBOL.phases.frontierIndex(facts);
    var spine = OBOL.phases.PHASES.map(function (p, i) {
      return '<span class="spine-node ph-' + p + (i <= reached ? ' reached' : '') + (i === frontier ? ' frontier' : '') + '">' + p + '</span>';
    }).join('<span class="spine-sep">›</span>');
    var mt = prof.machine_type ? (OBOL.profile.MACHINE_TYPES[prof.machine_type] || {}).name : '';
    var nt = (eng.targets || []).length, nf = Object.keys(facts.kinds()).length;
    var isCustom = !prof.platform || prof.platform === 'custom';
    return '<div class="eng-active">'
      + '<div class="eng-active-head">'
      + '<div><div class="eng-active-name">' + esc(eng.name) + '</div>'
      + '<div class="eng-badges">'
      // only show a platform badge for a real platform — "Custom" told the user nothing
      + (isCustom ? '' : '<span class="pf-badge ' + (exam ? 'exam' : 'lab') + '">' + esc(preset.name) + (exam ? ' · exam' : '') + '</span>')
      + (mt ? '<span class="pill">' + esc(mt) + '</span>' : '')
      + (prof.osid ? '<span class="pill">OSID ' + esc(prof.osid) + '</span>' : '')
      + '<span class="pill">' + nt + ' target' + (nt === 1 ? '' : 's') + '</span>'
      + '<span class="pill">' + nf + ' fact' + (nf === 1 ? '' : 's') + '</span>'
      + '</div></div>'
      + '<a class="btn-primary" href="#/path">Open coach →</a>'
      + '</div>'
      + '<div class="home-spine">' + spine + '</div>'
      + (ranked.length ? ('<div class="eng-nextmove"><span class="mini-label">next move</span> ' + esc(ranked[0].title) + '</div>') : '')
      + '</div>';
  }

  function libraryList() {
    var rows = OBOL.store.listEngagements().map(function (e) {
      var prof = e.profile || {};
      var preset = (OBOL.profile.PRESETS[prof.platform] || OBOL.profile.PRESETS.custom);
      var active = e.id === OBOL.store.activeId();
      return '<li class="lib-row' + (active ? ' active' : '') + '">'
        + '<button class="lib-open" data-eng="' + esc(e.id) + '"><span class="lib-name">' + esc(e.name) + '</span>'
        + '<span class="pill">' + esc(preset.name) + '</span>'
        + '<span class="lib-meta">' + (e.targets || []).length + ' targets · ' + (e.facts || []).length + ' facts</span></button>'
        + '<button class="lib-del" data-eng="' + esc(e.id) + '" title="Delete">×</button></li>';
    }).join('');
    return '<ul class="lib-list">' + rows + '</ul>';
  }

  function render() {
    var prof = (OBOL.store.active() || {}).profile || {};
    var sel = prof.platform || 'custom';
    return '<section class="engscreen">'
      + '<h1 class="route-h1">Engagements</h1>'
      + '<p class="route-sub">Pick a platform, set your scope, and launch a run. The profile decides which flags the hunt targets, the proof requirements, and the report shape.</p>'
      + activePanel()
      + '<div class="eng-create"><h2 class="coach-sec-h">New engagement</h2>'
      + '<label class="eng-field"><span>Name</span><input id="eng-name" placeholder="Name this run — e.g. “OSCP prep” or “Lab night 3”" autocomplete="off"></label>'
      + '<div class="eng-field"><span>Platform profile</span><div class="pf-grid" id="pf-grid">' + platformCards(sel) + '</div></div>'
      + '<div class="eng-row2">'
      + '<label class="eng-field"><span>Machine type</span><select id="eng-mt">' + machineOptions(prof.machine_type || '') + '</select></label>'
      + '<label class="eng-field pf-osid" id="pf-osid-wrap" style="display:none"><span>OSID (OffSec exam)</span><input id="eng-osid" placeholder="OS-XXXXX"></label>'
      + '<label class="eng-field pf-osid" id="pf-cand-wrap" style="display:none"><span>Candidate</span><input id="eng-cand" placeholder="Your name"></label>'
      + '</div>'
      + '<label class="eng-field"><span>Scope / targets — paste IPs &amp; CIDRs (junk is filtered)</span>'
      + '<textarea id="eng-scope" class="ev-textarea" style="min-height:90px" placeholder="10.10.10.161  10.10.10.175&#10;10.10.10.0/24"></textarea></label>'
      + '<button id="eng-launch" class="btn-primary">Create &amp; launch run →</button>'
      + '</div>'
      + '<div class="eng-library"><h2 class="coach-sec-h">Engagement library</h2>' + libraryList() + '</div>'
      + '</section>';
  }

  function syncOsidVisibility() {
    var sel = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
    var preset = OBOL.profile.listPresets().find(function (p) { return p.id === sel; }) || {};
    var show = preset.osid ? '' : 'none';
    var o = document.getElementById('pf-osid-wrap'), c = document.getElementById('pf-cand-wrap');
    if (o) o.style.display = show; if (c) c.style.display = show;
  }

  function mounted(ctx) {
    var mount = ctx.mount;
    // platform card selection styling + OSID reveal
    U.on(mount, 'change', 'input[name="pf-platform"]', function (e, t) {
      mount.querySelectorAll('.pf-card').forEach(function (el) { el.classList.remove('sel'); });
      var card = t.closest('.pf-card'); if (card) card.classList.add('sel');
      syncOsidVisibility();
    });
    syncOsidVisibility();

    // library: open / delete
    U.on(mount, 'click', '.lib-open', function (e, t) {
      OBOL.store.setActive(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });
    U.on(mount, 'click', '.lib-del', function (e, t) {
      if (!confirm('Delete this engagement? This cannot be undone.')) return;
      OBOL.store.deleteEngagement(t.getAttribute('data-eng')).then(function () { OBOL.app.renderSidebar(); OBOL.router.render(); });
    });

    // create & launch
    var launch = document.getElementById('eng-launch');
    if (launch) launch.addEventListener('click', function () {
      var name = (document.getElementById('eng-name').value || '').trim();
      var platform = (document.querySelector('input[name="pf-platform"]:checked') || {}).value || 'custom';
      var mt = (document.getElementById('eng-mt').value || '');
      var osid = (document.getElementById('eng-osid') || {}).value || '';
      var cand = (document.getElementById('eng-cand') || {}).value || '';
      var scopeText = (document.getElementById('eng-scope').value || '');
      var scope = extractScope(scopeText);
      if (!name) { name = (OBOL.profile.PRESETS[platform] || {}).name || 'Engagement'; }

      OBOL.store.createEngagement(name, { platform: platform, machine_type: mt, osid: osid.trim(), candidate: cand.trim(), scope: scope }).then(function (eng) {
        // seed targets from bare IPs; keep CIDRs as authorized scope only.
        var hosts = scope.filter(function (s) { return !isCidr(s); });
        var facts = [];
        OBOL.store.update(function (e) {
          e.targets = [];
          hosts.forEach(function (ip, i) {
            e.targets.push({ id: 't' + i + '-' + Date.now().toString(36), ip: ip, hostname: '', os: '' });
            facts.push(OBOL.facts.makeFact({ kind: 'target.configured', scope: 'host:' + ip, source: 'engagement' }));
          });
          if (!e.params) e.params = {};
          if (hosts[0]) e.params.target = hosts[0];
          if (scope.length) e.params.scope_defined = true;
        }, 'launch');
        if (facts.length) OBOL.store.addFacts(facts, 'launch');
        OBOL.app.renderSidebar();
        U.toast(hosts.length ? ('Launched — ' + hosts.length + ' target(s) scoped') : 'Engagement created — add targets to begin');
        OBOL.router.go('path');
      });
    });
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.home = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
