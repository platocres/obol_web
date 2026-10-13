/*!
 * obol ui — routes/help.js — the Help tab. The MAP of obol: what each surface is for, when to reach for
 * it, and obol's own vocabulary. Content lives in data/help-content.js (OBOL.HELP); this renders it.
 * Three sub-views (Index / Quick Start / Glossary), triage cards on the Index, a collapsible by-section
 * accordion with Go There deep links, a calm Charon quick-start, and an obol-vocabulary glossary.
 * Deep-linkable: #/help, #/help/<sectionId> (Index, that section open), #/help/start, #/help/glossary.
 * Presentation only: Help documents the app, it changes nothing.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};
  var U = OBOL.util;
  function esc(s) { return U.esc(s); }

  function gotoBtn(goto, label, set) {
    if (!goto) return '';
    return '<button type="button" class="help-go" data-goto="' + U.attr(goto) + '"'
      + (set ? ' data-set="' + U.attr(JSON.stringify(set)) + '"' : '') + '>' + esc(label) + ' &rsaquo;</button>';
  }

  function subRow(sub) {
    var kids = (sub.subs && sub.subs.length) ? '<div class="help-subs help-subs--deep">' + sub.subs.map(subRow).join('') + '</div>' : '';
    return '<div class="help-sub"><div class="help-sub-main"><span class="help-sub-t">' + esc(sub.title) + '</span> '
      + '<span class="help-sub-what">' + esc(sub.what) + '</span></div>'
      + gotoBtn(sub.goto, 'Go', sub.set) + '</div>' + kids;
  }

  function sectionCard(s, open) {
    var subsHtml = '';
    if (s.groups) {
      subsHtml = s.groups.map(function (g) {
        return '<div class="help-grp"><div class="help-grp-h">' + esc(g.group) + '</div>' + (g.subs || []).map(subRow).join('') + '</div>';
      }).join('');
    } else if (s.subs) {
      subsHtml = s.subs.map(subRow).join('');
    }
    return '<details class="help-sec" id="help-' + U.attr(s.id) + '"' + (open ? ' open' : '') + '>'
      + '<summary class="help-sec-sum"><span class="help-sec-t">' + esc(s.title) + '</span>'
      + '<span class="help-sec-what">' + esc(s.what) + '</span></summary>'
      + '<div class="help-sec-body">'
      + (s.when ? '<p class="help-when"><span class="help-lbl">When</span> ' + esc(s.when) + '</p>' : '')
      + '<div class="help-goable">' + gotoBtn(s.goto, 'Go To ' + s.title) + '</div>'
      + (subsHtml ? '<div class="help-subs">' + subsHtml + '</div>' : '')
      + '</div></details>';
  }

  function renderIndex(H, focus) {
    var triage = '<div class="help-triage">' + (H.triage || []).map(function (t) {
      return '<button type="button" class="help-tri" data-goto="' + U.attr(t.goto) + '">'
        + '<span class="help-tri-t">' + esc(t.title) + '</span>'
        + '<span class="help-tri-b">' + esc(t.body) + '</span>'
        + '<span class="help-tri-cta">' + esc(t.cta) + ' &rsaquo;</span></button>';
    }).join('') + '</div>';
    var sections = (H.sections || []).map(function (s) { return sectionCard(s, s.id === focus); }).join('');
    return triage
      + '<h2 class="help-h2">Everything In obol, By Section</h2>'
      + '<p class="help-note">Open a section to see what it holds. Every row has a Go There.</p>'
      + '<div class="help-index">' + sections + '</div>';
  }

  function renderStart(H) {
    // the cyberpunk Charon illustration, floating in emanating ring-light (same ferryman as Stuck?)
    var intro = '<div class="help-charon">'
      + '<div class="charon-fig"><span class="charon-aura"></span><span class="charon-ring"></span><span class="charon-ring r2"></span>'
      + '<img class="charon-img" src="assets/img/charon.webp?v=2" width="216" height="216" loading="lazy" decoding="async" alt="Charon the ferryman, hooded with glowing red eyes in a skull boat on the green Styx"></div>'
      + '<p class="help-charon-say">' + esc(H.charonIntro || '') + '</p></div>';
    var cards = (H.quickstart || []).map(function (q, i) {
      return '<div class="help-qs"><div class="help-qs-n" aria-hidden="true">' + (i + 1) + '</div>'
        + '<div class="help-qs-b"><div class="help-qs-t">' + esc(q.title) + '</div>'
        + (q.charon ? '<p class="help-qs-say">' + esc(q.charon) + '</p>' : '')
        + '<p class="help-qs-body">' + esc(q.body) + '</p>'
        + gotoBtn(q.goto, q.cta) + '</div></div>';
    }).join('');
    return intro + '<div class="help-qs-grid">' + cards + '</div>';
  }

  function renderGlossary(H) {
    var terms = (H.glossary || []).slice().sort(function (a, b) { return a.term < b.term ? -1 : 1; }).map(function (g) {
      var see = (g.see && g.see.length) ? '<div class="help-term-see">See: ' + g.see.map(function (id) {
        return '<a href="#/help/' + U.attr(id) + '">' + esc(id) + '</a>';
      }).join(', ') + '</div>' : '';
      return '<div class="help-term"><div class="help-term-t">' + esc(g.term) + '</div>'
        + '<div class="help-term-d">' + esc(g.def) + '</div>' + see + '</div>';
    }).join('');
    return '<p class="help-note">The words obol uses. For pentest terms (SUID, Kerberoast, and the rest) see Learn and the field notes.</p>'
      + '<div class="help-glossary">' + terms + '</div>';
  }

  var TABS = [['start', 'Quick Start', '#/help/start'], ['index', 'Index', '#/help/index'], ['glossary', 'Glossary', '#/help/glossary']];
  function tabBar(active) {
    return '<div class="help-tabs" role="tablist">' + TABS.map(function (t) {
      return '<a class="help-tab' + (t[0] === active ? ' active' : '') + '" href="' + t[2] + '" role="tab" aria-selected="' + (t[0] === active) + '">' + esc(t[1]) + '</a>';
    }).join('') + '</div>';
  }

  function subOf(ctx) { return (ctx && ctx.args && ctx.args[0]) || ''; }

  function render(ctx) {
    var H = OBOL.HELP || {};
    var sub = subOf(ctx);
    // Quick Start leads: a bare #/help opens it. The Index tab is #/help/index; a section id
    // (#/help/engagements, from the "?" on-ramp) opens the Index focused on that section.
    var tab = sub === 'glossary' ? 'glossary' : (sub === '' || sub === 'start') ? 'start' : 'index';
    var focus = (tab === 'index' && sub && sub !== 'index') ? sub : '';
    var head = '<section class="help-route"><div class="help-head"><h1 class="route-h1">Help</h1>'
      + '<p class="route-sub">What each part of obol is for, and when to reach for it. This is the map. For how to pentest, see Learn and the field notes.</p></div>'
      + tabBar(tab);
    if (!H.sections) {
      return head + '<p class="route-sub">Help is coming online. If you just opened it, give the bundle a moment and try again.</p></section>';
    }
    var body = tab === 'start' ? renderStart(H) : tab === 'glossary' ? renderGlossary(H) : renderIndex(H, focus);
    return head + body + '</section>';
  }

  function mounted(ctx) {
    var mount = (ctx && ctx.mount) || document;
    // Go There (any element carrying data-goto, including the triage cards): optionally set UI state
    // (e.g. a Findings sub-view), then navigate.
    U.on(mount, 'click', '[data-goto]', function (e, b) {
      var set = b.getAttribute('data-set');
      if (set) { try { var o = JSON.parse(set); OBOL.store.update(function (eng) { eng.ui = eng.ui || {}; Object.keys(o).forEach(function (k) { eng.ui[k] = o[k]; }); }, 'ui'); } catch (x) {} }
      var go = b.getAttribute('data-goto'); if (go) location.hash = go;
    });
    // a deep link to a section opens it (the <details open> above) and scrolls it into view
    var s = subOf(ctx);
    var focus = (s && s !== 'start' && s !== 'glossary' && s !== 'index') ? s : '';
    if (focus) {
      var el = mount.querySelector('#help-' + (window.CSS && CSS.escape ? CSS.escape(focus) : focus));
      if (el) { try { el.open = true; el.scrollIntoView({ block: 'start' }); } catch (x) {} }
    }
  }

  OBOL.routes = OBOL.routes || {};
  OBOL.routes.help = { render: render, mounted: mounted };
})(typeof globalThis !== 'undefined' ? globalThis : this);
